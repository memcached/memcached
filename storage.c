/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int lru_maintainer_store(void *storage, const int clsid) {
    //int i;
    int did_moves = 0;
    int item_age = settings.ext_item_age;
    bool mem_limit_reached = false;
    unsigned int chunks_free;
    unsigned int chunks_perslab;
    struct lru_pull_tail_return it_info;
    // FIXME: need to directly ask the slabber how big a class is
    if (slabs_clsid(settings.ext_item_size) > clsid)
        return 0;
    chunks_free = slabs_available_chunks(clsid, &mem_limit_reached,
            NULL, &chunks_perslab);
    // if we are low on chunks and no spare, push out early.
    if (chunks_free < (chunks_perslab / 2) && mem_limit_reached)
        item_age = 0;

    it_info.it = NULL;
    lru_pull_tail(clsid, COLD_LRU, 0, LRU_PULL_RETURN_ITEM, 0, &it_info);
    /* Item isn't locked, but we have a reference to it. */
    if (it_info.it != NULL) {
        obj_io io;
        item *it = it_info.it;
        /* First, storage for the header object */
        size_t orig_ntotal = ITEM_ntotal(it);
        uint32_t flags;
        // TODO: Doesn't presently work with chunked items. */
        if ((it->it_flags & (ITEM_CHUNKED|ITEM_HDR)) == 0 &&
                (item_age == 0 || current_time - it->time > item_age)) {
            if (settings.inline_ascii_response) {
                flags = (uint32_t) strtoul(ITEM_suffix(it)+1, (char **) NULL, 10);
            } else if (it->nsuffix > 0) {
                flags = *((uint32_t *)ITEM_suffix(it));
            } else {
                flags = 0;
            }
            item *hdr_it = do_item_alloc(ITEM_key(it), it->nkey, flags, it->exptime, sizeof(item_hdr));
            /* Run the storage write understanding the header is dirty.
             * We will fill it from the header on read either way.
             */
            if (hdr_it != NULL) {
                // cuddle the hash value into the time field so we don't have
                // to recalculate it.
                uint32_t crc = crc32c(0, (char*)it+32, orig_ntotal-32);
                hdr_it->it_flags |= ITEM_HDR;
                io.len = orig_ntotal;
                io.mode = OBJ_IO_WRITE;
                // NOTE: when the item is read back in, the slab mover
                // may see it. Important to have refcount>=2 or ~ITEM_LINKED
                assert(it->refcount >= 2);
                if (extstore_write_request(storage, 0, &io) == 0) {
                    item *buf_it = (item *) io.buf;
                    buf_it->time = it_info.hv;
                    buf_it->exptime = crc;
                    // copy from past the headers + time headers.
                    memcpy((char *)io.buf+32, (char *)it+32, io.len-32);
                    extstore_write(storage, &io);
                    item_hdr *hdr = (item_hdr *) ITEM_data(hdr_it);
                    hdr->page_version = io.page_version;
                    hdr->page_id = io.page_id;
                    hdr->offset  = io.offset;
                    // overload nbytes for the header it
                    hdr_it->nbytes = it->nbytes;
                    /* success! Now we need to fill relevant data into the new
                     * header and replace. Most of this requires the item lock
                     */
                    /* CAS gets set while linking. Copy post-replace */
                    item_replace(it, hdr_it, it_info.hv);
                    ITEM_set_cas(hdr_it, ITEM_get_cas(it));
                    //fprintf(stderr, "EXTSTORE: swapped an item: %s %lu %lu\n", ITEM_key(it), orig_ntotal, ntotal);
                    do_item_remove(hdr_it);
                    did_moves = 1;
                } else {
                    //fprintf(stderr, "EXTSTORE: failed to write\n");
                    /* Failed to write for some reason, can't continue. */
                    slabs_free(hdr_it, ITEM_ntotal(hdr_it), ITEM_clsid(hdr_it));
                }
            }
        }
        do_item_remove(it);
        item_unlock(it_info.hv);
    }
    return did_moves;
}

/* Fetch stats from the external storage system and decide to compact.
 * If we're more than half full, start skewing how aggressively to run
 * compaction, up to a desired target when all pages are full.
 */
static int storage_compact_check(void *storage, logger *l,
        uint32_t *page_id,
        uint64_t *page_version, uint64_t *page_size) {
    struct extstore_stats st;
    int x;
    double rate;
    uint64_t frag_limit;
    uint64_t low_version = ULLONG_MAX;
    unsigned int low_page = 0;
    extstore_get_stats(storage, &st);
    if (st.pages_used == 0)
        return 0;

    // lets pick a target "wasted" value and slew.
    if (st.pages_free > st.page_count / 4)
        return 0;

    // the number of free pages reduces the configured frag limit
    // this allows us to defrag early if pages are very empty.
    rate = 1.0 - ((double)st.pages_free / st.page_count);
    rate *= settings.ext_max_frag;
    frag_limit = st.page_size * rate;
    LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_FRAGINFO,
            NULL, rate, frag_limit);
    st.page_data = calloc(st.page_count, sizeof(struct extstore_page_data));
    extstore_get_page_data(storage, &st);

    // find oldest page by version that violates the constraint
    for (x = 0; x < st.page_count; x++) {
        if (st.page_data[x].version == 0)
            continue;
        if (st.page_data[x].bytes_used < frag_limit) {
            if (st.page_data[x].version < low_version) {
                low_page = x;
                low_version = st.page_data[x].version;
            }
        }
    }
    *page_size = st.page_size;
    free(st.page_data);

    // we have a page + version to attempt to reclaim.
    if (low_version != ULLONG_MAX) {
        *page_id = low_page;
        *page_version = low_version;
        return 1;
    }

    return 0;
}

static pthread_t storage_compact_tid;
#define MIN_STORAGE_COMPACT_SLEEP 10000
#define MAX_STORAGE_COMPACT_SLEEP 2000000

struct storage_compact_wrap {
    obj_io io;
    pthread_mutex_t lock; // gates the bools.
    bool done;
    bool submitted;
    bool miss; // version flipped out from under us
};

static void storage_compact_readback(void *storage, logger *l,
        char *readback_buf,
        uint32_t page_id, uint64_t page_version, uint64_t read_size) {
    uint64_t offset = 0;
    unsigned int rescues = 0;
    unsigned int lost = 0;

    while (offset < read_size) {
        item *hdr_it = NULL;
        item_hdr *hdr = NULL;
        item *it = (item *)(readback_buf+offset);
        unsigned int ntotal;
        // probably zeroed out junk at the end of the wbuf
        if (it->nkey == 0) {
            break;
        }

        ntotal = ITEM_ntotal(it);
        uint32_t hv = (uint32_t)it->time;
        item_lock(hv);
        // We don't have a conn and don't need to do most of do_item_get
        hdr_it = assoc_find(ITEM_key(it), it->nkey, hv);
        if (hdr_it != NULL) {
            bool do_write = false;
            refcount_incr(hdr_it);

            // Check validity but don't bother removing it.
            if ((hdr_it->it_flags & ITEM_HDR) && !item_is_flushed(hdr_it) &&
                   (hdr_it->exptime == 0 || hdr_it->exptime > current_time)) {
                hdr = (item_hdr *)ITEM_data(hdr_it);
                if (hdr->page_id == page_id && hdr->page_version == page_version) {
                    // Item header is still completely valid.
                    extstore_delete(storage, page_id, page_version, 1, ntotal);
                    do_write = true;
                }
            }

            if (do_write) {
                bool do_update = false;
                int tries;
                obj_io io;
                io.len = ntotal;
                io.mode = OBJ_IO_WRITE;
                for (tries = 10; tries > 0; tries--) {
                    if (extstore_write_request(storage, 1, &io) == 0) {
                        memcpy(io.buf, it, io.len);
                        extstore_write(storage, &io);
                        do_update = true;
                        break;
                    } else {
                        usleep(1000);
                    }
                }

                if (do_update) {
                    if (it->refcount == 2) {
                        hdr->page_version = io.page_version;
                        hdr->page_id = io.page_id;
                        hdr->offset = io.offset;
                        rescues++;
                    } else {
                        lost++;
                        // TODO: re-alloc and replace header.
                    }
                }
            }

            do_item_remove(hdr_it);
        }

        item_unlock(hv);
        offset += ntotal;
        if (read_size - offset < sizeof(struct _stritem))
            break;
    }

    LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_READ_END,
            NULL, page_id, offset, rescues, lost);
}

static void _storage_compact_cb(void *e, obj_io *io, int ret) {
    struct storage_compact_wrap *wrap = (struct storage_compact_wrap *)io->data;
    assert(wrap->submitted == true);

    pthread_mutex_lock(&wrap->lock);

    if (ret < 1) {
        wrap->miss = true;
    }
    wrap->done = true;

    pthread_mutex_unlock(&wrap->lock);
}

// TODO: hoist the storage bits from lru_maintainer_thread in here.
// would be nice if they could avoid hammering the same locks though?
// I guess it's only COLD. that's probably fine.
static void *storage_compact_thread(void *arg) {
    void *storage = arg;
    useconds_t to_sleep = MAX_STORAGE_COMPACT_SLEEP;
    bool compacting = false;
    uint64_t page_version = 0;
    uint64_t page_size = 0;
    uint64_t page_offset = 0;
    uint32_t page_id = 0;
    char *readback_buf = NULL;
    struct storage_compact_wrap wrap;

    logger *l = logger_create();
    if (l == NULL) {
        fprintf(stderr, "Failed to allocate logger for LRU maintainer thread\n");
        abort();
    }

    // TODO: check error.
    readback_buf = malloc(settings.ext_wbuf_size);

    pthread_mutex_init(&wrap.lock, NULL);
    wrap.done = false;
    wrap.submitted = false;
    wrap.io.data = &wrap;
    wrap.io.buf = (void *)readback_buf;

    wrap.io.len = settings.ext_wbuf_size;
    wrap.io.mode = OBJ_IO_READ;
    wrap.io.cb = _storage_compact_cb;

    while (1) {
        if (to_sleep) {
            extstore_run_maint(storage);
            usleep(to_sleep);
        }

        if (!compacting && storage_compact_check(storage, l,
                    &page_id, &page_version, &page_size)) {
            page_offset = 0;
            compacting = true;
            LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_START,
                    NULL, page_id, page_version);
        }

        if (compacting) {
            pthread_mutex_lock(&wrap.lock);
            if (page_offset < page_size && !wrap.done && !wrap.submitted) {
                wrap.io.page_version = page_version;
                wrap.io.page_id = page_id;
                wrap.io.offset = page_offset;
                // FIXME: should be smarter about io->next (unlink at use?)
                wrap.io.next = NULL;
                wrap.submitted = true;
                wrap.miss = false;

                extstore_submit(storage, &wrap.io);
            } else if (wrap.miss) {
                LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_ABORT,
                        NULL, page_id);
                wrap.done = false;
                wrap.submitted = false;
                compacting = false;
            } else if (wrap.submitted && wrap.done) {
                LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_READ_START,
                        NULL, page_id, page_offset);
                storage_compact_readback(storage, l,
                        readback_buf, page_id, page_version, settings.ext_wbuf_size);
                page_offset += settings.ext_wbuf_size;
                wrap.done = false;
                wrap.submitted = false;
            } else if (page_offset >= page_size) {
                compacting = false;
                wrap.done = false;
                wrap.submitted = false;
                extstore_close_page(storage, page_id, page_version);
                LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_END,
                        NULL, page_id);
            }
            pthread_mutex_unlock(&wrap.lock);

            if (to_sleep > MIN_STORAGE_COMPACT_SLEEP)
                to_sleep /= 2;
        } else {
            if (to_sleep < MAX_STORAGE_COMPACT_SLEEP)
                to_sleep += MIN_STORAGE_COMPACT_SLEEP;
        }
    }
    free(readback_buf);

    return NULL;
}

// TODO
/*int stop_storage_compact_thread(void) {
    int ret;
    pthread_mutex_lock(&lru_maintainer_lock);
    do_run_lru_maintainer_thread = 0;
    pthread_mutex_unlock(&lru_maintainer_lock);
    if ((ret = pthread_join(lru_maintainer_tid, NULL)) != 0) {
        fprintf(stderr, "Failed to stop LRU maintainer thread: %s\n", strerror(ret));
        return -1;
    }
    settings.lru_maintainer_thread = false;
    return 0;
}*/

int start_storage_compact_thread(void *arg) {
    int ret;

    if ((ret = pthread_create(&storage_compact_tid, NULL,
        storage_compact_thread, arg)) != 0) {
        fprintf(stderr, "Can't create storage_compact thread: %s\n",
            strerror(ret));
        return -1;
    }

    return 0;
}


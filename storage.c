/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#ifdef EXTSTORE

#include "storage.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#define PAGE_BUCKET_DEFAULT 0
#define PAGE_BUCKET_COMPACT 1
#define PAGE_BUCKET_CHUNKED 2
#define PAGE_BUCKET_LOWTTL  3

int lru_maintainer_store(void *storage, const int clsid) {
    //int i;
    int did_moves = 0;
    int item_age = settings.ext_item_age;
    bool mem_limit_reached = false;
    unsigned int chunks_free;
    struct lru_pull_tail_return it_info;
    // FIXME: need to directly ask the slabber how big a class is
    if (slabs_clsid(settings.ext_item_size) > clsid)
        return 0;
    chunks_free = slabs_available_chunks(clsid, &mem_limit_reached,
            NULL, NULL);
    // if we are low on chunks and no spare, push out early.
    if (chunks_free < settings.ext_free_memchunks[clsid] && mem_limit_reached)
        item_age = 0;

    it_info.it = NULL;
    lru_pull_tail(clsid, COLD_LRU, 0, LRU_PULL_RETURN_ITEM, 0, &it_info);
    /* Item is locked, and we have a reference to it. */
    if (it_info.it == NULL) {
        return did_moves;
    }

    obj_io io;
    item *it = it_info.it;
    /* First, storage for the header object */
    size_t orig_ntotal = ITEM_ntotal(it);
    uint32_t flags;
    if ((it->it_flags & ITEM_HDR) == 0 &&
            (item_age == 0 || current_time - it->time > item_age)) {
        // FIXME: flag conversion again
        if (settings.inline_ascii_response) {
            flags = (uint32_t) strtoul(ITEM_suffix(it), (char **) NULL, 10);
        } else if (it->nsuffix > 0) {
            flags = *((uint32_t *)ITEM_suffix(it));
        } else {
            flags = 0;
        }
        item *hdr_it = do_item_alloc(ITEM_key(it), it->nkey, flags, it->exptime, sizeof(item_hdr));
        /* Run the storage write understanding the start of the item is dirty.
         * We will fill it (time/exptime/etc) from the header item on read.
         */
        if (hdr_it != NULL) {
            int bucket = (it->it_flags & ITEM_CHUNKED) ?
                PAGE_BUCKET_CHUNKED : PAGE_BUCKET_DEFAULT;
            // Compress soon to expire items into similar pages.
            if (it->exptime - current_time < settings.ext_low_ttl) {
                bucket = PAGE_BUCKET_LOWTTL;
            }
            hdr_it->it_flags |= ITEM_HDR;
            io.len = orig_ntotal;
            io.mode = OBJ_IO_WRITE;
            // NOTE: when the item is read back in, the slab mover
            // may see it. Important to have refcount>=2 or ~ITEM_LINKED
            assert(it->refcount >= 2);
            if (extstore_write_request(storage, bucket, &io) == 0) {
                // cuddle the hash value into the time field so we don't have
                // to recalculate it.
                item *buf_it = (item *) io.buf;
                buf_it->time = it_info.hv;
                // copy from past the headers + time headers.
                // TODO: should be in items.c
                if (it->it_flags & ITEM_CHUNKED) {
                    // Need to loop through the item and copy
                    item_chunk *sch = (item_chunk *) ITEM_data(it);
                    int remain = orig_ntotal;
                    int copied = 0;
                    // copy original header
                    int hdrtotal = ITEM_ntotal(it) - it->nbytes;
                    memcpy((char *)io.buf+STORE_OFFSET, (char *)it+STORE_OFFSET, hdrtotal - STORE_OFFSET);
                    copied = hdrtotal;
                    // copy data in like it were one large object.
                    while (sch && remain) {
                        assert(remain >= sch->used);
                        memcpy((char *)io.buf+copied, sch->data, sch->used);
                        // FIXME: use one variable?
                        remain -= sch->used;
                        copied += sch->used;
                        sch = sch->next;
                    }
                } else {
                    memcpy((char *)io.buf+STORE_OFFSET, (char *)it+STORE_OFFSET, io.len-STORE_OFFSET);
                }
                // crc what we copied so we can do it sequentially.
                buf_it->it_flags &= ~ITEM_LINKED;
                buf_it->exptime = crc32c(0, (char*)io.buf+STORE_OFFSET, orig_ntotal-STORE_OFFSET);
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
                do_item_remove(hdr_it);
                did_moves = 1;
                LOGGER_LOG(NULL, LOG_EVICTIONS, LOGGER_EXTSTORE_WRITE, it, bucket);
            } else {
                /* Failed to write for some reason, can't continue. */
                slabs_free(hdr_it, ITEM_ntotal(hdr_it), ITEM_clsid(hdr_it));
            }
        }
    }
    do_item_remove(it);
    item_unlock(it_info.hv);
    return did_moves;
}

/* Fetch stats from the external storage system and decide to compact.
 * If we're more than half full, start skewing how aggressively to run
 * compaction, up to a desired target when all pages are full.
 */
static int storage_compact_check(void *storage, logger *l,
        uint32_t *page_id, uint64_t *page_version,
        uint64_t *page_size, bool *drop_unread) {
    struct extstore_stats st;
    int x;
    double rate;
    uint64_t frag_limit;
    uint64_t low_version = ULLONG_MAX;
    uint64_t lowest_version = ULLONG_MAX;
    unsigned int low_page = 0;
    unsigned int lowest_page = 0;
    extstore_get_stats(storage, &st);
    if (st.pages_used == 0)
        return 0;

    // lets pick a target "wasted" value and slew.
    if (st.pages_free > settings.ext_compact_under)
        return 0;
    *drop_unread = false;

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
        if (st.page_data[x].version == 0 ||
            st.page_data[x].bucket == PAGE_BUCKET_LOWTTL)
            continue;
        if (st.page_data[x].version < lowest_version) {
            lowest_page = x;
            lowest_version = st.page_data[x].version;
        }
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
    } else if (lowest_version != ULLONG_MAX && settings.ext_drop_unread
            && st.pages_free <= settings.ext_drop_under) {
        // nothing matched the frag rate barrier, so pick the absolute oldest
        // version if we're configured to drop items.
        *page_id = lowest_page;
        *page_version = lowest_version;
        *drop_unread = true;
        return 1;
    }

    return 0;
}

static pthread_t storage_compact_tid;
static pthread_mutex_t storage_compact_plock;
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
        bool drop_unread, char *readback_buf,
        uint32_t page_id, uint64_t page_version, uint64_t read_size) {
    uint64_t offset = 0;
    unsigned int rescues = 0;
    unsigned int lost = 0;
    unsigned int skipped = 0;

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
                    // drop inactive items.
                    if (drop_unread && GET_LRU(hdr_it->slabs_clsid) == COLD_LRU) {
                        do_write = false;
                        skipped++;
                    } else {
                        do_write = true;
                    }
                }
            }

            if (do_write) {
                bool do_update = false;
                int tries;
                obj_io io;
                io.len = ntotal;
                io.mode = OBJ_IO_WRITE;
                for (tries = 10; tries > 0; tries--) {
                    if (extstore_write_request(storage, PAGE_BUCKET_COMPACT, &io) == 0) {
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
                } else {
                    lost++;
                }
            }

            do_item_remove(hdr_it);
        }

        item_unlock(hv);
        offset += ntotal;
        if (read_size - offset < sizeof(struct _stritem))
            break;
    }

    STATS_LOCK();
    stats.extstore_compact_lost += lost;
    stats.extstore_compact_rescues += rescues;
    stats.extstore_compact_skipped += skipped;
    STATS_UNLOCK();
    LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_READ_END,
            NULL, page_id, offset, rescues, lost, skipped);
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
    bool drop_unread = false;
    char *readback_buf = NULL;
    struct storage_compact_wrap wrap;

    logger *l = logger_create();
    if (l == NULL) {
        fprintf(stderr, "Failed to allocate logger for storage compaction thread\n");
        abort();
    }

    readback_buf = malloc(settings.ext_wbuf_size);
    if (readback_buf == NULL) {
        fprintf(stderr, "Failed to allocate readback buffer for storage compaction thread\n");
        abort();
    }

    pthread_mutex_init(&wrap.lock, NULL);
    wrap.done = false;
    wrap.submitted = false;
    wrap.io.data = &wrap;
    wrap.io.buf = (void *)readback_buf;

    wrap.io.len = settings.ext_wbuf_size;
    wrap.io.mode = OBJ_IO_READ;
    wrap.io.cb = _storage_compact_cb;
    pthread_mutex_lock(&storage_compact_plock);

    while (1) {
        pthread_mutex_unlock(&storage_compact_plock);
        if (to_sleep) {
            extstore_run_maint(storage);
            usleep(to_sleep);
        }
        pthread_mutex_lock(&storage_compact_plock);

        if (!compacting && storage_compact_check(storage, l,
                    &page_id, &page_version, &page_size, &drop_unread)) {
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
                storage_compact_readback(storage, l, drop_unread,
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
// logger needs logger_destroy() to exist/work before this is safe.
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

void storage_compact_pause(void) {
    pthread_mutex_lock(&storage_compact_plock);
}

void storage_compact_resume(void) {
    pthread_mutex_unlock(&storage_compact_plock);
}

int start_storage_compact_thread(void *arg) {
    int ret;

    pthread_mutex_init(&storage_compact_plock, NULL);
    if ((ret = pthread_create(&storage_compact_tid, NULL,
        storage_compact_thread, arg)) != 0) {
        fprintf(stderr, "Can't create storage_compact thread: %s\n",
            strerror(ret));
        return -1;
    }

    return 0;
}

#endif

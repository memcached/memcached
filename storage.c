/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#ifdef EXTSTORE

#include "storage.h"
#include "extstore.h"
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>

#define PAGE_BUCKET_DEFAULT 0
#define PAGE_BUCKET_COMPACT 1
#define PAGE_BUCKET_CHUNKED 2
#define PAGE_BUCKET_LOWTTL  3
#define PAGE_BUCKET_COLDCOMPACT 4
#define PAGE_BUCKET_OLD     5
// Not another bucket; this is the total number of buckets.
#define PAGE_BUCKET_COUNT   6

/*
 * API functions
 */
static void storage_finalize_cb(io_pending_t *pending);
static void storage_return_cb(io_pending_t *pending);

// re-cast an io_pending_t into this more descriptive structure.
// the first few items _must_ match the original struct.
typedef struct _io_pending_storage_t {
    uint8_t io_queue_type;
    uint8_t io_sub_type;
    uint8_t payload; // payload offset
    LIBEVENT_THREAD *thread;
    conn *c;
    mc_resp *resp;
    io_queue_cb return_cb;    // called on worker thread.
    io_queue_cb finalize_cb;  // called back on the worker thread.
    STAILQ_ENTRY(io_pending_t) iop_next; // queue chain.
                              /* original struct ends here */
    item *hdr_it;             /* original header item. */
    obj_io io_ctx;            /* embedded extstore IO header */
    unsigned int iovec_data;  /* specific index of data iovec */
    bool noreply;             /* whether the response had noreply set */
    bool miss;                /* signal a miss to unlink hdr_it */
    bool badcrc;              /* signal a crc failure */
    bool active;              /* tells if IO was dispatched or not */
} io_pending_storage_t;

static pthread_t storage_compact_tid;
static pthread_mutex_t storage_compact_plock;
static pthread_cond_t storage_compact_cond;

// Only call this if item has ITEM_HDR
bool storage_validate_item(void *e, item *it) {
    item_hdr *hdr = (item_hdr *)ITEM_data(it);
    if (extstore_check(e, hdr->page_id, hdr->page_version) != 0) {
        return false;
    } else {
        return true;
    }
}

void storage_delete(void *e, item *it) {
    if (it->it_flags & ITEM_HDR) {
        item_hdr *hdr = (item_hdr *)ITEM_data(it);
        extstore_delete(e, hdr->page_id, hdr->page_version,
                1, ITEM_ntotal(it));
    }
}

// Function for the extra stats called from a protocol.
// NOTE: This either needs a name change or a wrapper, perhaps?
// it's defined here to reduce exposure of extstore.h to the rest of memcached
// but feels a little off being defined here.
// At very least maybe "process_storage_stats" in line with making this more
// of a generic wrapper module.
void process_extstore_stats(ADD_STAT add_stats, void *c) {
    int i;
    char key_str[STAT_KEY_LEN];
    char val_str[STAT_VAL_LEN];
    int klen = 0, vlen = 0;
    struct extstore_stats st;

    assert(add_stats);

    void *storage = ext_storage;
    if (storage == NULL) {
        return;
    }
    extstore_get_stats(storage, &st);
    st.page_data = calloc(st.page_count, sizeof(struct extstore_page_data));
    extstore_get_page_data(storage, &st);

    for (i = 0; i < st.page_count; i++) {
        APPEND_NUM_STAT(i, "version", "%llu",
                (unsigned long long) st.page_data[i].version);
        APPEND_NUM_STAT(i, "bytes", "%llu",
                (unsigned long long) st.page_data[i].bytes_used);
        APPEND_NUM_STAT(i, "bucket", "%u",
                st.page_data[i].bucket);
        APPEND_NUM_STAT(i, "free_bucket", "%u",
                st.page_data[i].free_bucket);
    }

    free(st.page_data);
}

// Additional storage stats for the main stats output.
void storage_stats(ADD_STAT add_stats, void *c) {
    struct extstore_stats st;
    if (ext_storage) {
        STATS_LOCK();
        APPEND_STAT("extstore_memory_pressure", "%.2f", stats_state.extstore_memory_pressure);
        APPEND_STAT("extstore_compact_lost", "%llu", (unsigned long long)stats.extstore_compact_lost);
        APPEND_STAT("extstore_compact_rescues", "%llu", (unsigned long long)stats.extstore_compact_rescues);
        APPEND_STAT("extstore_compact_resc_cold", "%llu", (unsigned long long)stats.extstore_compact_resc_cold);
        APPEND_STAT("extstore_compact_resc_old", "%llu", (unsigned long long)stats.extstore_compact_resc_old);
        APPEND_STAT("extstore_compact_skipped", "%llu", (unsigned long long)stats.extstore_compact_skipped);
        STATS_UNLOCK();
        extstore_get_stats(ext_storage, &st);
        APPEND_STAT("extstore_page_allocs", "%llu", (unsigned long long)st.page_allocs);
        APPEND_STAT("extstore_page_evictions", "%llu", (unsigned long long)st.page_evictions);
        APPEND_STAT("extstore_page_reclaims", "%llu", (unsigned long long)st.page_reclaims);
        APPEND_STAT("extstore_pages_free", "%llu", (unsigned long long)st.pages_free);
        APPEND_STAT("extstore_pages_used", "%llu", (unsigned long long)st.pages_used);
        APPEND_STAT("extstore_objects_evicted", "%llu", (unsigned long long)st.objects_evicted);
        APPEND_STAT("extstore_objects_read", "%llu", (unsigned long long)st.objects_read);
        APPEND_STAT("extstore_objects_written", "%llu", (unsigned long long)st.objects_written);
        APPEND_STAT("extstore_objects_used", "%llu", (unsigned long long)st.objects_used);
        APPEND_STAT("extstore_bytes_evicted", "%llu", (unsigned long long)st.bytes_evicted);
        APPEND_STAT("extstore_bytes_written", "%llu", (unsigned long long)st.bytes_written);
        APPEND_STAT("extstore_bytes_read", "%llu", (unsigned long long)st.bytes_read);
        APPEND_STAT("extstore_bytes_used", "%llu", (unsigned long long)st.bytes_used);
        APPEND_STAT("extstore_bytes_fragmented", "%llu", (unsigned long long)st.bytes_fragmented);
        APPEND_STAT("extstore_limit_maxbytes", "%llu", (unsigned long long)(st.page_count * st.page_size));
        APPEND_STAT("extstore_io_queue", "%llu", (unsigned long long)(st.io_queue));
    }

}

// This callback runs in the IO thread.
// TODO: Some or all of this should move to the
// io_pending's callback back in the worker thread.
// It might make sense to keep the crc32c check here though.
static void _storage_get_item_cb(void *e, obj_io *io, int ret) {
    // FIXME: assumes success
    io_pending_storage_t *p = (io_pending_storage_t *)io->data;
    mc_resp *resp = p->resp;
    conn *c = p->c;
    assert(p->active == true);
    item *read_it = (item *)io->buf;
    bool miss = false;

    // TODO: How to do counters for hit/misses?
    if (ret < 1) {
        miss = true;
    } else {
        uint32_t crc2;
        uint32_t crc = (uint32_t) read_it->exptime;
        int x;
        // item is chunked, crc the iov's
        if (io->iov != NULL) {
            // first iov is the header, which we don't use beyond crc
            crc2 = crc32c(0, (char *)io->iov[0].iov_base+STORE_OFFSET, io->iov[0].iov_len-STORE_OFFSET);
            // make sure it's not sent. hack :(
            io->iov[0].iov_len = 0;
            for (x = 1; x < io->iovcnt; x++) {
                crc2 = crc32c(crc2, (char *)io->iov[x].iov_base, io->iov[x].iov_len);
            }
        } else {
            crc2 = crc32c(0, (char *)read_it+STORE_OFFSET, io->len-STORE_OFFSET);
        }

        if (crc != crc2) {
            miss = true;
            p->badcrc = true;
        }
    }

    if (miss) {
        if (p->noreply) {
            // In all GET cases, noreply means we send nothing back.
            resp->skip = true;
        } else {
            // TODO: This should be movable to the worker thread.
            // Convert the binprot response into a miss response.
            // The header requires knowing a bunch of stateful crap, so rather
            // than simply writing out a "new" miss response we mangle what's
            // already there.
            if (c->protocol == binary_prot) {
                protocol_binary_response_header *header =
                    (protocol_binary_response_header *)resp->wbuf;

                // cut the extra nbytes off of the body_len
                uint32_t body_len = ntohl(header->response.bodylen);
                uint8_t hdr_len = header->response.extlen;
                body_len -= resp->iov[p->iovec_data].iov_len + hdr_len;
                resp->tosend -= resp->iov[p->iovec_data].iov_len + hdr_len;
                header->response.extlen = 0;
                header->response.status = (uint16_t)htons(PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
                header->response.bodylen = htonl(body_len);

                // truncate the data response.
                resp->iov[p->iovec_data].iov_len = 0;
                // wipe the extlen iov... wish it was just a flat buffer.
                resp->iov[p->iovec_data-1].iov_len = 0;
                resp->chunked_data_iov = 0;
            } else {
                int i;
                // Meta commands have EN status lines for miss, rather than
                // END as a trailer as per normal ascii.
                if (resp->iov[0].iov_len >= 3
                        && memcmp(resp->iov[0].iov_base, "VA ", 3) == 0) {
                    // TODO: These miss translators should use specific callback
                    // functions attached to the io wrap. This is weird :(
                    resp->iovcnt = 1;
                    resp->iov[0].iov_len = 4;
                    resp->iov[0].iov_base = "EN\r\n";
                    resp->tosend = 4;
                } else {
                    // Wipe the iovecs up through our data injection.
                    // Allows trailers to be returned (END)
                    for (i = 0; i <= p->iovec_data; i++) {
                        resp->tosend -= resp->iov[i].iov_len;
                        resp->iov[i].iov_len = 0;
                        resp->iov[i].iov_base = NULL;
                    }
                }
                resp->chunked_total = 0;
                resp->chunked_data_iov = 0;
            }
        }
        p->miss = true;
    } else {
        assert(read_it->slabs_clsid != 0);
        // TODO: should always use it instead of ITEM_data to kill more
        // chunked special casing.
        if ((read_it->it_flags & ITEM_CHUNKED) == 0) {
            resp->iov[p->iovec_data].iov_base = ITEM_data(read_it);
        }
        p->miss = false;
    }

    p->active = false;
    //assert(c->io_wrapleft >= 0);

    return_io_pending((io_pending_t *)p);
}

int storage_get_item(conn *c, item *it, mc_resp *resp) {
#ifdef NEED_ALIGN
    item_hdr hdr;
    memcpy(&hdr, ITEM_data(it), sizeof(hdr));
#else
    item_hdr *hdr = (item_hdr *)ITEM_data(it);
#endif
    io_queue_t *q = thread_io_queue_get(c->thread, IO_QUEUE_EXTSTORE);
    size_t ntotal = ITEM_ntotal(it);
    unsigned int clsid = slabs_clsid(ntotal);
    item *new_it;
    bool chunked = false;
    if (ntotal > settings.slab_chunk_size_max) {
        // Pull a chunked item header.
        client_flags_t flags;
        FLAGS_CONV(it, flags);
        new_it = item_alloc(ITEM_key(it), it->nkey, flags, it->exptime, it->nbytes);
        assert(new_it == NULL || (new_it->it_flags & ITEM_CHUNKED));
        chunked = true;
    } else {
        new_it = do_item_alloc_pull(ntotal, clsid);
    }
    if (new_it == NULL)
        return -1;
    // so we can free the chunk on a miss
    new_it->slabs_clsid = clsid;

    io_pending_storage_t *p = do_cache_alloc(c->thread->io_cache);
    // this is a re-cast structure, so assert that we never outsize it.
    assert(sizeof(io_pending_t) >= sizeof(io_pending_storage_t));
    memset(p, 0, sizeof(io_pending_storage_t));
    p->active = true;
    p->miss = false;
    p->badcrc = false;
    p->noreply = c->noreply;
    p->thread = c->thread;
    p->return_cb = storage_return_cb;
    p->finalize_cb = storage_finalize_cb;
    // io_pending owns the reference for this object now.
    p->hdr_it = it;
    p->resp = resp;
    p->io_queue_type = IO_QUEUE_EXTSTORE;
    p->payload = offsetof(io_pending_storage_t, io_ctx);
    obj_io *eio = &p->io_ctx;

    // FIXME: error handling.
    if (chunked) {
        unsigned int ciovcnt = 0;
        size_t remain = new_it->nbytes;
        item_chunk *chunk = (item_chunk *) ITEM_schunk(new_it);
        // TODO: This might make sense as a _global_ cache vs a per-thread.
        // but we still can't load objects requiring > IOV_MAX iovs.
        // In the meantime, these objects are rare/slow enough that
        // malloc/freeing a statically sized object won't cause us much pain.
        eio->iov = malloc(sizeof(struct iovec) * IOV_MAX);
        if (eio->iov == NULL) {
            item_remove(new_it);
            do_cache_free(c->thread->io_cache, p);
            return -1;
        }

        // fill the header so we can get the full data + crc back.
        eio->iov[0].iov_base = new_it;
        eio->iov[0].iov_len = ITEM_ntotal(new_it) - new_it->nbytes;
        ciovcnt++;

        while (remain > 0) {
            chunk = do_item_alloc_chunk(chunk, remain);
            // FIXME: _pure evil_, silently erroring if item is too large.
            if (chunk == NULL || ciovcnt > IOV_MAX-1) {
                item_remove(new_it);
                free(eio->iov);
                // TODO: wrapper function for freeing up an io wrap?
                eio->iov = NULL;
                do_cache_free(c->thread->io_cache, p);
                return -1;
            }
            eio->iov[ciovcnt].iov_base = chunk->data;
            eio->iov[ciovcnt].iov_len = (remain < chunk->size) ? remain : chunk->size;
            chunk->used = (remain < chunk->size) ? remain : chunk->size;
            remain -= chunk->size;
            ciovcnt++;
        }

        eio->iovcnt = ciovcnt;
    }

    // Chunked or non chunked we reserve a response iov here.
    p->iovec_data = resp->iovcnt;
    int iovtotal = (c->protocol == binary_prot) ? it->nbytes - 2 : it->nbytes;
    if (chunked) {
        resp_add_chunked_iov(resp, new_it, iovtotal);
    } else {
        resp_add_iov(resp, "", iovtotal);
    }

    // We can't bail out anymore, so mc_resp owns the IO from here.
    resp->io_pending = (io_pending_t *)p;
    conn_resp_suspend(c, resp);

    eio->buf = (void *)new_it;
    p->c = c;

    STAILQ_INSERT_TAIL(&q->stack, (io_pending_t *)p, iop_next);

    // reference ourselves for the callback.
    eio->data = (void *)p;

    // Now, fill in io->io based on what was in our header.
#ifdef NEED_ALIGN
    eio->page_version = hdr.page_version;
    eio->page_id = hdr.page_id;
    eio->offset = hdr.offset;
#else
    eio->page_version = hdr->page_version;
    eio->page_id = hdr->page_id;
    eio->offset = hdr->offset;
#endif
    eio->len = ntotal;
    eio->mode = OBJ_IO_READ;
    eio->cb = _storage_get_item_cb;

    // FIXME: This stat needs to move to reflect # of flash hits vs misses
    // for now it's a good gauge on how often we request out to flash at
    // least.
    pthread_mutex_lock(&c->thread->stats.mutex);
    c->thread->stats.get_extstore++;
    pthread_mutex_unlock(&c->thread->stats.mutex);

    return 0;
}

void storage_submit_cb(io_queue_t *q) {
    // TODO: until we decide to port extstore's internal code to use
    // io_pending objs we "port" the IOP's into an obj_io chain just before
    // submission here.
    void *eio_head = NULL;
    while(!STAILQ_EMPTY(&q->stack)) {
        io_pending_t *p = STAILQ_FIRST(&q->stack);
        STAILQ_REMOVE_HEAD(&q->stack, iop_next);
        // FIXME: re-evaluate this.
        obj_io *io_ctx = (obj_io *) ((char *)p + p->payload);
        io_ctx->next = eio_head;
        eio_head = io_ctx;
    }
    extstore_submit(q->ctx, eio_head);
}

// Runs locally in worker thread.
static void recache_or_free(io_pending_t *pending) {
    // re-cast to our specific struct.
    io_pending_storage_t *p = (io_pending_storage_t *)pending;

    conn *c = p->c;
    obj_io *io = &p->io_ctx;
    assert(io != NULL);
    item *it = (item *)io->buf;
    assert(c != NULL);
    bool do_free = true;
    if (p->active) {
        // If request never dispatched, free the read buffer but leave the
        // item header alone.
        do_free = false;
        size_t ntotal = ITEM_ntotal(p->hdr_it);
        slabs_free(it, slabs_clsid(ntotal));

        p->resp->suspended = false;
        c->resps_suspended--;
        // this is an unsubmitted IO, so unlink ourselves.
        // (note: slow but should be very rare op)
        io_queue_t *q = thread_io_queue_get(p->thread, p->io_queue_type);
        STAILQ_REMOVE(&q->stack, pending, _io_pending_t, iop_next);

        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.get_aborted_extstore++;
        pthread_mutex_unlock(&c->thread->stats.mutex);
    } else if (p->miss) {
        // If request was ultimately a miss, unlink the header.
        do_free = false;
        size_t ntotal = ITEM_ntotal(p->hdr_it);
        item_unlink(p->hdr_it);
        slabs_free(it, slabs_clsid(ntotal));
        pthread_mutex_lock(&c->thread->stats.mutex);
        c->thread->stats.miss_from_extstore++;
        if (p->badcrc)
            c->thread->stats.badcrc_from_extstore++;
        pthread_mutex_unlock(&c->thread->stats.mutex);
    } else if (settings.ext_recache_rate) {
        // hashvalue is cuddled during store
        uint32_t hv = (uint32_t)it->time;
        // opt to throw away rather than wait on a lock.
        void *hold_lock = item_trylock(hv);
        if (hold_lock != NULL) {
            item *h_it = p->hdr_it;
            uint8_t flags = ITEM_LINKED|ITEM_FETCHED|ITEM_ACTIVE;
            // Item must be recently hit at least twice to recache.
            if (((h_it->it_flags & flags) == flags) &&
                    h_it->time > current_time - ITEM_UPDATE_INTERVAL &&
                    c->recache_counter++ % settings.ext_recache_rate == 0) {
                do_free = false;
                // In case it's been updated.
                it->exptime = h_it->exptime;
                it->it_flags &= ~ITEM_LINKED;
                it->refcount = 0;
                it->h_next = NULL; // might not be necessary.
                STORAGE_delete(c->thread->storage, h_it);
                item_replace(h_it, it, hv, ITEM_get_cas(h_it));
                pthread_mutex_lock(&c->thread->stats.mutex);
                c->thread->stats.recache_from_extstore++;
                pthread_mutex_unlock(&c->thread->stats.mutex);
            }
        }
        if (hold_lock)
            item_trylock_unlock(hold_lock);
    }
    if (do_free)
        slabs_free(it, ITEM_clsid(it));

    p->io_ctx.buf = NULL;
    p->io_ctx.next = NULL;
    p->active = false;

    // TODO: reuse lock and/or hv.
    item_remove(p->hdr_it);
}

// Called after an IO has been returned to the worker thread.
static void storage_return_cb(io_pending_t *pending) {
    conn_resp_unsuspend(pending->c, pending->resp);
}

// Called after responses have been transmitted. Need to free up related data.
static void storage_finalize_cb(io_pending_t *pending) {
    recache_or_free(pending);
    io_pending_storage_t *p = (io_pending_storage_t *)pending;
    obj_io *io = &p->io_ctx;
    // malloc'ed iovec list used for chunked extstore fetches.
    if (io->iov) {
        free(io->iov);
        io->iov = NULL;
    }
    // don't need to free the main context, since it's embedded.
}

/*
 * WRITE FLUSH THREAD
 */

static int storage_write(void *storage, const int clsid, const int item_age) {
    int did_moves = 0;
    struct lru_pull_tail_return it_info;

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
    client_flags_t flags;
    if ((it->it_flags & ITEM_HDR) == 0 &&
            (item_age == 0 || current_time - it->time > item_age)) {
        FLAGS_CONV(it, flags);
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
            // NOTE: write bucket vs free page bucket will disambiguate once
            // lowttl feature is better understood.
            if (extstore_write_request(storage, bucket, bucket, &io) == 0) {
                // cuddle the hash value into the time field so we don't have
                // to recalculate it.
                item *buf_it = (item *) io.buf;
                buf_it->time = it_info.hv;
                // copy from past the headers + time headers.
                // TODO: should be in items.c
                if (it->it_flags & ITEM_CHUNKED) {
                    // Need to loop through the item and copy
                    item_chunk *sch = (item_chunk *) ITEM_schunk(it);
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
                item_replace(it, hdr_it, it_info.hv, ITEM_get_cas(it));
                do_item_remove(hdr_it);
                did_moves = 1;
                LOGGER_LOG(NULL, LOG_EVICTIONS, LOGGER_EXTSTORE_WRITE, it, bucket);
            } else {
                /* Failed to write for some reason, can't continue. */
                slabs_free(hdr_it, ITEM_clsid(hdr_it));
            }
        }
    }
    do_item_remove(it);
    item_unlock(it_info.hv);
    return did_moves;
}

static pthread_t storage_write_tid;
static pthread_mutex_t storage_write_plock;
#define WRITE_SLEEP_MIN 200

static void *storage_write_thread(void *arg) {
    void *storage = arg;
    // NOTE: ignoring overflow since that would take years of uptime in a
    // specific load pattern of never going to sleep.
    unsigned int backoff[MAX_NUMBER_OF_SLAB_CLASSES] = {0};
    unsigned int counter = 0;
    useconds_t to_sleep = WRITE_SLEEP_MIN;
    logger *l = logger_create();
    if (l == NULL) {
        fprintf(stderr, "Failed to allocate logger for storage compaction thread\n");
        abort();
    }

    pthread_mutex_lock(&storage_write_plock);
    // The compaction checker is CPU intensive, so we do a loose fudging to
    // only activate it once every "slab page size" worth of bytes written.
    // I was calling the compact checker once per run through this main loop,
    // but we can end up doing lots of short loops without sleeping and end up
    // calling the compact checker pretty frequently.
    int check_compact = settings.slab_page_size;

    while (1) {
        // cache per-loop to avoid calls to the slabs_clsid() search loop
        int min_class = slabs_clsid(settings.ext_item_size);
        unsigned int global_pages = global_page_pool_size(NULL);
        bool do_sleep = true;
        int target_pages = 0;
        if (global_pages < settings.ext_global_pool_min) {
            target_pages = settings.ext_global_pool_min - global_pages;
        } else if (global_pages == settings.ext_global_pool_min) {
            // start flushing a little early to lessen pressure on page mover
            target_pages = 1;
        }
        counter++;
        if (to_sleep > settings.ext_max_sleep)
            to_sleep = settings.ext_max_sleep;

        // the largest items have the least overhead from going to disk.
        for (int x = MAX_NUMBER_OF_SLAB_CLASSES-1; x > 0; x--) {
            bool did_move = false;
            bool mem_limit_reached = false;
            unsigned int chunks_free;
            int item_age;

            if (min_class > x || (backoff[x] && (counter % backoff[x] != 0))) {
                continue;
            }

            // Avoid extra slab lock calls during heavy writing.
            unsigned int chunks_perpage = 0;
            chunks_free = slabs_available_chunks(x, &mem_limit_reached,
                    &chunks_perpage);

            if (chunks_perpage == 0) {
                // no slab class here, skip.
                continue;
            }
            // Loose estimate for cutting the calls to compacter
            unsigned int chunk_size = settings.slab_page_size / chunks_perpage;
            // NOTE: stupid heuristic: we need to avoid over-flushing small
            // slab classes because the relative size of the headers is close
            // enough to cause runaway problems.
            unsigned int max_pages = 0;
            unsigned int target = 0;
            if (chunk_size < 500) {
                max_pages = 3;
            } else if (chunk_size < 1000) {
                max_pages = 4;
            } else if (chunk_size < 2000) {
                max_pages = 5;
            } else {
                max_pages = target_pages;
            }

            if (target_pages > max_pages) {
                target = chunks_perpage * max_pages;
            } else {
                target = chunks_perpage * target_pages;
            }

            // storage_write() will fail and cut loop after filling write buffer.
            while (1) {
                // if we are low on chunks and no spare, push out early.
                if (chunks_free < target) {
                    item_age = 0;
                } else {
                    item_age = settings.ext_item_age;
                }
                if (storage_write(storage, x, item_age)) {
                    chunks_free++; // Allow stopping if we've done enough this loop
                    check_compact -= chunk_size;
                    // occasionally kick the compact checker.
                    if (check_compact < 0) {
                        pthread_cond_signal(&storage_compact_cond);
                        check_compact = settings.slab_page_size;
                    }
                    did_move = true;
                    do_sleep = false;
                    if (to_sleep > WRITE_SLEEP_MIN)
                        to_sleep /= 2;
                } else {
                    break;
                }
            }

            if (!did_move) {
                backoff[x]++;
            } else {
                backoff[x] = 1;
            }
        }

        // flip lock so we can be paused or stopped
        pthread_mutex_unlock(&storage_write_plock);
        if (do_sleep) {
            // Only do backoffs on other slab classes if we're actively
            // flushing at least one class.
            for (int x = 0; x < MAX_NUMBER_OF_SLAB_CLASSES; x++) {
                backoff[x] = 1;
            }

            // call the compact checker occasionally even if we're just
            // sleeping.
            check_compact -= to_sleep * 10;
            if (check_compact < 0) {
                pthread_cond_signal(&storage_compact_cond);
                check_compact = settings.slab_page_size;
            }

            usleep(to_sleep);
            to_sleep++;
        }
        pthread_mutex_lock(&storage_write_plock);
    }
    return NULL;
}

// TODO
// logger needs logger_destroy() to exist/work before this is safe.
/*int stop_storage_write_thread(void) {
    int ret;
    pthread_mutex_lock(&lru_maintainer_lock);
    do_run_lru_maintainer_thread = 0;
    pthread_mutex_unlock(&lru_maintainer_lock);
    // WAKEUP SIGNAL
    if ((ret = pthread_join(lru_maintainer_tid, NULL)) != 0) {
        fprintf(stderr, "Failed to stop LRU maintainer thread: %s\n", strerror(ret));
        return -1;
    }
    settings.lru_maintainer_thread = false;
    return 0;
}*/

void storage_write_pause(void) {
    pthread_mutex_lock(&storage_write_plock);
}

void storage_write_resume(void) {
    pthread_mutex_unlock(&storage_write_plock);
}

int start_storage_write_thread(void *arg) {
    int ret;

    pthread_mutex_init(&storage_write_plock, NULL);
    if ((ret = pthread_create(&storage_write_tid, NULL,
        storage_write_thread, arg)) != 0) {
        fprintf(stderr, "Can't create storage_write thread: %s\n",
            strerror(ret));
        return -1;
    }
    thread_setname(storage_write_tid, "mc-ext-write");

    return 0;
}

/*** COMPACTOR ***/
typedef struct __storage_buk {
    unsigned int bucket;
    unsigned int low_page;
    unsigned int lowest_page;
    uint64_t low_version;
    uint64_t lowest_version;
    unsigned int pages_free;
    unsigned int pages_used;
    unsigned int pages_total;
    unsigned int bytes_fragmented; // fragmented bytes for low page
    bool do_compact; // indicate this bucket should do a compaction.
    bool do_compact_drop;
} _storage_buk;

struct _compact_flags {
    unsigned int drop_unread : 1;
    unsigned int has_coldcompact : 1;
    unsigned int has_old : 1;
    unsigned int use_old : 1;
};

/* Fetch stats from the external storage system and decide to compact.
 */
static int storage_compact_check(void *storage, logger *l,
        uint32_t *page_id, uint64_t *page_version,
        uint64_t *page_size, struct _compact_flags *flags) {
    struct extstore_stats st;
    _storage_buk buckets[PAGE_BUCKET_COUNT];
    _storage_buk *buk = NULL;
    uint64_t frag_limit;
    extstore_get_stats(storage, &st);
    if (st.pages_used == 0)
        return 0;

    for (int x = 0; x < PAGE_BUCKET_COUNT; x++) {
        memset(&buckets[x], 0, sizeof(_storage_buk));
        buckets[x].low_version = ULLONG_MAX;
        buckets[x].lowest_version = ULLONG_MAX;
    }
    flags->drop_unread = 0;

    frag_limit = st.page_size * settings.ext_max_frag;
    LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_FRAGINFO,
            NULL, settings.ext_max_frag, frag_limit);
    st.page_data = calloc(st.page_count, sizeof(struct extstore_page_data));
    extstore_get_page_data(storage, &st);

    // find either the most fragmented page or the lowest version.
    for (int x = 0; x < st.page_count; x++) {
        buk = &buckets[st.page_data[x].free_bucket];
        buk->pages_total++;
        if (st.page_data[x].version == 0) {
            buk->pages_free++;
            // free pages don't contribute after this point.
            continue;
        } else {
            buk->pages_used++;
        }

        // skip pages actively being used.
        if (st.page_data[x].active) {
            continue;
        }

        if (st.page_data[x].version < buk->lowest_version) {
            buk->lowest_page = x;
            buk->lowest_version = st.page_data[x].version;
        }
        // track the most fragmented page.
        unsigned int frag = st.page_size - st.page_data[x].bytes_used;
        if (st.page_data[x].bytes_used < frag_limit && frag > buk->bytes_fragmented) {
            buk->low_page = x;
            buk->low_version = st.page_data[x].version;
            buk->bytes_fragmented = frag;
        }
    }
    *page_size = st.page_size;
    free(st.page_data);

    buk = &buckets[PAGE_BUCKET_COLDCOMPACT];
    if (buk->pages_total != 0) {
        flags->has_coldcompact = 1;
        if (buk->pages_free == 0 && buk->lowest_version != ULLONG_MAX) {
            extstore_evict_page(storage, buk->lowest_page, buk->lowest_version);
            return 0;
        }
    }

    buk = &buckets[PAGE_BUCKET_OLD];
    if (buk->pages_total != 0) {
        flags->has_old = 1;
        if (buk->pages_free == 0 && buk->lowest_version != ULLONG_MAX) {
            extstore_evict_page(storage, buk->lowest_page, buk->lowest_version);
            return 0;
        }
    }

    for (int x = 0; x < PAGE_BUCKET_COUNT; x++) {
        buk = &buckets[x];
        assert(buk->pages_total == (buk->pages_used + buk->pages_free));
        unsigned int pages_total = buk->pages_total;
        // only process buckets which have dedicated pages assigned.
        // LOWTTL skips compaction.
        if (pages_total == 0 || x == PAGE_BUCKET_LOWTTL)
            continue;

        if (buk->pages_free < settings.ext_compact_under) {
            if (buk->low_version != ULLONG_MAX) {
                // found a normally defraggable page.
                *page_id = buk->low_page;
                *page_version = buk->low_version;
                return 1;
            } else if (buk->pages_free < settings.ext_drop_under
                    && buk->lowest_version != ULLONG_MAX) {

                if (x == PAGE_BUCKET_COLDCOMPACT || x == PAGE_BUCKET_OLD) {
                    // this freeing technique doesn't apply to these buckets.
                    // instead these buckets are eviction or normal
                    // defragmentation only.
                    continue;
                }
                // Nothing defraggable. Check for other usable conditions.
                if (settings.ext_drop_unread) {
                    flags->drop_unread = 1;
                }

                // If OLD and/or COLDCOMPACT pages exist we should always have
                // one free page in those buckets, so we can always attempt to
                // defrag into them.
                // If only COLDCOMPACT exists this will attempt to segment off
                // parts of a page that haven't been used.
                // If OLD exists everything else in this "oldest page" goes
                // into the OLD stream.
                if (flags->drop_unread || flags->has_coldcompact || flags->has_old) {
                    // only actually use the old flag if we can't compact.
                    flags->use_old = flags->has_old;
                    *page_id = buk->lowest_page;
                    *page_version = buk->lowest_version;
                    return 1;
                }
            }
        }
    }

    return 0;
}

#define MIN_STORAGE_COMPACT_SLEEP 1000

struct storage_compact_wrap {
    obj_io io;
    pthread_mutex_t lock; // gates the bools.
    bool done;
    bool submitted;
    bool miss; // version flipped out from under us
};

static void storage_compact_readback(void *storage, logger *l,
        struct _compact_flags flags, char *readback_buf,
        uint32_t page_id, uint64_t page_version, uint32_t page_offset, uint64_t read_size) {
    uint64_t offset = 0;
    unsigned int rescues = 0;
    unsigned int lost = 0;
    unsigned int skipped = 0;
    unsigned int rescue_cold = 0;
    unsigned int rescue_old = 0;

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
            int bucket = flags.use_old ? PAGE_BUCKET_OLD : PAGE_BUCKET_COMPACT;
            refcount_incr(hdr_it);

            // Check validity but don't bother removing it.
            if ((hdr_it->it_flags & ITEM_HDR) && !item_is_flushed(hdr_it) &&
                   (hdr_it->exptime == 0 || hdr_it->exptime > current_time)) {
                hdr = (item_hdr *)ITEM_data(hdr_it);
                if (hdr->page_id == page_id && hdr->page_version == page_version
                        && hdr->offset == (int)offset + page_offset) {
                    // Item header is still completely valid.
                    extstore_delete(storage, page_id, page_version, 1, ntotal);
                    // special case inactive items.
                    do_write = true;
                    if (GET_LRU(hdr_it->slabs_clsid) == COLD_LRU) {
                        if (flags.has_coldcompact) {
                            // Write the cold items to a different stream.
                            bucket = PAGE_BUCKET_COLDCOMPACT;
                        } else if (flags.drop_unread) {
                            do_write = false;
                            skipped++;
                        }
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
                    if (extstore_write_request(storage, bucket, bucket, &io) == 0) {
                        memcpy(io.buf, it, io.len);
                        extstore_write(storage, &io);
                        do_update = true;
                        break;
                    } else {
                        usleep(1000);
                    }
                }

                if (do_update) {
                    bool rescued = false;
                    if (it->refcount == 2) {
                        hdr->page_version = io.page_version;
                        hdr->page_id = io.page_id;
                        hdr->offset = io.offset;
                        rescued = true;
                    } else {
                        // re-alloc and replace header.
                        client_flags_t flags;
                        FLAGS_CONV(hdr_it, flags);
                        item *new_it = do_item_alloc(ITEM_key(hdr_it), hdr_it->nkey, flags, hdr_it->exptime, sizeof(item_hdr));
                        if (new_it) {
                            // need to preserve the original item flags, but we
                            // start unlinked, with linked being added during
                            // item_replace below.
                            new_it->it_flags = hdr_it->it_flags & (~ITEM_LINKED);
                            new_it->time = hdr_it->time;
                            new_it->nbytes = hdr_it->nbytes;

                            // copy the hdr data.
                            item_hdr *new_hdr = (item_hdr *) ITEM_data(new_it);
                            new_hdr->page_version = io.page_version;
                            new_hdr->page_id = io.page_id;
                            new_hdr->offset = io.offset;

                            // replace the item in the hash table.
                            item_replace(hdr_it, new_it, hv, ITEM_get_cas(hdr_it));
                            do_item_remove(new_it); // release our reference.
                            rescued = true;
                        } else {
                            lost++;
                        }
                    }

                    if (rescued) {
                        rescues++;
                        if (bucket == PAGE_BUCKET_COLDCOMPACT) {
                            rescue_cold++;
                        } else if (bucket == PAGE_BUCKET_OLD) {
                            rescue_old++;
                        }
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
    stats.extstore_compact_resc_cold += rescue_cold;
    stats.extstore_compact_resc_old += rescue_old;
    STATS_UNLOCK();
    LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_READ_END,
            NULL, page_id, offset, rescues, lost, skipped);
}

// wrap lock is held while waiting for this callback, preventing caller thread
// from fast-looping.
static void _storage_compact_cb(void *e, obj_io *io, int ret) {
    struct storage_compact_wrap *wrap = (struct storage_compact_wrap *)io->data;
    assert(wrap->submitted == true);

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
    bool compacting = false;
    uint64_t page_version = 0;
    uint64_t page_size = 0;
    uint32_t page_offset = 0;
    uint32_t page_id = 0;
    struct _compact_flags flags;
    char *readback_buf = NULL;
    struct storage_compact_wrap wrap;
    memset(&flags, 0, sizeof(flags));

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
    wrap.io.iov = NULL;
    wrap.io.buf = (void *)readback_buf;

    wrap.io.len = settings.ext_wbuf_size;
    wrap.io.mode = OBJ_IO_READ;
    wrap.io.cb = _storage_compact_cb;
    pthread_mutex_lock(&storage_compact_plock);

    while (1) {
        if (!compacting && storage_compact_check(storage, l,
                    &page_id, &page_version, &page_size, &flags)) {
            page_offset = 0;
            compacting = true;
            LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_START,
                    NULL, page_id, page_version);
        } else {
            pthread_cond_wait(&storage_compact_cond, &storage_compact_plock);
        }

        while (compacting) {
            pthread_mutex_lock(&wrap.lock);
            if (page_offset < page_size && !wrap.done && !wrap.submitted) {
                wrap.io.page_version = page_version;
                wrap.io.page_id = page_id;
                wrap.io.offset = page_offset;
                // FIXME: should be smarter about io->next (unlink at use?)
                wrap.io.next = NULL;
                wrap.submitted = true;
                wrap.miss = false;

                extstore_submit_bg(storage, &wrap.io);
            } else if (wrap.miss) {
                LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_ABORT,
                        NULL, page_id);
                wrap.done = false;
                wrap.submitted = false;
                compacting = false;
            } else if (wrap.submitted && wrap.done) {
                LOGGER_LOG(l, LOG_SYSEVENTS, LOGGER_COMPACT_READ_START,
                        NULL, page_id, page_offset);
                storage_compact_readback(storage, l, flags,
                        readback_buf, page_id, page_version, page_offset,
                        settings.ext_wbuf_size);
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
                // short cooling period between defragmentation runs.
                usleep(MIN_STORAGE_COMPACT_SLEEP);
            }
            pthread_mutex_unlock(&wrap.lock);
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
    pthread_cond_init(&storage_compact_cond, NULL);
    if ((ret = pthread_create(&storage_compact_tid, NULL,
        storage_compact_thread, arg)) != 0) {
        fprintf(stderr, "Can't create storage_compact thread: %s\n",
            strerror(ret));
        return -1;
    }
    thread_setname(storage_compact_tid, "mc-ext-compact");

    return 0;
}

/*** UTILITY ***/
// /path/to/file:100G:bucket1
// FIXME: Modifies argument. copy instead?
struct extstore_conf_file *storage_conf_parse(char *arg, unsigned int page_size) {
    struct extstore_conf_file *cf = NULL;
    char *b = NULL;
    char *p = strtok_r(arg, ":", &b);
    char unit = 0;
    uint64_t multiplier = 0;
    int base_size = 0;
    if (p == NULL)
        goto error;
    // First arg is the filepath.
    cf = calloc(1, sizeof(struct extstore_conf_file));
    if (cf == NULL) {
       fprintf(stderr, "Failed to allocate extstore config structure\n");
       goto error;
    }

    cf->file = strdup(p);
    if (cf->file == NULL) {
       fprintf(stderr, "Failed to allocate extstore path string\n");
       goto error;
    }

    p = strtok_r(NULL, ":", &b);
    if (p == NULL) {
        fprintf(stderr, "must supply size to ext_path, ie: ext_path=/f/e:64m (M|G|T|P supported)\n");
        goto error;
    }
    unit = tolower(p[strlen(p)-1]);
    p[strlen(p)-1] = '\0';
    // sigh.
    switch (unit) {
        case 'm':
            multiplier = 1024 * 1024;
            break;
        case 'g':
            multiplier = 1024 * 1024 * 1024;
            break;
        case 't':
            multiplier = 1024 * 1024;
            multiplier *= 1024 * 1024;
            break;
        case 'p':
            multiplier = 1024 * 1024;
            multiplier *= 1024 * 1024 * 1024;
            break;
        default:
            fprintf(stderr, "must supply size to ext_path, ie: ext_path=/f/e:64m (M|G|T|P supported)\n");
            goto error;
    }
    base_size = atoi(p);
    multiplier *= base_size;
    // page_count is nearest-but-not-larger-than pages * psize
    cf->page_count = multiplier / page_size;
    assert(page_size * cf->page_count <= multiplier);
    if (cf->page_count == 0) {
        fprintf(stderr, "supplied ext_path has zero size, cannot use\n");
        goto error;
    }

    // final token would be a default free bucket
    p = strtok_r(NULL, ":", &b);
    // TODO: We reuse the original DEFINES for now,
    // but if lowttl gets split up this needs to be its own set.
    if (p != NULL) {
        if (strcmp(p, "compact") == 0) {
            cf->free_bucket = PAGE_BUCKET_COMPACT;
        } else if (strcmp(p, "lowttl") == 0) {
            cf->free_bucket = PAGE_BUCKET_LOWTTL;
        } else if (strcmp(p, "chunked") == 0) {
            cf->free_bucket = PAGE_BUCKET_CHUNKED;
        } else if (strcmp(p, "default") == 0) {
            cf->free_bucket = PAGE_BUCKET_DEFAULT;
        } else if (strcmp(p, "coldcompact") == 0) {
            cf->free_bucket = PAGE_BUCKET_COLDCOMPACT;
        } else if (strcmp(p, "old") == 0) {
            cf->free_bucket = PAGE_BUCKET_OLD;
        } else {
            fprintf(stderr, "Unknown extstore bucket: %s\n", p);
            goto error;
        }
    } else {
        // TODO: is this necessary?
        cf->free_bucket = PAGE_BUCKET_DEFAULT;
    }

    return cf;
error:
    if (cf) {
        if (cf->file)
            free(cf->file);
        free(cf);
    }
    return NULL;
}

struct storage_settings {
    struct extstore_conf_file *storage_file;
    struct extstore_conf ext_cf;
};

void *storage_init_config(struct settings *s) {
    struct storage_settings *cf = calloc(1, sizeof(struct storage_settings));

    s->ext_item_size = 512;
    s->ext_item_age = UINT_MAX;
    s->ext_low_ttl = 0;
    s->ext_recache_rate = 2000;
    s->ext_max_frag = 0.8;
    s->ext_drop_unread = false;
    s->ext_wbuf_size = 1024 * 1024 * 4;
    s->ext_compact_under = 0;
    s->ext_drop_under = 0;
    s->ext_max_sleep = 1000000;
    s->slab_automove_freeratio = 0.01;
    s->ext_page_size = 1024 * 1024 * 64;
    s->ext_io_threadcount = 1;
    cf->ext_cf.page_size = settings.ext_page_size;
    cf->ext_cf.wbuf_size = settings.ext_wbuf_size;
    cf->ext_cf.io_threadcount = settings.ext_io_threadcount;
    cf->ext_cf.io_depth = 1;
    cf->ext_cf.page_buckets = PAGE_BUCKET_COUNT;
    cf->ext_cf.wbuf_count = cf->ext_cf.page_buckets;

    return cf;
}

// TODO: pass settings struct?
int storage_read_config(void *conf, char **subopt) {
    struct storage_settings *cf = conf;
    struct extstore_conf *ext_cf = &cf->ext_cf;
    char *subopts_value;

    enum {
        EXT_PAGE_SIZE,
        EXT_WBUF_SIZE,
        EXT_THREADS,
        EXT_IO_DEPTH,
        EXT_PATH,
        EXT_ITEM_SIZE,
        EXT_ITEM_AGE,
        EXT_LOW_TTL,
        EXT_RECACHE_RATE,
        EXT_COMPACT_UNDER,
        EXT_DROP_UNDER,
        EXT_MAX_SLEEP,
        EXT_MAX_FRAG,
        EXT_DROP_UNREAD,
        SLAB_AUTOMOVE_FREERATIO, // FIXME: move this back?
    };

    char *const subopts_tokens[] = {
        [EXT_PAGE_SIZE] = "ext_page_size",
        [EXT_WBUF_SIZE] = "ext_wbuf_size",
        [EXT_THREADS] = "ext_threads",
        [EXT_IO_DEPTH] = "ext_io_depth",
        [EXT_PATH] = "ext_path",
        [EXT_ITEM_SIZE] = "ext_item_size",
        [EXT_ITEM_AGE] = "ext_item_age",
        [EXT_LOW_TTL] = "ext_low_ttl",
        [EXT_RECACHE_RATE] = "ext_recache_rate",
        [EXT_COMPACT_UNDER] = "ext_compact_under",
        [EXT_DROP_UNDER] = "ext_drop_under",
        [EXT_MAX_SLEEP] = "ext_max_sleep",
        [EXT_MAX_FRAG] = "ext_max_frag",
        [EXT_DROP_UNREAD] = "ext_drop_unread",
        [SLAB_AUTOMOVE_FREERATIO] = "slab_automove_freeratio",
        NULL
    };

    switch (getsubopt(subopt, subopts_tokens, &subopts_value)) {
        case EXT_PAGE_SIZE:
            if (cf->storage_file) {
                fprintf(stderr, "Must specify ext_page_size before any ext_path arguments\n");
                return 1;
            }
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_page_size argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &ext_cf->page_size)) {
                fprintf(stderr, "could not parse argument to ext_page_size\n");
                return 1;
            }
            ext_cf->page_size *= 1024 * 1024; /* megabytes */
            break;
        case EXT_WBUF_SIZE:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_wbuf_size argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &ext_cf->wbuf_size)) {
                fprintf(stderr, "could not parse argument to ext_wbuf_size\n");
                return 1;
            }
            ext_cf->wbuf_size *= 1024 * 1024; /* megabytes */
            settings.ext_wbuf_size = ext_cf->wbuf_size;
            break;
        case EXT_THREADS:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_threads argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &ext_cf->io_threadcount)) {
                fprintf(stderr, "could not parse argument to ext_threads\n");
                return 1;
            }
            break;
        case EXT_IO_DEPTH:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_io_depth argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &ext_cf->io_depth)) {
                fprintf(stderr, "could not parse argument to ext_io_depth\n");
                return 1;
            }
            break;
        case EXT_ITEM_SIZE:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_item_size argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &settings.ext_item_size)) {
                fprintf(stderr, "could not parse argument to ext_item_size\n");
                return 1;
            }
            break;
        case EXT_ITEM_AGE:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_item_age argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &settings.ext_item_age)) {
                fprintf(stderr, "could not parse argument to ext_item_age\n");
                return 1;
            }
            break;
        case EXT_LOW_TTL:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_low_ttl argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &settings.ext_low_ttl)) {
                fprintf(stderr, "could not parse argument to ext_low_ttl\n");
                return 1;
            }
            break;
        case EXT_RECACHE_RATE:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_recache_rate argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &settings.ext_recache_rate)) {
                fprintf(stderr, "could not parse argument to ext_recache_rate\n");
                return 1;
            }
            break;
        case EXT_COMPACT_UNDER:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_compact_under argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &settings.ext_compact_under)) {
                fprintf(stderr, "could not parse argument to ext_compact_under\n");
                return 1;
            }
            break;
        case EXT_DROP_UNDER:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_drop_under argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &settings.ext_drop_under)) {
                fprintf(stderr, "could not parse argument to ext_drop_under\n");
                return 1;
            }
            break;
        case EXT_MAX_SLEEP:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_max_sleep argument\n");
                return 1;
            }
            if (!safe_strtoul(subopts_value, &settings.ext_max_sleep)) {
                fprintf(stderr, "could not parse argument to ext_max_sleep\n");
                return 1;
            }
            break;
        case EXT_MAX_FRAG:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing ext_max_frag argument\n");
                return 1;
            }
            if (!safe_strtod(subopts_value, &settings.ext_max_frag)) {
                fprintf(stderr, "could not parse argument to ext_max_frag\n");
                return 1;
            }
            break;
        case SLAB_AUTOMOVE_FREERATIO:
            if (subopts_value == NULL) {
                fprintf(stderr, "Missing slab_automove_freeratio argument\n");
                return 1;
            }
            if (!safe_strtod(subopts_value, &settings.slab_automove_freeratio)) {
                fprintf(stderr, "could not parse argument to slab_automove_freeratio\n");
                return 1;
            }
            break;
        case EXT_DROP_UNREAD:
            settings.ext_drop_unread = true;
            break;
        case EXT_PATH:
            if (subopts_value) {
                struct extstore_conf_file *tmp = storage_conf_parse(subopts_value, ext_cf->page_size);
                if (tmp == NULL) {
                    fprintf(stderr, "failed to parse ext_path argument\n");
                    return 1;
                }
                if (cf->storage_file != NULL) {
                    tmp->next = cf->storage_file;
                }
                cf->storage_file = tmp;
            } else {
                fprintf(stderr, "missing argument to ext_path, ie: ext_path=/d/file:5G\n");
                return 1;
            }
            break;
        default:
            fprintf(stderr, "Illegal suboption \"%s\"\n", subopts_value);
            return 1;
    }

    return 0;
}

int storage_check_config(void *conf) {
    struct storage_settings *cf = conf;
    struct extstore_conf *ext_cf = &cf->ext_cf;

    if (cf->storage_file) {
        if (settings.item_size_max > ext_cf->wbuf_size) {
            fprintf(stderr, "-I (item_size_max: %d) cannot be larger than ext_wbuf_size: %d\n",
                settings.item_size_max, ext_cf->wbuf_size);
            return 1;
        }

        if (settings.udpport) {
            fprintf(stderr, "Cannot use UDP with extstore enabled (-U 0 to disable)\n");
            return 1;
        }

        return 0;
    }

    return 2;
}

void *storage_init(void *conf) {
    struct storage_settings *cf = conf;
    struct extstore_conf *ext_cf = &cf->ext_cf;

    enum extstore_res eres;
    void *storage = NULL;
    if (settings.ext_compact_under == 0) {
        // If changing the default fraction, change the help text as well.
        settings.ext_compact_under = cf->storage_file->page_count * 0.01;
        settings.ext_drop_under = cf->storage_file->page_count * 0.01;
        if (settings.ext_compact_under < 1) {
            settings.ext_compact_under = 1;
        }
        if (settings.ext_drop_under < 1) {
            settings.ext_drop_under = 1;
        }
    }
    crc32c_init();

    settings.ext_global_pool_min = 0;
    storage = extstore_init(cf->storage_file, ext_cf, &eres);
    if (storage == NULL) {
        fprintf(stderr, "Failed to initialize external storage: %s\n",
                extstore_err(eres));
        if (eres == EXTSTORE_INIT_OPEN_FAIL) {
            perror("extstore open");
        }
        return NULL;
    }

    return storage;
}

#endif

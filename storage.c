/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#ifdef EXTSTORE
#include "storage.h"
#include <storage_engine/storage_engine.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <dlfcn.h>

typedef storage_engine *(*create_engine_func)(void);

static void *plugin = NULL;

/* Dynamically load plugin */
storage_engine *load_engine(char *path) {
    create_engine_func create_engine;

    plugin = dlopen(path, RTLD_LAZY);
    if (plugin == NULL) {
        char *error = dlerror();
        if(error) {
            fprintf(stderr, "Error loading storage engine plugin: %s\n", error);
        } else {
            fprintf(stderr, "Error loading storage engine plugin\n");
        }
        return NULL;
    }

    *(void **)(&create_engine) = dlsym(plugin, "create_engine");
    if (create_engine == NULL) {
        char *error = dlerror();
        if(error) {
            fprintf(stderr, "Error loading storage engine plugin: %s\n", error);
        } else {
            fprintf(stderr, "Error loading storage engine plugin\n");
        }
        return NULL;
    }

    return (*create_engine)();
}


void unload_engine() {
    if(plugin != NULL)
        dlclose(plugin);
}



/*** WRITE FLUSH THREAD ***/

static int storage_write(storage_engine *engine, const int clsid, const int item_age) {
    int did_moves = 0;
    struct lru_pull_tail_return it_info;

    it_info.it = NULL;
    lru_pull_tail(clsid, COLD_LRU, 0, LRU_PULL_RETURN_ITEM, 0, &it_info);
    /* Item is locked, and we have a reference to it. */
    if (it_info.it == NULL) {
        return did_moves;
    }

    // If item is not in storage yet
    // Allocate space for new header item
    // Send item to storage

    item *it = it_info.it;
    /* First, storage for the header object */

    uint32_t flags;
    if ((it->it_flags & ITEM_HDR) == 0 &&
            (item_age == 0 || current_time - it->time > item_age)) {
        FLAGS_CONV(it, flags);
        item *hdr_it = do_item_alloc(ITEM_key(it), it->nkey, flags, it->exptime, engine->locator_size);

        /* Run the storage write understanding the start of the item is dirty.
         * We will fill it (time/exptime/etc) from the header item on read.
         */
        if (hdr_it != NULL) {
            hdr_it->it_flags |= ITEM_HDR;

            int ret = engine->write_item(it, it_info.hv, ITEM_data(hdr_it));
            if(ret == 0) {
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
            } else {
                slabs_free(hdr_it, ITEM_ntotal(hdr_it), ITEM_clsid(hdr_it));
            }
        }
    }
    do_item_remove(it);
    item_unlock(it_info.hv);
    return did_moves;
}



static pthread_t storage_write_tid;
static pthread_mutex_t storage_write_plock;
#define WRITE_SLEEP_MAX 1000000
#define WRITE_SLEEP_MIN 500

static void *storage_write_thread(void *arg) {
    storage_engine *storage = arg;
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

    while (1) {
        // cache per-loop to avoid calls to the slabs_clsid() search loop
        int min_class = slabs_clsid(settings.ext_item_size);
        bool do_sleep = true;
        counter++;
        if (to_sleep > WRITE_SLEEP_MAX)
            to_sleep = WRITE_SLEEP_MAX;

        for (int x = 0; x < MAX_NUMBER_OF_SLAB_CLASSES; x++) {
            bool did_move = false;
            bool mem_limit_reached = false;
            unsigned int chunks_free;
            int item_age;
            int target = settings.ext_free_memchunks[x];
            if (min_class > x || (backoff[x] && (counter % backoff[x] != 0))) {
                // Long sleeps means we should retry classes sooner.
                if (to_sleep > WRITE_SLEEP_MIN * 10)
                    backoff[x] /= 2;
                continue;
            }

            // Avoid extra slab lock calls during heavy writing.
            chunks_free = slabs_available_chunks(x, &mem_limit_reached,
                    NULL);

            // storage_write() will fail and cut loop after filling write buffer.
            while (1) {
                // if we are low on chunks and no spare, push out early.
                if (chunks_free < target && mem_limit_reached) {
                    item_age = 0;
                } else {
                    item_age = storage->get_item_age();
                }
                if (storage_write(storage, x, item_age)) {
                    chunks_free++; // Allow stopping if we've done enough this loop
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
            } else if (backoff[x]) {
                backoff[x] /= 2;
            }
        }

        // flip lock so we can be paused or stopped
        pthread_mutex_unlock(&storage_write_plock);
        if (do_sleep) {
            usleep(to_sleep);
            to_sleep *= 2;
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

    return 0;
}


int storage_logger_create() {
    logger *l = logger_create();
    if(l == NULL)
        return -1;
    else
        return 0;
}

enum logger_ret_type storage_logger_log(int flag, int type, const void *entry, ...) {
    enum logger_ret_type ret = LOGGER_RET_ERR;
    va_list args;

    logger *myl = myl = (logger *) pthread_getspecific(logger_key);
    if (myl->eflags & flag) {
        va_start(args, entry);
        ret = logger_log_args(myl, type, entry, args);
        va_end(args);
    }

    return ret;
}


bool item_is_cold(item *it) {
    if(GET_LRU(it->slabs_clsid) == COLD_LRU)
        return true;
    else
        return false;
}


void queue_storage_read(storage_read *rd) {
    conn *c = (conn *)rd->c;

    rd->next = c->storage_reads;
    c->storage_reads = rd;
    assert(c->num_pending_storage_reads >= 0);
    c->num_pending_storage_reads++;
}


void respond_storage_read(storage_read *rd) {
    if (rd->miss) {
        conn *c = (conn *)rd->c;
        int i;
        struct iovec *v;
        // TODO: This should be movable to the worker thread.
        if (c->protocol == binary_prot) {
            protocol_binary_response_header *header =
                    (protocol_binary_response_header *)c->wbuf;
            // this zeroes out the iovecs since binprot never stacks them.
            if (header->response.keylen) {
                write_bin_miss_response(c, ITEM_key(rd->hdr_it), rd->hdr_it->nkey);
            } else {
                write_bin_miss_response(c, 0, 0);
            }

        } else {
            for (i = 0; i < rd->iovec_count; i++) {
                v = &c->iov[rd->iovec_start + i];
                v->iov_len = 0;
                v->iov_base = NULL;
            }
        }
    } else {
        assert(rd->read_it->slabs_clsid != 0);
        // kill \r\n for binprot
        if (rd->nchunks == 1) {
            rd->iov[rd->iovec_data].iov_base = ITEM_data(rd->read_it);
            if (rd->protocol == binary_prot)
                rd->iov[rd->iovec_data].iov_len -= 2;
        } else {
            struct iovec *iov = &rd->iov[rd->iovused];
            // FIXME: Might need to go back and ensure chunked binprots don't
            // ever span two chunks for the final \r\n
            if (rd->protocol == binary_prot) {
                if (iov[rd->nchunks-1].iov_len >= 2) {
                    iov[rd->nchunks-1].iov_len -= 2;
                } else {
                    iov[rd->nchunks-1].iov_len = 0;
                    iov[rd->nchunks-2].iov_len -= 1;
                }
            }
        }
        // iov_len is already set
        // TODO: Should do that here instead and cuddle in the wrap object
    }
}


void complete_storage_read(storage_read *rd, bool redispatch) {
    conn *c = (conn *)rd->c;

    c->num_pending_storage_reads--;
    rd->active = false;
    //assert(c->io_wrapleft >= 0);

    // All storage reads have completed, lets re-attach this connection to our original
    // thread.
    if (c->num_pending_storage_reads == 0) {
        if(redispatch) {
            assert(c->storage_reads_queued == true);
            c->storage_reads_queued = false;
            redispatch_conn(c);
        }
        else {
            c->storage_reads_queued = false;
        }
    }
}


rel_time_t get_current_time() {
    return current_time;
}

#endif

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#ifdef __WIN32__
#include "win32.h"
#else
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <netinet/in.h>
#endif

#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <inttypes.h>

#include "default_engine.h"

/* Forward Declarations */
static void item_link_q(struct default_engine *engine, hash_item *it);
static void item_unlink_q(struct default_engine *engine, hash_item *it);
static hash_item *do_item_alloc(struct default_engine *engine,
                                const void *key, const size_t nkey,
                                const int flags, const rel_time_t exptime,
                                const int nbytes,
                                const void *cookie);
static hash_item *do_item_get(struct default_engine *engine,
                              const char *key, const size_t nkey);
static int do_item_link(struct default_engine *engine, hash_item *it);
static void do_item_unlink(struct default_engine *engine, hash_item *it);
static void do_item_release(struct default_engine *engine, hash_item *it);
static void do_item_update(struct default_engine *engine, hash_item *it);
static int do_item_replace(struct default_engine *engine,
                            hash_item *it, hash_item *new_it);
static void item_free(struct default_engine *engine, hash_item *it);

/*
 * We only reposition items in the LRU queue if they haven't been repositioned
 * in this many seconds. That saves us from churning on frequently-accessed
 * items.
 */
#define ITEM_UPDATE_INTERVAL 60

void item_stats_reset(struct default_engine *engine) {
    pthread_mutex_lock(&engine->cache_lock);
    memset(engine->items.itemstats, 0, sizeof(engine->items.itemstats));
    pthread_mutex_unlock(&engine->cache_lock);
}


/* warning: don't use these macros with a function, as it evals its arg twice */
static inline size_t ITEM_ntotal(struct default_engine *engine,
                                 const hash_item *item) {
    size_t ret = sizeof(*item) + item->nkey + item->nbytes;
    if (engine->config.use_cas) {
        ret += sizeof(uint64_t);
    }

    return ret;
}

/* Get the next CAS id for a new item. */
static uint64_t get_cas_id(void) {
    static uint64_t cas_id = 0;
    return ++cas_id;
}

/* Enable this for reference-count debugging. */
#if 0
# define DEBUG_REFCNT(it,op) \
                fprintf(stderr, "item %x refcnt(%c) %d %c%c%c\n", \
                        it, op, it->refcount, \
                        (it->it_flags & ITEM_LINKED) ? 'L' : ' ', \
                        (it->it_flags & ITEM_SLABBED) ? 'S' : ' ')
#else
# define DEBUG_REFCNT(it,op) while(0)
#endif


/*@null@*/
hash_item *do_item_alloc(struct default_engine *engine,
                         const void *key,
                         const size_t nkey,
                         const int flags,
                         const rel_time_t exptime,
                         const int nbytes,
                         const void *cookie) {
    hash_item *it = NULL;
    size_t ntotal = sizeof(hash_item) + nkey + nbytes;
    if (engine->config.use_cas) {
        ntotal += sizeof(uint64_t);
    }

    unsigned int id = slabs_clsid(engine, ntotal);
    if (id == 0)
        return 0;

    /* do a quick check if we have any expired items in the tail.. */
    int tries = 50;
    hash_item *search;

    rel_time_t current_time = engine->server.get_current_time();

    for (search = engine->items.tails[id];
         tries > 0 && search != NULL;
         tries--, search=search->prev) {
        if (search->refcount == 0 &&
            (search->exptime != 0 && search->exptime < current_time)) {
            it = search;
            /* I don't want to actually free the object, just steal
             * the item to avoid to grab the slab mutex twice ;-)
             */
            pthread_mutex_lock(&engine->stats.lock);
            engine->stats.reclaimed++;
            pthread_mutex_unlock(&engine->stats.lock);
            engine->items.itemstats[id].reclaimed++;
            it->refcount = 1;
            do_item_unlink(engine, it);
            /* Initialize the item block: */
            it->slabs_clsid = 0;
            it->refcount = 0;
            break;
        }
    }

    if (it == NULL && (it = slabs_alloc(engine, ntotal, id)) == NULL) {
        /*
        ** Could not find an expired item at the tail, and memory allocation
        ** failed. Try to evict some items!
        */
        tries = 50;

        /* If requested to not push old items out of cache when memory runs out,
         * we're out of luck at this point...
         */

        if (engine->config.evict_to_free == 0) {
            engine->items.itemstats[id].outofmemory++;
            return NULL;
        }

        /*
         * try to get one off the right LRU
         * don't necessariuly unlink the tail because it may be locked: refcount>0
         * search up from tail an item with refcount==0 and unlink it; give up after 50
         * tries
         */

        if (engine->items.tails[id] == 0) {
            engine->items.itemstats[id].outofmemory++;
            return NULL;
        }

        for (search = engine->items.tails[id]; tries > 0 && search != NULL; tries--, search=search->prev) {
            if (search->refcount == 0) {
                if (search->exptime == 0 || search->exptime > current_time) {
                    engine->items.itemstats[id].evicted++;
                    engine->items.itemstats[id].evicted_time = current_time - search->time;
                    if (search->exptime != 0) {
                        engine->items.itemstats[id].evicted_nonzero++;
                    }
                    pthread_mutex_lock(&engine->stats.lock);
                    engine->stats.evictions++;
                    pthread_mutex_unlock(&engine->stats.lock);
                    engine->server.count_eviction(cookie,
                                                  item_get_key(search),
                                                  search->nkey);
                } else {
                    engine->items.itemstats[id].reclaimed++;
                    pthread_mutex_lock(&engine->stats.lock);
                    engine->stats.reclaimed++;
                    pthread_mutex_unlock(&engine->stats.lock);
                }
                do_item_unlink(engine, search);
                break;
            }
        }
        it = slabs_alloc(engine, ntotal, id);
        if (it == 0) {
            engine->items.itemstats[id].outofmemory++;
            /* Last ditch effort. There is a very rare bug which causes
             * refcount leaks. We've fixed most of them, but it still happens,
             * and it may happen in the future.
             * We can reasonably assume no item can stay locked for more than
             * three hours, so if we find one in the tail which is that old,
             * free it anyway.
             */
            tries = 50;
            for (search = engine->items.tails[id]; tries > 0 && search != NULL; tries--, search=search->prev) {
                if (search->refcount != 0 && search->time + TAIL_REPAIR_TIME < current_time) {
                    engine->items.itemstats[id].tailrepairs++;
                    search->refcount = 0;
                    do_item_unlink(engine, search);
                    break;
                }
            }
            it = slabs_alloc(engine, ntotal, id);
            if (it == 0) {
                return NULL;
            }
        }
    }

    assert(it->slabs_clsid == 0);

    it->slabs_clsid = id;

    assert(it != engine->items.heads[it->slabs_clsid]);

    it->next = it->prev = it->h_next = 0;
    it->refcount = 1;     /* the caller will have a reference */
    DEBUG_REFCNT(it, '*');
    it->iflag = engine->config.use_cas ? ITEM_WITH_CAS : 0;
    it->nkey = nkey;
    it->nbytes = nbytes;
    it->flags = flags;
    memcpy((void*)item_get_key(it), key, nkey);
    it->exptime = exptime;
    return it;
}

static void item_free(struct default_engine *engine, hash_item *it) {
    size_t ntotal = ITEM_ntotal(engine, it);
    unsigned int clsid;
    assert((it->iflag & ITEM_LINKED) == 0);
    assert(it != engine->items.heads[it->slabs_clsid]);
    assert(it != engine->items.tails[it->slabs_clsid]);
    assert(it->refcount == 0);

    /* so slab size changer can tell later if item is already free or not */
    clsid = it->slabs_clsid;
    it->slabs_clsid = 0;
    it->iflag |= ITEM_SLABBED;
    DEBUG_REFCNT(it, 'F');
    slabs_free(engine, it, ntotal, clsid);
}

static void item_link_q(struct default_engine *engine, hash_item *it) { /* item is the new head */
    hash_item **head, **tail;
    assert(it->slabs_clsid < POWER_LARGEST);
    assert((it->iflag & ITEM_SLABBED) == 0);

    head = &engine->items.heads[it->slabs_clsid];
    tail = &engine->items.tails[it->slabs_clsid];
    assert(it != *head);
    assert((*head && *tail) || (*head == 0 && *tail == 0));
    it->prev = 0;
    it->next = *head;
    if (it->next) it->next->prev = it;
    *head = it;
    if (*tail == 0) *tail = it;
    engine->items.sizes[it->slabs_clsid]++;
    return;
}

static void item_unlink_q(struct default_engine *engine, hash_item *it) {
    hash_item **head, **tail;
    assert(it->slabs_clsid < POWER_LARGEST);
    head = &engine->items.heads[it->slabs_clsid];
    tail = &engine->items.tails[it->slabs_clsid];

    if (*head == it) {
        assert(it->prev == 0);
        *head = it->next;
    }
    if (*tail == it) {
        assert(it->next == 0);
        *tail = it->prev;
    }
    assert(it->next != it);
    assert(it->prev != it);

    if (it->next) it->next->prev = it->prev;
    if (it->prev) it->prev->next = it->next;
    engine->items.sizes[it->slabs_clsid]--;
    return;
}

int do_item_link(struct default_engine *engine, hash_item *it) {
    MEMCACHED_ITEM_LINK(item_get_key(it), it->nkey, it->nbytes);
    assert((it->iflag & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    assert(it->nbytes < (1024 * 1024));  /* 1MB max size */
    it->iflag |= ITEM_LINKED;
    it->time = engine->server.get_current_time();
    assoc_insert(engine, engine->server.hash(item_get_key(it), it->nkey, 0),
                 it);

    pthread_mutex_lock(&engine->stats.lock);
    engine->stats.curr_bytes += ITEM_ntotal(engine, it);
    engine->stats.curr_items += 1;
    engine->stats.total_items += 1;
    pthread_mutex_unlock(&engine->stats.lock);

    /* Allocate a new CAS ID on link. */
    item_set_cas(NULL, it, get_cas_id());

    item_link_q(engine, it);

    return 1;
}

void do_item_unlink(struct default_engine *engine, hash_item *it) {
    MEMCACHED_ITEM_UNLINK(item_get_key(it), it->nkey, it->nbytes);
    if ((it->iflag & ITEM_LINKED) != 0) {
        it->iflag &= ~ITEM_LINKED;
        pthread_mutex_lock(&engine->stats.lock);
        engine->stats.curr_bytes -= ITEM_ntotal(engine, it);
        engine->stats.curr_items -= 1;
        pthread_mutex_unlock(&engine->stats.lock);
        assoc_delete(engine, engine->server.hash(item_get_key(it), it->nkey, 0),
                     item_get_key(it), it->nkey);
        item_unlink_q(engine, it);
        if (it->refcount == 0) {
            item_free(engine, it);
        }
    }
}

void do_item_release(struct default_engine *engine, hash_item *it) {
    MEMCACHED_ITEM_REMOVE(item_get_key(it), it->nkey, it->nbytes);
    if (it->refcount != 0) {
        it->refcount--;
        DEBUG_REFCNT(it, '-');
    }
    if (it->refcount == 0 && (it->iflag & ITEM_LINKED) == 0) {
        item_free(engine, it);
    }
}

void do_item_update(struct default_engine *engine, hash_item *it) {
    rel_time_t current_time = engine->server.get_current_time();
    MEMCACHED_ITEM_UPDATE(item_get_key(it), it->nkey, it->nbytes);
    if (it->time < current_time - ITEM_UPDATE_INTERVAL) {
        assert((it->iflag & ITEM_SLABBED) == 0);

        if ((it->iflag & ITEM_LINKED) != 0) {
            item_unlink_q(engine, it);
            it->time = current_time;
            item_link_q(engine, it);
        }
    }
}

int do_item_replace(struct default_engine *engine,
                    hash_item *it, hash_item *new_it) {
    MEMCACHED_ITEM_REPLACE(item_get_key(it), it->nkey, it->nbytes,
                           item_get_key(new_it), new_it->nkey, new_it->nbytes);
    assert((it->iflag & ITEM_SLABBED) == 0);

    do_item_unlink(engine, it);
    return do_item_link(engine, new_it);
}

/*@null@*/
static char *do_item_cachedump(const unsigned int slabs_clsid,
                               const unsigned int limit,
                               unsigned int *bytes) {
#ifdef FUTURE
    unsigned int memlimit = 2 * 1024 * 1024;   /* 2MB max response size */
    char *buffer;
    unsigned int bufcurr;
    hash_item *it;
    unsigned int len;
    unsigned int shown = 0;
    char key_temp[KEY_MAX_LENGTH + 1];
    char temp[512];

    it = engine->items.heads[slabs_clsid];

    buffer = malloc((size_t)memlimit);
    if (buffer == 0) return NULL;
    bufcurr = 0;


    while (it != NULL && (limit == 0 || shown < limit)) {
        assert(it->nkey <= KEY_MAX_LENGTH);
        /* Copy the key since it may not be null-terminated in the struct */
        strncpy(key_temp, item_get_key(it), it->nkey);
        key_temp[it->nkey] = 0x00; /* terminate */
        len = snprintf(temp, sizeof(temp), "ITEM %s [%d b; %lu s]\r\n",
                       key_temp, it->nbytes - 2,
                       (unsigned long)it->exptime + process_started);
        if (bufcurr + len + 6 > memlimit)  /* 6 is END\r\n\0 */
            break;
        memcpy(buffer + bufcurr, temp, len);
        bufcurr += len;
        shown++;
        it = it->next;
    }


    memcpy(buffer + bufcurr, "END\r\n", 6);
    bufcurr += 5;

    *bytes = bufcurr;
    return buffer;
#endif
    (void)slabs_clsid;
    (void)limit;
    (void)bytes;
    return NULL;
}

static void do_item_stats(struct default_engine *engine,
                          ADD_STAT add_stats, void *c) {
    int i;
    for (i = 0; i < POWER_LARGEST; i++) {
        if (engine->items.tails[i] != NULL) {
            const char *prefix = "items";
            add_statistics(c, add_stats, prefix, i, "number", "%u",
                           engine->items.sizes[i]);
            add_statistics(c, add_stats, prefix, i, "age", "%u",
                           engine->items.tails[i]->time);
            add_statistics(c, add_stats, prefix, i, "evicted",
                           "%u", engine->items.itemstats[i].evicted);
            add_statistics(c, add_stats, prefix, i, "evicted_nonzero",
                           "%u", engine->items.itemstats[i].evicted_nonzero);
            add_statistics(c, add_stats, prefix, i, "evicted_time",
                           "%u", engine->items.itemstats[i].evicted_time);
            add_statistics(c, add_stats, prefix, i, "outofmemory",
                           "%u", engine->items.itemstats[i].outofmemory);
            add_statistics(c, add_stats, prefix, i, "tailrepairs",
                           "%u", engine->items.itemstats[i].tailrepairs);;
            add_statistics(c, add_stats, prefix, i, "reclaimed",
                           "%u", engine->items.itemstats[i].reclaimed);;
        }
    }

    /* getting here means both ascii and binary terminators fit */
    add_stats(NULL, 0, NULL, 0, c);
}

/** dumps out a list of objects of each size, with granularity of 32 bytes */
/*@null@*/
static void do_item_stats_sizes(struct default_engine *engine,
                                ADD_STAT add_stats, void *c) {

    /* max 1MB object, divided into 32 bytes size buckets */
    const int num_buckets = 32768;
    unsigned int *histogram = calloc(num_buckets, sizeof(int));

    if (histogram != NULL) {
        int i;

        /* build the histogram */
        for (i = 0; i < POWER_LARGEST; i++) {
            hash_item *iter = engine->items.heads[i];
            while (iter) {
                int ntotal = ITEM_ntotal(engine, iter);
                int bucket = ntotal / 32;
                if ((ntotal % 32) != 0) bucket++;
                if (bucket < num_buckets) histogram[bucket]++;
                iter = iter->next;
            }
        }

        /* write the buffer */
        for (i = 0; i < num_buckets; i++) {
            if (histogram[i] != 0) {
                char key[8], val[32];
                int klen, vlen;
                klen = snprintf(key, sizeof(key), "%d", i * 32);
                vlen = snprintf(val, sizeof(val), "%u", histogram[i]);
                assert(klen < sizeof(key));
                assert(vlen < sizeof(val));
                add_stats(key, klen, val, vlen, c);
            }
        }
        free(histogram);
    }
    add_stats(NULL, 0, NULL, 0, c);
}

/** wrapper around assoc_find which does the lazy expiration logic */
hash_item *do_item_get(struct default_engine *engine,
                       const char *key, const size_t nkey) {
    rel_time_t current_time = engine->server.get_current_time();
    hash_item *it = assoc_find(engine, engine->server.hash(key, nkey, 0), key, nkey);
    int was_found = 0;

    if (engine->config.verbose > 2) {
        if (it == NULL) {
            fprintf(stderr, "> NOT FOUND %s", key);
        } else {
            fprintf(stderr, "> FOUND KEY %s", (const char*)item_get_key(it));
            was_found++;
        }
    }

    if (it != NULL && engine->config.oldest_live != 0 &&
        engine->config.oldest_live <= current_time &&
        it->time <= engine->config.oldest_live) {
        do_item_unlink(engine, it);           /* MTSAFE - cache_lock held */
        it = NULL;
    }

    if (it == NULL && was_found) {
        fprintf(stderr, " -nuked by flush");
        was_found--;
    }

    if (it != NULL && it->exptime != 0 && it->exptime <= current_time) {
        do_item_unlink(engine, it);           /* MTSAFE - cache_lock held */
        it = NULL;
    }

    if (it == NULL && was_found) {
        fprintf(stderr, " -nuked by expire");
        was_found--;
    }

    if (it != NULL) {
        it->refcount++;
        DEBUG_REFCNT(it, '+');
    }

    if (engine->config.verbose > 2)
        fprintf(stderr, "\n");

    return it;
}

/*
 * Stores an item in the cache according to the semantics of one of the set
 * commands. In threaded mode, this is protected by the cache lock.
 *
 * Returns the state of storage.
 */
static ENGINE_ERROR_CODE do_store_item(struct default_engine *engine,
                                       hash_item *it, uint64_t *cas,
                                       ENGINE_STORE_OPERATION operation,
                                       const void *cookie) {
    const char *key = item_get_key(it);
    hash_item *old_it = do_item_get(engine, key, it->nkey);
    ENGINE_ERROR_CODE stored = ENGINE_NOT_STORED;

    hash_item *new_it = NULL;

    if (old_it != NULL && operation == OPERATION_ADD) {
        /* add only adds a nonexistent item, but promote to head of LRU */
        do_item_update(engine, old_it);
    } else if (!old_it && (operation == OPERATION_REPLACE
        || operation == OPERATION_APPEND || operation == OPERATION_PREPEND))
    {
        /* replace only replaces an existing value; don't store */
    } else if (operation == OPERATION_CAS) {
        /* validate cas operation */
        if(old_it == NULL) {
            // LRU expired
            stored = ENGINE_KEY_ENOENT;
#if 0
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.cas_misses++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
#endif
        }
        else if (item_get_cas(it) == item_get_cas(old_it)) {
            // cas validates
            // it and old_it may belong to different classes.
            // I'm updating the stats for the one that's getting pushed out
#if 0
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[item_get_clsid(old_it)].cas_hits++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
#endif

            do_item_replace(engine, old_it, it);
            stored = ENGINE_SUCCESS;
        } else {
#if 0
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[item_get_clsid(old_it)].cas_badval++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
#endif
            if (engine->config.verbose > 1) {
                fprintf(stderr,
                        "CAS:  failure: expected %"PRIu64", got %"PRIu64"\n",
                        item_get_cas(old_it),
                        item_get_cas(it));
            }
            stored = ENGINE_KEY_EEXISTS;
        }
    } else {
        /*
         * Append - combine new and old record into single one. Here it's
         * atomic and thread-safe.
         */
        if (operation == OPERATION_APPEND || operation == OPERATION_PREPEND) {
            /*
             * Validate CAS
             */
            if (item_get_cas(it) != 0) {
                // CAS much be equal
                if (item_get_cas(it) != item_get_cas(old_it)) {
                    stored = ENGINE_KEY_EEXISTS;
                }
            }

            if (stored == ENGINE_NOT_STORED) {
                /* we have it and old_it here - alloc memory to hold both */
                new_it = do_item_alloc(engine, key, it->nkey,
                                       old_it->flags,
                                       old_it->exptime,
                                       it->nbytes + old_it->nbytes - 2 /* CRLF */,
                                       cookie);

                if (new_it == NULL) {
                    /* SERVER_ERROR out of memory */
                    if (old_it != NULL) {
                        do_item_release(engine, old_it);
                    }

                    return ENGINE_NOT_STORED;
                }

                /* copy data from it and old_it to new_it */

                if (operation == OPERATION_APPEND) {
                    memcpy(item_get_data(new_it), item_get_data(old_it), old_it->nbytes);
                    memcpy(item_get_data(new_it) + old_it->nbytes - 2 /* CRLF */, item_get_data(it), it->nbytes);
                } else {
                    /* OPERATION_PREPEND */
                    memcpy(item_get_data(new_it), item_get_data(it), it->nbytes);
                    memcpy(item_get_data(new_it) + it->nbytes - 2 /* CRLF */, item_get_data(old_it), old_it->nbytes);
                }

                it = new_it;
            }
        }

        if (stored == ENGINE_NOT_STORED) {
            if (old_it != NULL) {
                do_item_replace(engine, old_it, it);
            } else {
                do_item_link(engine, it);
            }

            *cas = item_get_cas(it);
            stored = ENGINE_SUCCESS;
        }
    }

    if (old_it != NULL) {
        do_item_release(engine, old_it);         /* release our reference */
    }

    if (new_it != NULL) {
        do_item_release(engine, new_it);
    }

    if (stored == ENGINE_SUCCESS) {
        *cas = item_get_cas(it);
    }

    return stored;
}


/*
 * adds a delta value to a numeric item.
 *
 * c     connection requesting the operation
 * it    item to adjust
 * incr  true to increment value, false to decrement
 * delta amount to adjust value by
 * buf   buffer for response string
 *
 * returns a response string to send back to the client.
 */
static ENGINE_ERROR_CODE do_add_delta(struct default_engine *engine,
                                      hash_item *it, const bool incr,
                                      const int64_t delta, uint64_t *rcas,
                                      uint64_t *result, const void *cookie) {
    const char *ptr;
    uint64_t value;
    int res;

    ptr = item_get_data(it);

    if (!safe_strtoull(ptr, &value)) {
        return ENGINE_EINVAL;
    }

    if (incr) {
        value += delta;
    } else {
        if(delta > value) {
            value = 0;
        } else {
            value -= delta;
        }
    }

    *result = value;
    char buf[80];
    if ((res = snprintf(buf, sizeof(buf), "%" PRIu64 "\r\n", value)) == -1) {
        return ENGINE_EINVAL;
    }
    hash_item *new_it = do_item_alloc(engine, item_get_key(it),
                                      it->nkey, it->flags,
                                      it->exptime, res,
                                      cookie );
    if (new_it == 0) {
        do_item_unlink(engine, it);
        return ENGINE_ENOMEM;
    }
    memcpy(item_get_data(new_it), buf, res);
    do_item_replace(engine, it, new_it);
    *rcas = item_get_cas(new_it);
    do_item_release(engine, new_it);       /* release our reference */

    return ENGINE_SUCCESS;
}

/********************************* ITEM ACCESS *******************************/

/*
 * Allocates a new item.
 */
hash_item *item_alloc(struct default_engine *engine,
                      const void *key, size_t nkey, int flags,
                      rel_time_t exptime, int nbytes, const void *cookie) {
    hash_item *it;
    pthread_mutex_lock(&engine->cache_lock);
    it = do_item_alloc(engine, key, nkey, flags, exptime, nbytes, cookie);
    pthread_mutex_unlock(&engine->cache_lock);
    return it;
}

/*
 * Returns an item if it hasn't been marked as expired,
 * lazy-expiring as needed.
 */
hash_item *item_get(struct default_engine *engine,
                    const void *key, const size_t nkey) {
    hash_item *it;
    pthread_mutex_lock(&engine->cache_lock);
    it = do_item_get(engine, key, nkey);
    pthread_mutex_unlock(&engine->cache_lock);
    return it;
}

/*
 * Decrements the reference count on an item and adds it to the freelist if
 * needed.
 */
void item_release(struct default_engine *engine, hash_item *item) {
    pthread_mutex_lock(&engine->cache_lock);
    do_item_release(engine, item);
    pthread_mutex_unlock(&engine->cache_lock);
}

/*
 * Unlinks an item from the LRU and hashtable.
 */
void item_unlink(struct default_engine *engine, hash_item *item) {
    pthread_mutex_lock(&engine->cache_lock);
    do_item_unlink(engine, item);
    pthread_mutex_unlock(&engine->cache_lock);
}

/*
 * Does arithmetic on a numeric item value.
 */
ENGINE_ERROR_CODE add_delta(struct default_engine *engine,
                            hash_item *item, const bool incr,
                            const int64_t delta, uint64_t *rcas,
                            uint64_t *result, const void *cookie) {
    ENGINE_ERROR_CODE ret;

    pthread_mutex_lock(&engine->cache_lock);
    ret = do_add_delta(engine, item, incr, delta, rcas, result, cookie);
    pthread_mutex_unlock(&engine->cache_lock);
    return ret;
}

/*
 * Stores an item in the cache (high level, obeys set/add/replace semantics)
 */
ENGINE_ERROR_CODE store_item(struct default_engine *engine,
                             hash_item *item, uint64_t *cas,
                             ENGINE_STORE_OPERATION operation,
                             const void *cookie) {
    ENGINE_ERROR_CODE ret;

    pthread_mutex_lock(&engine->cache_lock);
    ret = do_store_item(engine, item, cas, operation, cookie);
    pthread_mutex_unlock(&engine->cache_lock);
    return ret;
}

/*
 * Flushes expired items after a flush_all call
 */
void item_flush_expired(struct default_engine *engine, time_t when) {
    int i;
    hash_item *iter, *next;

    pthread_mutex_lock(&engine->cache_lock);

    if (when == 0) {
        engine->config.oldest_live = engine->server.get_current_time() - 1;
    } else {
        engine->config.oldest_live = engine->server.realtime(when) - 1;
    }

    if (engine->config.oldest_live != 0) {
        for (i = 0; i < POWER_LARGEST; i++) {
            /*
             * The LRU is sorted in decreasing time order, and an item's
             * timestamp is never newer than its last access time, so we
             * only need to walk back until we hit an item older than the
             * oldest_live time.
             * The oldest_live checking will auto-expire the remaining items.
             */
            for (iter = engine->items.heads[i]; iter != NULL; iter = next) {
                if (iter->time >= engine->config.oldest_live) {
                    next = iter->next;
                    if ((iter->iflag & ITEM_SLABBED) == 0) {
                        do_item_unlink(engine, iter);
                    }
                } else {
                    /* We've hit the first old item. Continue to the next queue. */
                    break;
                }
            }
        }
    }
    pthread_mutex_unlock(&engine->cache_lock);
}

/*
 * Dumps part of the cache
 */
char *item_cachedump(struct default_engine *engine,
                     unsigned int slabs_clsid,
                     unsigned int limit,
                     unsigned int *bytes) {
    char *ret;

    pthread_mutex_lock(&engine->cache_lock);
    ret = do_item_cachedump(slabs_clsid, limit, bytes);
    pthread_mutex_unlock(&engine->cache_lock);
    return ret;
}

void item_stats(struct default_engine *engine,
                   ADD_STAT add_stat, const void *cookie)
{
    pthread_mutex_lock(&engine->cache_lock);
    do_item_stats(engine, add_stat, (void*)cookie);
    pthread_mutex_unlock(&engine->cache_lock);
}


void item_stats_sizes(struct default_engine *engine,
                      ADD_STAT add_stat, const void *cookie)
{
    pthread_mutex_lock(&engine->cache_lock);
    do_item_stats_sizes(engine, add_stat, (void*)cookie);
    pthread_mutex_unlock(&engine->cache_lock);
}

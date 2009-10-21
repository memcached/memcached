/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>

#include "default_engine.h"


/* Forward Declarations */
static void item_link_q(hash_item *it);
static void item_unlink_q(hash_item *it);

/*
 * We only reposition items in the LRU queue if they haven't been repositioned
 * in this many seconds. That saves us from churning on frequently-accessed
 * items.
 */
#define ITEM_UPDATE_INTERVAL 60

#define LARGEST_ID POWER_LARGEST
typedef struct {
    unsigned int evicted;
    unsigned int evicted_nonzero;
    rel_time_t evicted_time;
    unsigned int reclaimed;
    unsigned int outofmemory;
    unsigned int tailrepairs;
} itemstats_t;

static hash_item *heads[LARGEST_ID];
static hash_item *tails[LARGEST_ID];
static itemstats_t itemstats[LARGEST_ID];
static unsigned int sizes[LARGEST_ID];

void item_stats_reset(void) {
    pthread_mutex_lock(&default_engine.cache_lock);
    memset(itemstats, 0, sizeof(itemstats));
    pthread_mutex_unlock(&default_engine.cache_lock);
}


/* warning: don't use these macros with a function, as it evals its arg twice */
static inline size_t ITEM_ntotal(const hash_item *item) {
    size_t ret = sizeof(*item) + item->item.nkey + item->item.nbytes;
    if (settings.use_cas) {
        ret += sizeof(uint64_t);
    }

    return ret;
}

/* Get the next CAS id for a new item. */
uint64_t get_cas_id(void) {
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
hash_item *do_item_alloc(const void *key, const size_t nkey, const int flags, const rel_time_t exptime, const int nbytes) {
    hash_item *it = NULL;
    size_t ntotal = sizeof(hash_item) + nkey + nbytes;
    if (settings.use_cas) {
        ntotal += sizeof(uint64_t);
    }

    unsigned int id = slabs_clsid(ntotal);
    if (id == 0)
        return 0;

    /* do a quick check if we have any expired items in the tail.. */
    int tries = 50;
    hash_item *search;

    for (search = tails[id];
         tries > 0 && search != NULL;
         tries--, search=search->prev) {
        if (search->refcount == 0 &&
            (search->item.exptime != 0 && search->item.exptime < current_time)) {
            it = search;
            /* I don't want to actually free the object, just steal
             * the item to avoid to grab the slab mutex twice ;-)
             */
            STATS_LOCK();
            default_engine.stats.reclaimed++;
            STATS_UNLOCK();
            itemstats[id].reclaimed++;
            it->refcount = 1;
            do_item_unlink(it);
            /* Initialize the item block: */
            it->slabs_clsid = 0;
            it->refcount = 0;
            break;
        }
    }

    if (it == NULL && (it = slabs_alloc(ntotal, id)) == NULL) {
        /*
        ** Could not find an expired item at the tail, and memory allocation
        ** failed. Try to evict some items!
        */
        tries = 50;

        /* If requested to not push old items out of cache when memory runs out,
         * we're out of luck at this point...
         */

        if (settings.evict_to_free == 0) {
            itemstats[id].outofmemory++;
            return NULL;
        }

        /*
         * try to get one off the right LRU
         * don't necessariuly unlink the tail because it may be locked: refcount>0
         * search up from tail an item with refcount==0 and unlink it; give up after 50
         * tries
         */

        if (tails[id] == 0) {
            itemstats[id].outofmemory++;
            return NULL;
        }

        for (search = tails[id]; tries > 0 && search != NULL; tries--, search=search->prev) {
            if (search->refcount == 0) {
                if (search->item.exptime == 0 || search->item.exptime > current_time) {
                    itemstats[id].evicted++;
                    itemstats[id].evicted_time = current_time - search->time;
                    if (search->item.exptime != 0) {
                        itemstats[id].evicted_nonzero++;
                    }
                    STATS_LOCK();
                    default_engine.stats.evictions++;
                    STATS_UNLOCK();
                } else {
                    itemstats[id].reclaimed++;
                    STATS_LOCK();
                    default_engine.stats.reclaimed++;
                    STATS_UNLOCK();
                }
                do_item_unlink(search);
                break;
            }
        }
        it = slabs_alloc(ntotal, id);
        if (it == 0) {
            itemstats[id].outofmemory++;
            /* Last ditch effort. There is a very rare bug which causes
             * refcount leaks. We've fixed most of them, but it still happens,
             * and it may happen in the future.
             * We can reasonably assume no item can stay locked for more than
             * three hours, so if we find one in the tail which is that old,
             * free it anyway.
             */
            tries = 50;
            for (search = tails[id]; tries > 0 && search != NULL; tries--, search=search->prev) {
                if (search->refcount != 0 && search->time + TAIL_REPAIR_TIME < current_time) {
                    itemstats[id].tailrepairs++;
                    search->refcount = 0;
                    do_item_unlink(search);
                    break;
                }
            }
            it = slabs_alloc(ntotal, id);
            if (it == 0) {
                return NULL;
            }
        }
    }

    assert(it->slabs_clsid == 0);

    it->slabs_clsid = id;

    assert(it != heads[it->slabs_clsid]);

    it->next = it->prev = it->h_next = 0;
    it->refcount = 1;     /* the caller will have a reference */
    DEBUG_REFCNT(it, '*');
    it->item.iflag = settings.use_cas ? ITEM_CAS : 0;
    it->item.nkey = nkey;
    it->item.nbytes = nbytes;
    it->item.flags = flags;
    memcpy(ITEM_key(&it->item), key, nkey);
    it->item.exptime = exptime;
    return it;
}

void item_free(hash_item *it) {
    size_t ntotal = ITEM_ntotal(it);
    unsigned int clsid;
    assert((it->item.iflag & ITEM_LINKED) == 0);
    assert(it != heads[it->slabs_clsid]);
    assert(it != tails[it->slabs_clsid]);
    assert(it->refcount == 0);

    /* so slab size changer can tell later if item is already free or not */
    clsid = it->slabs_clsid;
    it->slabs_clsid = 0;
    it->item.iflag |= ITEM_SLABBED;
    DEBUG_REFCNT(it, 'F');
    slabs_free(it, ntotal, clsid);
}

/**
 * Returns true if an item will fit in the cache (its size does not exceed
 * the maximum for a cache entry.)
 */
bool item_size_ok(const size_t nkey, const int flags, const int nbytes) {
    size_t ntotal = sizeof(hash_item) + nkey + nbytes;
    if (settings.use_cas) {
        ntotal += sizeof(uint64_t);
    }

    return slabs_clsid(ntotal) != 0;
}

static void item_link_q(hash_item *it) { /* item is the new head */
    hash_item **head, **tail;
    assert(it->slabs_clsid < LARGEST_ID);
    assert((it->item.iflag & ITEM_SLABBED) == 0);

    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];
    assert(it != *head);
    assert((*head && *tail) || (*head == 0 && *tail == 0));
    it->prev = 0;
    it->next = *head;
    if (it->next) it->next->prev = it;
    *head = it;
    if (*tail == 0) *tail = it;
    sizes[it->slabs_clsid]++;
    return;
}

static void item_unlink_q(hash_item *it) {
    hash_item **head, **tail;
    assert(it->slabs_clsid < LARGEST_ID);
    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];

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
    sizes[it->slabs_clsid]--;
    return;
}

int do_item_link(hash_item *it) {
    MEMCACHED_ITEM_LINK(ITEM_key(it), it->item.nkey, it->item.nbytes);
    assert((it->item.iflag & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    assert(it->item.nbytes < (1024 * 1024));  /* 1MB max size */
    it->item.iflag |= ITEM_LINKED;
    it->time = current_time;
    assoc_insert(it);

    STATS_LOCK();
    default_engine.stats.curr_bytes += ITEM_ntotal(it);
    default_engine.stats.curr_items += 1;
    default_engine.stats.total_items += 1;
    STATS_UNLOCK();

    /* Allocate a new CAS ID on link. */
    ITEM_set_cas(&it->item, (settings.use_cas) ? get_cas_id() : 0);

    item_link_q(it);

    return 1;
}

void do_item_unlink(hash_item *it) {
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->item.nkey, it->item.nbytes);
    if ((it->item.iflag & ITEM_LINKED) != 0) {
        it->item.iflag &= ~ITEM_LINKED;
        STATS_LOCK();
        default_engine.stats.curr_bytes -= ITEM_ntotal(it);
        default_engine.stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(&it->item), it->item.nkey);
        item_unlink_q(it);
        if (it->refcount == 0) item_free(it);
    }
}

void do_item_remove(hash_item *it) {
    MEMCACHED_ITEM_REMOVE(ITEM_key(it), it->item.nkey, it->item.nbytes);
    assert((it->item.iflag & ITEM_SLABBED) == 0);
    if (it->refcount != 0) {
        it->refcount--;
        DEBUG_REFCNT(it, '-');
    }
    if (it->refcount == 0 && (it->item.iflag & ITEM_LINKED) == 0) {
        item_free(it);
    }
}

void do_item_update(hash_item *it) {
    MEMCACHED_ITEM_UPDATE(ITEM_key(it), it->item.nkey, it->item.nbytes);
    if (it->time < current_time - ITEM_UPDATE_INTERVAL) {
        assert((it->item.iflag & ITEM_SLABBED) == 0);

        if ((it->item.iflag & ITEM_LINKED) != 0) {
            item_unlink_q(it);
            it->time = current_time;
            item_link_q(it);
        }
    }
}

int do_item_replace(hash_item *it, hash_item *new_it) {
    MEMCACHED_ITEM_REPLACE(ITEM_key(it), it->item.nkey, it->item.nbytes,
                           ITEM_key(new_it), new_it->item.nkey, new_it->item.nbytes);
    assert((it->item.iflag & ITEM_SLABBED) == 0);

    do_item_unlink(it);
    return do_item_link(new_it);
}

/*@null@*/
char *do_item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes) {
    unsigned int memlimit = 2 * 1024 * 1024;   /* 2MB max response size */
    char *buffer;
    unsigned int bufcurr;
    hash_item *it;
    unsigned int len;
    unsigned int shown = 0;
    char key_temp[KEY_MAX_LENGTH + 1];
    char temp[512];

    it = heads[slabs_clsid];

    buffer = malloc((size_t)memlimit);
    if (buffer == 0) return NULL;
    bufcurr = 0;

    while (it != NULL && (limit == 0 || shown < limit)) {
        assert(it->item.nkey <= KEY_MAX_LENGTH);
        /* Copy the key since it may not be null-terminated in the struct */
        strncpy(key_temp, ITEM_key(&it->item), it->item.nkey);
        key_temp[it->item.nkey] = 0x00; /* terminate */
        len = snprintf(temp, sizeof(temp), "ITEM %s [%d b; %lu s]\r\n",
                       key_temp, it->item.nbytes - 2,
                       (unsigned long)it->item.exptime + process_started);
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
}

void do_item_stats(ADD_STAT add_stats, void *c) {
    int i;
    for (i = 0; i < LARGEST_ID; i++) {
        if (tails[i] != NULL) {
            const char *fmt = "items:%d:%s";
            char key_str[STAT_KEY_LEN];
            char val_str[STAT_VAL_LEN];
            int klen = 0, vlen = 0;

            APPEND_NUM_FMT_STAT(fmt, i, "number", "%u", sizes[i]);
            APPEND_NUM_FMT_STAT(fmt, i, "age", "%u", tails[i]->time);
            APPEND_NUM_FMT_STAT(fmt, i, "evicted",
                                "%u", itemstats[i].evicted);
            APPEND_NUM_FMT_STAT(fmt, i, "evicted_nonzero",
                                "%u", itemstats[i].evicted_nonzero);
            APPEND_NUM_FMT_STAT(fmt, i, "evicted_time",
                                "%u", itemstats[i].evicted_time);
            APPEND_NUM_FMT_STAT(fmt, i, "outofmemory",
                                "%u", itemstats[i].outofmemory);
            APPEND_NUM_FMT_STAT(fmt, i, "tailrepairs",
                                "%u", itemstats[i].tailrepairs);;
            APPEND_NUM_FMT_STAT(fmt, i, "reclaimed",
                                "%u", itemstats[i].reclaimed);;
        }
    }

    /* getting here means both ascii and binary terminators fit */
    add_stats(NULL, 0, NULL, 0, c);
}

/** dumps out a list of objects of each size, with granularity of 32 bytes */
/*@null@*/
void do_item_stats_sizes(ADD_STAT add_stats, void *c) {

    /* max 1MB object, divided into 32 bytes size buckets */
    const int num_buckets = 32768;
    unsigned int *histogram = calloc(num_buckets, sizeof(int));

    if (histogram != NULL) {
        int i;

        /* build the histogram */
        for (i = 0; i < LARGEST_ID; i++) {
            hash_item *iter = heads[i];
            while (iter) {
                int ntotal = ITEM_ntotal(iter);
                int bucket = ntotal / 32;
                if ((ntotal % 32) != 0) bucket++;
                if (bucket < num_buckets) histogram[bucket]++;
                iter = iter->next;
            }
        }

        /* write the buffer */
        for (i = 0; i < num_buckets; i++) {
            if (histogram[i] != 0) {
                char key[8];
                int klen = 0;
                klen = snprintf(key, sizeof(key), "%d", i * 32);
                assert(klen < sizeof(key));
                APPEND_STAT(key, "%u", histogram[i]);
            }
        }
        free(histogram);
    }
    add_stats(NULL, 0, NULL, 0, c);
}

/** wrapper around assoc_find which does the lazy expiration logic */
hash_item *do_item_get(const char *key, const size_t nkey) {
    hash_item *it = assoc_find(key, nkey);
    int was_found = 0;

    if (settings.verbose > 2) {
        if (it == NULL) {
            fprintf(stderr, "> NOT FOUND %s", key);
        } else {
            fprintf(stderr, "> FOUND KEY %s", ITEM_key(&it->item));
            was_found++;
        }
    }

    if (it != NULL && default_engine.config.oldest_live != 0 &&
        default_engine.config.oldest_live <= current_time &&
        it->time <= default_engine.config.oldest_live) {
        do_item_unlink(it);           /* MTSAFE - cache_lock held */
        it = NULL;
    }

    if (it == NULL && was_found) {
        fprintf(stderr, " -nuked by flush");
        was_found--;
    }

    if (it != NULL && it->item.exptime != 0 && it->item.exptime <= current_time) {
        do_item_unlink(it);           /* MTSAFE - cache_lock held */
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

    if (settings.verbose > 2)
        fprintf(stderr, "\n");

    return it;
}

/** returns an item whether or not it's expired. */
hash_item *do_item_get_nocheck(const char *key, const size_t nkey) {
    hash_item *it = assoc_find(key, nkey);
    if (it) {
        it->refcount++;
        DEBUG_REFCNT(it, '+');
    }
    return it;
}

/* expires items that are more recent than the oldest_live setting. */
void do_item_flush_expired(void) {
    int i;
    hash_item *iter, *next;
    if (default_engine.config.oldest_live == 0)
        return;
    for (i = 0; i < LARGEST_ID; i++) {
        /* The LRU is sorted in decreasing time order, and an item's timestamp
         * is never newer than its last access time, so we only need to walk
         * back until we hit an item older than the oldest_live time.
         * The oldest_live checking will auto-expire the remaining items.
         */
        for (iter = heads[i]; iter != NULL; iter = next) {
            if (iter->time >= default_engine.config.oldest_live) {
                next = iter->next;
                if ((iter->item.iflag & ITEM_SLABBED) == 0) {
                    do_item_unlink(iter);
                }
            } else {
                /* We've hit the first old item. Continue to the next queue. */
                break;
            }
        }
    }
}

/*
 * Stores an item in the cache according to the semantics of one of the set
 * commands. In threaded mode, this is protected by the cache lock.
 *
 * Returns the state of storage.
 */
static ENGINE_ERROR_CODE do_store_item(hash_item *it, uint64_t *cas,
                                       ENGINE_STORE_OPERATION operation) {
    char *key = ITEM_key(&it->item);
    hash_item *old_it = do_item_get(key, it->item.nkey);
    ENGINE_ERROR_CODE stored = ENGINE_NOT_STORED;

    hash_item *new_it = NULL;

    if (old_it != NULL && operation == OPERATION_ADD) {
        /* add only adds a nonexistent item, but promote to head of LRU */
        do_item_update(old_it);
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
        else if (ITEM_get_cas(&it->item) == ITEM_get_cas(&old_it->item)) {
            // cas validates
            // it and old_it may belong to different classes.
            // I'm updating the stats for the one that's getting pushed out
#if 0
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_hits++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
#endif

            item_replace(old_it, it);
            stored = ENGINE_SUCCESS;
        } else {
#if 0
            pthread_mutex_lock(&c->thread->stats.mutex);
            c->thread->stats.slab_stats[ITEM_clsid(old_it)].cas_badval++;
            pthread_mutex_unlock(&c->thread->stats.mutex);
#endif
            if(settings.verbose > 1) {
                fprintf(stderr, "CAS:  failure: expected %llu, got %llu\n",
                        (unsigned long long)ITEM_get_cas(&old_it->item),
                        (unsigned long long)ITEM_get_cas(&it->item));
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
            if (ITEM_get_cas(&it->item) != 0) {
                // CAS much be equal
                if (ITEM_get_cas(&it->item) != ITEM_get_cas(&old_it->item)) {
                    stored = ENGINE_KEY_EEXISTS;
                }
            }

            if (stored == ENGINE_NOT_STORED) {
                /* we have it and old_it here - alloc memory to hold both */
                new_it = do_item_alloc(key, it->item.nkey, old_it->item.flags, old_it->item.exptime, it->item.nbytes + old_it->item.nbytes - 2 /* CRLF */);

                if (new_it == NULL) {
                    /* SERVER_ERROR out of memory */
                    if (old_it != NULL)
                        do_item_remove(old_it);

                    return ENGINE_NOT_STORED;
                }

                /* copy data from it and old_it to new_it */

                if (operation == OPERATION_APPEND) {
                    memcpy(ITEM_data(&new_it->item), ITEM_data(&old_it->item), old_it->item.nbytes);
                    memcpy(ITEM_data(&new_it->item) + old_it->item.nbytes - 2 /* CRLF */, ITEM_data(&it->item), it->item.nbytes);
                } else {
                    /* OPERATION_PREPEND */
                    memcpy(ITEM_data(&new_it->item), ITEM_data(&it->item), it->item.nbytes);
                    memcpy(ITEM_data(&new_it->item) + it->item.nbytes - 2 /* CRLF */, ITEM_data(&old_it->item), old_it->item.nbytes);
                }

                it = new_it;
            }
        }

        if (stored == ENGINE_NOT_STORED) {
            if (old_it != NULL)
                item_replace(old_it, it);
            else
                do_item_link(it);

            *cas = ITEM_get_cas(&it->item);
            stored = ENGINE_SUCCESS;
        }
    }

    if (old_it != NULL)
        do_item_remove(old_it);         /* release our reference */
    if (new_it != NULL)
        do_item_remove(new_it);

    if (stored == ENGINE_SUCCESS) {
        *cas = ITEM_get_cas(&it->item);
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
ENGINE_ERROR_CODE do_add_delta(conn *c, hash_item *it, const bool incr,
                               const int64_t delta, uint64_t *rcas,
                               uint64_t *result) {
    char *ptr;
    uint64_t value;
    int res;

    ptr = ITEM_data(&it->item);

    if (!safe_strtoull(ptr, &value)) {
        return ENGINE_EINVAL;
    }

    if (incr) {
        value += delta;
        MEMCACHED_COMMAND_INCR(c->sfd, ITEM_key(it), it->item.nkey, value);
    } else {
        if(delta > value) {
            value = 0;
        } else {
            value -= delta;
        }
        MEMCACHED_COMMAND_DECR(c->sfd, ITEM_key(it), it->item.nkey, value);
    }

    *result = value;
    char buf[80];
    snprintf(buf, sizeof(buf), "%llu", (unsigned long long)value);
    res = strlen(buf);
    if (res + 2 > it->item.nbytes) { /* need to realloc */
        hash_item *new_it;
        new_it = do_item_alloc(ITEM_key(&it->item), it->item.nkey, it->item.flags, it->item.exptime, res + 2 );
        if (new_it == 0) {
            return ENGINE_ENOMEM;
        }
        memcpy(ITEM_data(&new_it->item), buf, res);
        memcpy(ITEM_data(&new_it->item) + res, "\r\n", 2);
        item_replace(it, new_it);
        *rcas = ITEM_get_cas(&new_it->item);
        do_item_remove(new_it);       /* release our reference */
    } else { /* replace in-place */
        /* When changing the value without replacing the item, we
           need to update the CAS on the existing item. */
        ITEM_set_cas(&it->item, (settings.use_cas) ? get_cas_id() : 0);
        *rcas = ITEM_get_cas(&it->item);

        memcpy(ITEM_data(&it->item), buf, res);
        memset(ITEM_data(&it->item) + res, ' ', it->item.nbytes - res - 2);
    }

    return ENGINE_SUCCESS;
}


/********************************* ITEM ACCESS *******************************/

/*
 * Allocates a new item.
 */
hash_item *item_alloc(const void *key, size_t nkey, int flags,
                      rel_time_t exptime, int nbytes) {
    hash_item *it;
    pthread_mutex_lock(&default_engine.cache_lock);
    it = do_item_alloc(key, nkey, flags, exptime, nbytes);
    pthread_mutex_unlock(&default_engine.cache_lock);
    return it;
}

/*
 * Returns an item if it hasn't been marked as expired,
 * lazy-expiring as needed.
 */
hash_item *item_get(const void *key, const size_t nkey) {
    hash_item *it;
    pthread_mutex_lock(&default_engine.cache_lock);
    it = do_item_get(key, nkey);
    pthread_mutex_unlock(&default_engine.cache_lock);
    return it;
}

/*
 * Links an item into the LRU and hashtable.
 */
int item_link(hash_item *item) {
    int ret;

    pthread_mutex_lock(&default_engine.cache_lock);
    ret = do_item_link(item);
    pthread_mutex_unlock(&default_engine.cache_lock);
    return ret;
}

/*
 * Decrements the reference count on an item and adds it to the freelist if
 * needed.
 */
void item_remove(hash_item *item) {
    pthread_mutex_lock(&default_engine.cache_lock);
    do_item_remove(item);
    pthread_mutex_unlock(&default_engine.cache_lock);
}

/*
 * Replaces one item with another in the hashtable.
 * Unprotected by a mutex lock since the core server does not require
 * it to be thread-safe.
 */
int item_replace(hash_item *old_it, hash_item *new_it) {
    return do_item_replace(old_it, new_it);
}

/*
 * Unlinks an item from the LRU and hashtable.
 */
void item_unlink(hash_item *item) {
    pthread_mutex_lock(&default_engine.cache_lock);
    do_item_unlink(item);
    pthread_mutex_unlock(&default_engine.cache_lock);
}

/*
 * Moves an item to the back of the LRU queue.
 */
void item_update(hash_item *item) {
    pthread_mutex_lock(&default_engine.cache_lock);
    do_item_update(item);
    pthread_mutex_unlock(&default_engine.cache_lock);
}

/*
 * Does arithmetic on a numeric item value.
 */
ENGINE_ERROR_CODE add_delta(conn *c, hash_item *item, const bool incr,
                            const int64_t delta, uint64_t *rcas,
                            uint64_t *result) {
    ENGINE_ERROR_CODE ret;

    pthread_mutex_lock(&default_engine.cache_lock);
    ret = do_add_delta(c, item, incr, delta, rcas, result);
    pthread_mutex_unlock(&default_engine.cache_lock);
    return ret;
}

/*
 * Stores an item in the cache (high level, obeys set/add/replace semantics)
 */
ENGINE_ERROR_CODE store_item(hash_item *item, uint64_t *cas,
                             ENGINE_STORE_OPERATION operation) {
    ENGINE_ERROR_CODE ret;

    pthread_mutex_lock(&default_engine.cache_lock);
    ret = do_store_item(item, cas, operation);
    pthread_mutex_unlock(&default_engine.cache_lock);
    return ret;
}

/*
 * Flushes expired items after a flush_all call
 */
void item_flush_expired() {
    pthread_mutex_lock(&default_engine.cache_lock);
    do_item_flush_expired();
    pthread_mutex_unlock(&default_engine.cache_lock);
}

/*
 * Dumps part of the cache
 */
char *item_cachedump(unsigned int slabs_clsid, unsigned int limit, unsigned int *bytes) {
    char *ret;

    pthread_mutex_lock(&default_engine.cache_lock);
    ret = do_item_cachedump(slabs_clsid, limit, bytes);
    pthread_mutex_unlock(&default_engine.cache_lock);
    return ret;
}

/*
 * Dumps statistics about slab classes
 */
void  item_stats(ADD_STAT add_stats, void *c) {
    pthread_mutex_lock(&default_engine.cache_lock);
    do_item_stats(add_stats, c);
    pthread_mutex_unlock(&default_engine.cache_lock);
}

/*
 * Dumps a list of objects of each size in 32-byte increments
 */
void  item_stats_sizes(ADD_STAT add_stats, void *c) {
    pthread_mutex_lock(&default_engine.cache_lock);
    do_item_stats_sizes(add_stats, c);
    pthread_mutex_unlock(&default_engine.cache_lock);
}

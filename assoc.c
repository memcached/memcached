/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Hash table
 *
 */

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
#include <assert.h>
#include <pthread.h>

#include "default_engine.h"

static pthread_cond_t maintenance_cond = PTHREAD_COND_INITIALIZER;


typedef  unsigned long  int  ub4;   /* unsigned 4-byte quantities */
typedef  unsigned       char ub1;   /* unsigned 1-byte quantities */

/* how many powers of 2's worth of buckets we use */
static unsigned int hashpower = 16;

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/* Main hash table. This is where we look except during expansion. */
static hash_item** primary_hashtable = 0;

/*
 * Previous hash table. During expansion, we look here for keys that haven't
 * been moved over to the primary yet.
 */
static hash_item** old_hashtable = 0;

/* Number of items in the hash table. */
static unsigned int hash_items = 0;

/* Flag: Are we in the middle of expanding now? */
static bool expanding = false;

/*
 * During expansion we migrate values with bucket granularity; this is how
 * far we've gotten so far. Ranges from 0 .. hashsize(hashpower - 1) - 1.
 */
static unsigned int expand_bucket = 0;

ENGINE_ERROR_CODE assoc_init(void) {
    primary_hashtable = calloc(hashsize(hashpower), sizeof(void *));
    return (primary_hashtable != NULL) ? ENGINE_SUCCESS : ENGINE_ENOMEM;
}

hash_item *assoc_find(uint32_t hash, const char *key, const size_t nkey) {
    hash_item *it;
    unsigned int oldbucket;

    if (expanding &&
        (oldbucket = (hash & hashmask(hashpower - 1))) >= expand_bucket)
    {
        it = old_hashtable[oldbucket];
    } else {
        it = primary_hashtable[hash & hashmask(hashpower)];
    }

    hash_item *ret = NULL;
    int depth = 0;
    while (it) {
        if ((nkey == it->item.nkey) && (memcmp(key, ITEM_key(&it->item), nkey) == 0)) {
            ret = it;
            break;
        }
        it = it->h_next;
        ++depth;
    }
    MEMCACHED_ASSOC_FIND(key, nkey, depth);
    return ret;
}

/* returns the address of the item pointer before the key.  if *item == 0,
   the item wasn't found */

static hash_item** _hashitem_before (uint32_t hash,
                                     const char *key,
                                     const size_t nkey) {
    hash_item **pos;
    unsigned int oldbucket;

    if (expanding &&
        (oldbucket = (hash & hashmask(hashpower - 1))) >= expand_bucket)
    {
        pos = &old_hashtable[oldbucket];
    } else {
        pos = &primary_hashtable[hash & hashmask(hashpower)];
    }

    while (*pos && ((nkey != (*pos)->item.nkey) || memcmp(key, ITEM_key(&(*pos)->item), nkey))) {
        pos = &(*pos)->h_next;
    }
    return pos;
}

/* grows the hashtable to the next power of 2. */
static void assoc_expand(void) {
    old_hashtable = primary_hashtable;

    primary_hashtable = calloc(hashsize(hashpower + 1), sizeof(void *));
    if (primary_hashtable) {
        hashpower++;
        expanding = true;
        expand_bucket = 0;
        pthread_cond_signal(&maintenance_cond);
    } else {
        primary_hashtable = old_hashtable;
        /* Bad news, but we can keep running. */
    }
}

/* Note: this isn't an assoc_update.  The key must not already exist to call this */
int assoc_insert(uint32_t hash, hash_item *it) {
    unsigned int oldbucket;

    assert(assoc_find(hash, ITEM_key(&it->item), it->item.nkey) == 0);  /* shouldn't have duplicately named things defined */

    if (expanding &&
        (oldbucket = (hash & hashmask(hashpower - 1))) >= expand_bucket)
    {
        it->h_next = old_hashtable[oldbucket];
        old_hashtable[oldbucket] = it;
    } else {
        it->h_next = primary_hashtable[hash & hashmask(hashpower)];
        primary_hashtable[hash & hashmask(hashpower)] = it;
    }

    hash_items++;
    if (! expanding && hash_items > (hashsize(hashpower) * 3) / 2) {
        assoc_expand();
    }

    MEMCACHED_ASSOC_INSERT(ITEM_key(&it->item), it->item.nkey, hash_items);
    return 1;
}

void assoc_delete(uint32_t hash, const char *key, const size_t nkey) {
    hash_item **before = _hashitem_before(hash, key, nkey);

    if (*before) {
        hash_item *nxt;
        hash_items--;
        /* The DTrace probe cannot be triggered as the last instruction
         * due to possible tail-optimization by the compiler
         */
        MEMCACHED_ASSOC_DELETE(key, nkey, hash_items);
        nxt = (*before)->h_next;
        (*before)->h_next = 0;   /* probably pointless, but whatever. */
        *before = nxt;
        return;
    }
    /* Note:  we never actually get here.  the callers don't delete things
       they can't find. */
    assert(*before != 0);
}


static volatile int do_run_maintenance_thread = 1;

#define DEFAULT_HASH_BULK_MOVE 1
int hash_bulk_move = DEFAULT_HASH_BULK_MOVE;

static void *assoc_maintenance_thread(void *arg) {
    struct default_engine *engine = arg;

    while (do_run_maintenance_thread) {
        int ii = 0;

        /* Lock the cache, and bulk move multiple buckets to the new
         * hash table. */
        pthread_mutex_lock(&engine->cache_lock);

        for (ii = 0; ii < hash_bulk_move && expanding; ++ii) {
            hash_item *it, *next;
            int bucket;

            for (it = old_hashtable[expand_bucket]; NULL != it; it = next) {
                next = it->h_next;

                bucket = engine->server.hash(ITEM_key(&it->item), it->item.nkey, 0) & hashmask(hashpower);
                it->h_next = primary_hashtable[bucket];
                primary_hashtable[bucket] = it;
            }

            old_hashtable[expand_bucket] = NULL;

            expand_bucket++;
            if (expand_bucket == hashsize(hashpower - 1)) {
                expanding = false;
                free(old_hashtable);
                if (engine->config.verbose > 1) {
                    fprintf(stderr, "Hash table expansion done\n");
                }
            }
        }

        while (!expanding) {
            /* We are done expanding.. just wait for next invocation */
            pthread_cond_wait(&maintenance_cond, &engine->cache_lock);
        }

        if (engine->config.verbose > 1) {
            fprintf(stderr, "Start hash table expansion\n");
        }

        pthread_mutex_unlock(&engine->cache_lock);
    }
    return NULL;
}

static pthread_t maintenance_tid;

int start_assoc_maintenance_thread(struct default_engine *engine) {
    int ret;
    char *env = getenv("MEMCACHED_HASH_BULK_MOVE");
    if (env != NULL) {
        hash_bulk_move = atoi(env);
        if (hash_bulk_move == 0) {
            hash_bulk_move = DEFAULT_HASH_BULK_MOVE;
        }
    }
    if ((ret = pthread_create(&maintenance_tid, NULL,
                              assoc_maintenance_thread, engine)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n", strerror(ret));
        return -1;
    }
    return 0;
}

void stop_assoc_maintenance_thread(struct default_engine *engine) {
    pthread_mutex_lock(&engine->cache_lock);
    do_run_maintenance_thread = 0;
    pthread_cond_signal(&maintenance_cond);
    pthread_mutex_unlock(&engine->cache_lock);

    /* Wait for the maintenance thread to stop */
    pthread_join(maintenance_tid, NULL);
}



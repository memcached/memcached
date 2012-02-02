/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Slabs memory allocation, based on powers-of-N. Slabs are up to 1MB in size
 * and are divided into chunks. The chunk sizes start off at the size of the
 * "item" structure plus space for a small key and value. They increase by
 * a multiplier factor from there, up to half the maximum slab size. The last
 * slab size is always 1MB, since that's the maximum item size allowed by the
 * memcached protocol.
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

/* powers-of-N allocation structures */

typedef struct {
    unsigned int size;      /* sizes of items */
    unsigned int perslab;   /* how many items per slab */

    void *slots;           /* list of item ptrs */
    unsigned int sl_curr;   /* total free items in list */

    void *end_page_ptr;         /* pointer to next free item at end of page, or 0 */
    unsigned int end_page_free; /* number of items remaining at end of last alloced page */

    unsigned int slabs;     /* how many slabs were allocated for this class */

    void **slab_list;       /* array of slab pointers */
    unsigned int list_size; /* size of prev array */

    unsigned int killing;  /* index+1 of dying slab, or zero if none */
    size_t requested; /* The number of requested bytes */
} slabclass_t;

static slabclass_t slabclass[MAX_NUMBER_OF_SLAB_CLASSES];
static size_t mem_limit = 0;
static size_t mem_malloced = 0;
static int power_largest;

static void *mem_base = NULL;
static void *mem_current = NULL;
static size_t mem_avail = 0;

/**
 * Access to the slab allocator is protected by this lock
 */
static pthread_mutex_t slabs_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Forward Declarations
 */
static int do_slabs_newslab(const unsigned int id);
static void *memory_allocate(size_t size);

#ifndef DONT_PREALLOC_SLABS
/* Preallocate as many slab pages as possible (called from slabs_init)
   on start-up, so users don't get confused out-of-memory errors when
   they do have free (in-slab) space, but no space to make new slabs.
   if maxslabs is 18 (POWER_LARGEST - POWER_SMALLEST + 1), then all
   slab types can be made.  if max memory is less than 18 MB, only the
   smaller ones will be made.  */
static void slabs_preallocate (const unsigned int maxslabs);
#endif

/*
 * Figures out which slab class (chunk size) is required to store an item of
 * a given size.
 *
 * Given object size, return id to use when allocating/freeing memory for object
 * 0 means error: can't store such a large object
 */

unsigned int slabs_clsid(const size_t size) {
    int res = POWER_SMALLEST;

    if (size == 0)
        return 0;
    while (size > slabclass[res].size)
        if (res++ == power_largest)     /* won't fit in the biggest slab */
            return 0;
    return res;
}

/**
 * Determines the chunk sizes and initializes the slab class descriptors
 * accordingly.
 */
void slabs_init(const size_t limit, const double factor, const bool prealloc) {
    int i = POWER_SMALLEST - 1;
    unsigned int size = sizeof(item) + settings.chunk_size;

    mem_limit = limit;

    if (prealloc) {
        /* Allocate everything in a big chunk with malloc */
        mem_base = malloc(mem_limit);
        if (mem_base != NULL) {
            mem_current = mem_base;
            mem_avail = mem_limit;
        } else {
            fprintf(stderr, "Warning: Failed to allocate requested memory in"
                    " one large chunk.\nWill allocate in smaller chunks\n");
        }
    }

    memset(slabclass, 0, sizeof(slabclass));

    while (++i < POWER_LARGEST && size <= settings.item_size_max / factor) {
        /* Make sure items are always n-byte aligned */
        if (size % CHUNK_ALIGN_BYTES)
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

        slabclass[i].size = size;
        slabclass[i].perslab = settings.item_size_max / slabclass[i].size;
        size *= factor;
        if (settings.verbose > 1) {
            fprintf(stderr, "slab class %3d: chunk size %9u perslab %7u\n",
                    i, slabclass[i].size, slabclass[i].perslab);
        }
    }

    power_largest = i;
    slabclass[power_largest].size = settings.item_size_max;
    slabclass[power_largest].perslab = 1;
    if (settings.verbose > 1) {
        fprintf(stderr, "slab class %3d: chunk size %9u perslab %7u\n",
                i, slabclass[i].size, slabclass[i].perslab);
    }

    /* for the test suite:  faking of how much we've already malloc'd */
    {
        char *t_initial_malloc = getenv("T_MEMD_INITIAL_MALLOC");
        if (t_initial_malloc) {
            mem_malloced = (size_t)atol(t_initial_malloc);
        }

    }

#ifndef DONT_PREALLOC_SLABS
    {
        char *pre_alloc = getenv("T_MEMD_SLABS_ALLOC");

        if (pre_alloc == NULL || atoi(pre_alloc) != 0) {
            slabs_preallocate(power_largest);
        }
    }
#endif
}

#ifndef DONT_PREALLOC_SLABS
static void slabs_preallocate (const unsigned int maxslabs) {
    int i;
    unsigned int prealloc = 0;

    /* pre-allocate a 1MB slab in every size class so people don't get
       confused by non-intuitive "SERVER_ERROR out of memory"
       messages.  this is the most common question on the mailing
       list.  if you really don't want this, you can rebuild without
       these three lines.  */

    for (i = POWER_SMALLEST; i <= POWER_LARGEST; i++) {
        if (++prealloc > maxslabs)
            return;
        do_slabs_newslab(i);
    }

}
#endif

static int grow_slab_list (const unsigned int id) {
    slabclass_t *p = &slabclass[id];
    if (p->slabs == p->list_size) {
        size_t new_size =  (p->list_size != 0) ? p->list_size * 2 : 16;
        void *new_list = realloc(p->slab_list, new_size * sizeof(void *));
        if (new_list == 0) return 0;
        p->list_size = new_size;
        p->slab_list = new_list;
    }
    return 1;
}

static int do_slabs_newslab(const unsigned int id) {
    slabclass_t *p = &slabclass[id];
    int len = settings.slab_reassign ? settings.item_size_max
        : p->size * p->perslab;
    char *ptr;

    if ((mem_limit && mem_malloced + len > mem_limit && p->slabs > 0) ||
        (grow_slab_list(id) == 0) ||
        ((ptr = memory_allocate((size_t)len)) == 0)) {

        MEMCACHED_SLABS_SLABCLASS_ALLOCATE_FAILED(id);
        return 0;
    }

    memset(ptr, 0, (size_t)len);
    p->end_page_ptr = ptr;
    p->end_page_free = p->perslab;

    p->slab_list[p->slabs++] = ptr;
    mem_malloced += len;
    MEMCACHED_SLABS_SLABCLASS_ALLOCATE(id);

    return 1;
}

/*@null@*/
static void *do_slabs_alloc(const size_t size, unsigned int id) {
    slabclass_t *p;
    void *ret = NULL;
    item *it = NULL;

    if (id < POWER_SMALLEST || id > power_largest) {
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, 0);
        return NULL;
    }

    p = &slabclass[id];
    assert(p->sl_curr == 0 || ((item *)p->slots)->slabs_clsid == 0);

#ifdef USE_SYSTEM_MALLOC
    if (mem_limit && mem_malloced + size > mem_limit) {
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, id);
        return 0;
    }
    mem_malloced += size;
    ret = malloc(size);
    MEMCACHED_SLABS_ALLOCATE(size, id, 0, ret);
    return ret;
#endif

    /* fail unless we have space at the end of a recently allocated page,
       we have something on our freelist, or we could allocate a new page */
    if (! (p->end_page_ptr != 0 || p->sl_curr != 0 ||
           do_slabs_newslab(id) != 0)) {
        /* We don't have more memory available */
        ret = NULL;
    } else if (p->sl_curr != 0) {
        /* return off our freelist */
        it = (item *)p->slots;
        p->slots = it->next;
        if (it->next) it->next->prev = 0;
        p->sl_curr--;
        ret = (void *)it;
    } else {
        /* if we recently allocated a whole page, return from that */
        assert(p->end_page_ptr != NULL);
        ret = p->end_page_ptr;
        if (--p->end_page_free != 0) {
            p->end_page_ptr = ((caddr_t)p->end_page_ptr) + p->size;
        } else {
            p->end_page_ptr = 0;
        }
    }

    if (ret) {
        p->requested += size;
        MEMCACHED_SLABS_ALLOCATE(size, id, p->size, ret);
    } else {
        MEMCACHED_SLABS_ALLOCATE_FAILED(size, id);
    }

    return ret;
}

static void do_slabs_free(void *ptr, const size_t size, unsigned int id) {
    slabclass_t *p;
    item *it;

    assert(((item *)ptr)->slabs_clsid == 0);
    assert(id >= POWER_SMALLEST && id <= power_largest);
    if (id < POWER_SMALLEST || id > power_largest)
        return;

    MEMCACHED_SLABS_FREE(size, id, ptr);
    p = &slabclass[id];

#ifdef USE_SYSTEM_MALLOC
    mem_malloced -= size;
    free(ptr);
    return;
#endif

    it = (item *)ptr;
    it->it_flags |= ITEM_SLABBED;
    it->prev = 0;
    it->next = p->slots;
    if (it->next) it->next->prev = it;
    p->slots = it;

    p->sl_curr++;
    p->requested -= size;
    return;
}

static int nz_strcmp(int nzlength, const char *nz, const char *z) {
    int zlength=strlen(z);
    return (zlength == nzlength) && (strncmp(nz, z, zlength) == 0) ? 0 : -1;
}

bool get_stats(const char *stat_type, int nkey, ADD_STAT add_stats, void *c) {
    bool ret = true;

    if (add_stats != NULL) {
        if (!stat_type) {
            /* prepare general statistics for the engine */
            STATS_LOCK();
            APPEND_STAT("bytes", "%llu", (unsigned long long)stats.curr_bytes);
            APPEND_STAT("curr_items", "%u", stats.curr_items);
            APPEND_STAT("total_items", "%u", stats.total_items);
            APPEND_STAT("evictions", "%llu",
                        (unsigned long long)stats.evictions);
            APPEND_STAT("reclaimed", "%llu",
                        (unsigned long long)stats.reclaimed);
            STATS_UNLOCK();
        } else if (nz_strcmp(nkey, stat_type, "items") == 0) {
            item_stats(add_stats, c);
        } else if (nz_strcmp(nkey, stat_type, "slabs") == 0) {
            slabs_stats(add_stats, c);
        } else if (nz_strcmp(nkey, stat_type, "sizes") == 0) {
            item_stats_sizes(add_stats, c);
        } else {
            ret = false;
        }
    } else {
        ret = false;
    }

    return ret;
}

/*@null@*/
static void do_slabs_stats(ADD_STAT add_stats, void *c) {
    int i, total;
    /* Get the per-thread stats which contain some interesting aggregates */
    struct thread_stats thread_stats;
    threadlocal_stats_aggregate(&thread_stats);

    total = 0;
    for(i = POWER_SMALLEST; i <= power_largest; i++) {
        slabclass_t *p = &slabclass[i];
        if (p->slabs != 0) {
            uint32_t perslab, slabs;
            slabs = p->slabs;
            perslab = p->perslab;

            char key_str[STAT_KEY_LEN];
            char val_str[STAT_VAL_LEN];
            int klen = 0, vlen = 0;

            APPEND_NUM_STAT(i, "chunk_size", "%u", p->size);
            APPEND_NUM_STAT(i, "chunks_per_page", "%u", perslab);
            APPEND_NUM_STAT(i, "total_pages", "%u", slabs);
            APPEND_NUM_STAT(i, "total_chunks", "%u", slabs * perslab);
            APPEND_NUM_STAT(i, "used_chunks", "%u",
                            slabs*perslab - p->sl_curr - p->end_page_free);
            APPEND_NUM_STAT(i, "free_chunks", "%u", p->sl_curr);
            APPEND_NUM_STAT(i, "free_chunks_end", "%u", p->end_page_free);
            APPEND_NUM_STAT(i, "mem_requested", "%llu",
                            (unsigned long long)p->requested);
            APPEND_NUM_STAT(i, "get_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].get_hits);
            APPEND_NUM_STAT(i, "cmd_set", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].set_cmds);
            APPEND_NUM_STAT(i, "delete_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].delete_hits);
            APPEND_NUM_STAT(i, "incr_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].incr_hits);
            APPEND_NUM_STAT(i, "decr_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].decr_hits);
            APPEND_NUM_STAT(i, "cas_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].cas_hits);
            APPEND_NUM_STAT(i, "cas_badval", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].cas_badval);
            APPEND_NUM_STAT(i, "touch_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].touch_hits);
            total++;
        }
    }

    /* add overall slab stats and append terminator */

    APPEND_STAT("active_slabs", "%d", total);
    APPEND_STAT("total_malloced", "%llu", (unsigned long long)mem_malloced);
    add_stats(NULL, 0, NULL, 0, c);
}

static void *memory_allocate(size_t size) {
    void *ret;

    if (mem_base == NULL) {
        /* We are not using a preallocated large memory chunk */
        ret = malloc(size);
    } else {
        ret = mem_current;

        if (size > mem_avail) {
            return NULL;
        }

        /* mem_current pointer _must_ be aligned!!! */
        if (size % CHUNK_ALIGN_BYTES) {
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);
        }

        mem_current = ((char*)mem_current) + size;
        if (size < mem_avail) {
            mem_avail -= size;
        } else {
            mem_avail = 0;
        }
    }

    return ret;
}

void *slabs_alloc(size_t size, unsigned int id) {
    void *ret;

    pthread_mutex_lock(&slabs_lock);
    ret = do_slabs_alloc(size, id);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

void slabs_free(void *ptr, size_t size, unsigned int id) {
    pthread_mutex_lock(&slabs_lock);
    do_slabs_free(ptr, size, id);
    pthread_mutex_unlock(&slabs_lock);
}

void slabs_stats(ADD_STAT add_stats, void *c) {
    pthread_mutex_lock(&slabs_lock);
    do_slabs_stats(add_stats, c);
    pthread_mutex_unlock(&slabs_lock);
}

void slabs_adjust_mem_requested(unsigned int id, size_t old, size_t ntotal)
{
    pthread_mutex_lock(&slabs_lock);
    slabclass_t *p;
    if (id < POWER_SMALLEST || id > power_largest) {
        fprintf(stderr, "Internal error! Invalid slab class\n");
        abort();
    }

    p = &slabclass[id];
    p->requested = p->requested - old + ntotal;
    pthread_mutex_unlock(&slabs_lock);
}

static pthread_cond_t maintenance_cond = PTHREAD_COND_INITIALIZER;
static volatile int do_run_slab_thread = 1;

#define DEFAULT_SLAB_BULK_CHECK 1
int slab_bulk_check = DEFAULT_SLAB_BULK_CHECK;

static int slab_rebalance_start(void) {
    slabclass_t *s_cls;
    slabclass_t *d_cls;
    int no_go = 0;

    pthread_mutex_lock(&cache_lock);
    pthread_mutex_lock(&slabs_lock);

    if (slab_rebal.s_clsid < POWER_SMALLEST ||
        slab_rebal.s_clsid > power_largest  ||
        slab_rebal.d_clsid < POWER_SMALLEST ||
        slab_rebal.d_clsid > power_largest  ||
        slab_rebal.s_clsid == slab_rebal.d_clsid)
        no_go = -2;

    s_cls = &slabclass[slab_rebal.s_clsid];
    d_cls = &slabclass[slab_rebal.d_clsid];

    if (d_cls->end_page_ptr || s_cls->end_page_ptr ||
        !grow_slab_list(slab_rebal.d_clsid)) {
        no_go = -1;
    }

    if (s_cls->slabs < 2)
        no_go = -3;

    if (no_go != 0) {
        pthread_mutex_unlock(&slabs_lock);
        pthread_mutex_unlock(&cache_lock);
        return no_go; /* Should use a wrapper function... */
    }

    s_cls->killing = 1;

    slab_rebal.slab_start = s_cls->slab_list[s_cls->killing - 1];
    slab_rebal.slab_end   = (char *)slab_rebal.slab_start +
        (s_cls->size * s_cls->perslab);
    slab_rebal.slab_pos   = slab_rebal.slab_start;
    slab_rebal.done       = 0;

    /* Also tells do_item_get to search for items in this slab */
    slab_rebalance_signal = 2;

    if (settings.verbose > 1) {
        fprintf(stderr, "Started a slab rebalance\n");
    }

    pthread_mutex_unlock(&slabs_lock);
    pthread_mutex_unlock(&cache_lock);

    STATS_LOCK();
    stats.slab_reassign_running = true;
    STATS_UNLOCK();

    return 0;
}

enum move_status {
    MOVE_PASS=0, MOVE_DONE, MOVE_BUSY
};

/* refcount == 0 is safe since nobody can incr while cache_lock is held.
 * refcount != 0 is impossible since flags/etc can be modified in other
 * threads. instead, note we found a busy one and bail. logic in do_item_get
 * will prevent busy items from continuing to be busy
 */
static int slab_rebalance_move(void) {
    slabclass_t *s_cls;
    int x;
    int was_busy = 0;
    int refcount = 0;
    enum move_status status = MOVE_PASS;

    pthread_mutex_lock(&cache_lock);
    pthread_mutex_lock(&slabs_lock);

    s_cls = &slabclass[slab_rebal.s_clsid];

    for (x = 0; x < slab_bulk_check; x++) {
        item *it = slab_rebal.slab_pos;
        status = MOVE_PASS;
        if (it->slabs_clsid != 255) {
            refcount = refcount_incr(&it->refcount);
            if (refcount == 1) { /* item is unlinked, unused */
                if (it->it_flags & ITEM_SLABBED) {
                    /* remove from slab freelist */
                    if (s_cls->slots == it) {
                        s_cls->slots = it->next;
                    }
                    if (it->next) it->next->prev = it->prev;
                    if (it->prev) it->prev->next = it->next;
                    s_cls->sl_curr--;
                    status = MOVE_DONE;
                } else {
                    status = MOVE_BUSY;
                }
            } else if (refcount == 2) { /* item is linked but not busy */
                if ((it->it_flags & ITEM_LINKED) != 0) {
                    do_item_unlink_nolock(it, hash(ITEM_key(it), it->nkey, 0));
                    status = MOVE_DONE;
                } else {
                    /* refcount == 1 + !ITEM_LINKED means the item is being
                     * uploaded to, or was just unlinked but hasn't been freed
                     * yet. Let it bleed off on its own and try again later */
                    status = MOVE_BUSY;
                }
            } else {
                if (settings.verbose > 2) {
                    fprintf(stderr, "Slab reassign hit a busy item: refcount: %d (%d -> %d)\n",
                        it->refcount, slab_rebal.s_clsid, slab_rebal.d_clsid);
                }
                status = MOVE_BUSY;
            }
        }

        switch (status) {
            case MOVE_DONE:
                it->refcount = 0;
                it->it_flags = 0;
                it->slabs_clsid = 255;
                break;
            case MOVE_BUSY:
                slab_rebal.busy_items++;
                was_busy++;
                refcount_decr(&it->refcount);
                break;
            case MOVE_PASS:
                break;
        }

        slab_rebal.slab_pos = (char *)slab_rebal.slab_pos + s_cls->size;
        if (slab_rebal.slab_pos >= slab_rebal.slab_end)
            break;
    }

    if (slab_rebal.slab_pos >= slab_rebal.slab_end) {
        /* Some items were busy, start again from the top */
        if (slab_rebal.busy_items) {
            slab_rebal.slab_pos = slab_rebal.slab_start;
            slab_rebal.busy_items = 0;
        } else {
            slab_rebal.done++;
        }
    }

    pthread_mutex_unlock(&slabs_lock);
    pthread_mutex_unlock(&cache_lock);

    return was_busy;
}

static void slab_rebalance_finish(void) {
    slabclass_t *s_cls;
    slabclass_t *d_cls;

    pthread_mutex_lock(&cache_lock);
    pthread_mutex_lock(&slabs_lock);

    s_cls = &slabclass[slab_rebal.s_clsid];
    d_cls   = &slabclass[slab_rebal.d_clsid];

    /* At this point the stolen slab is completely clear */
    s_cls->slab_list[s_cls->killing - 1] =
        s_cls->slab_list[s_cls->slabs - 1];
    s_cls->slabs--;
    s_cls->killing = 0;

    memset(slab_rebal.slab_start, 0, (size_t)settings.item_size_max);

    d_cls->slab_list[d_cls->slabs++] = slab_rebal.slab_start;
    d_cls->end_page_ptr = slab_rebal.slab_start;
    d_cls->end_page_free = d_cls->perslab;

    slab_rebal.done       = 0;
    slab_rebal.s_clsid    = 0;
    slab_rebal.d_clsid    = 0;
    slab_rebal.slab_start = NULL;
    slab_rebal.slab_end   = NULL;
    slab_rebal.slab_pos   = NULL;

    slab_rebalance_signal = 0;

    pthread_mutex_unlock(&slabs_lock);
    pthread_mutex_unlock(&cache_lock);

    STATS_LOCK();
    stats.slab_reassign_running = false;
    stats.slabs_moved++;
    STATS_UNLOCK();

    if (settings.verbose > 1) {
        fprintf(stderr, "finished a slab move\n");
    }
}

/* Return 1 means a decision was reached.
 * Move to its own thread (created/destroyed as needed) once automover is more
 * complex.
 */
static int slab_automove_decision(int *src, int *dst) {
    static uint64_t evicted_old[POWER_LARGEST];
    static unsigned int slab_zeroes[POWER_LARGEST];
    static unsigned int slab_winner = 0;
    static unsigned int slab_wins   = 0;
    uint64_t evicted_new[POWER_LARGEST];
    uint64_t evicted_diff = 0;
    uint64_t evicted_max  = 0;
    unsigned int highest_slab = 0;
    unsigned int total_pages[POWER_LARGEST];
    int i;
    int source = 0;
    int dest = 0;
    static rel_time_t next_run;

    /* Run less frequently than the slabmove tester. */
    if (current_time >= next_run) {
        next_run = current_time + 10;
    } else {
        return 0;
    }

    item_stats_evictions(evicted_new);
    pthread_mutex_lock(&cache_lock);
    for (i = POWER_SMALLEST; i < power_largest; i++) {
        total_pages[i] = slabclass[i].slabs;
    }
    pthread_mutex_unlock(&cache_lock);

    /* Find a candidate source; something with zero evicts 3+ times */
    for (i = POWER_SMALLEST; i < power_largest; i++) {
        evicted_diff = evicted_new[i] - evicted_old[i];
        if (evicted_diff == 0 && total_pages[i] > 2) {
            slab_zeroes[i]++;
            if (source == 0 && slab_zeroes[i] >= 3)
                source = i;
        } else {
            slab_zeroes[i] = 0;
            if (evicted_diff > evicted_max) {
                evicted_max = evicted_diff;
                highest_slab = i;
            }
        }
        evicted_old[i] = evicted_new[i];
    }

    /* Pick a valid destination */
    if (slab_winner != 0 && slab_winner == highest_slab) {
        slab_wins++;
        if (slab_wins >= 3)
            dest = slab_winner;
    } else {
        slab_wins = 1;
        slab_winner = highest_slab;
    }

    if (source && dest) {
        *src = source;
        *dst = dest;
        return 1;
    }
    return 0;
}

/* Slab rebalancer thread.
 * Does not use spinlocks since it is not timing sensitive. Burn less CPU and
 * go to sleep if locks are contended
 */
static void *slab_maintenance_thread(void *arg) {
    int was_busy = 0;
    int src, dest;

    while (do_run_slab_thread) {
        if (slab_rebalance_signal == 1) {
            if (slab_rebalance_start() < 0) {
                /* Handle errors with more specifity as required. */
                slab_rebalance_signal = 0;
            }

        } else if (slab_rebalance_signal && slab_rebal.slab_start != NULL) {
            /* If we have a decision to continue, continue it */
            was_busy = slab_rebalance_move();
        } else if (settings.slab_automove && slab_automove_decision(&src, &dest) == 1) {
            /* Blind to the return codes. It will retry on its own */
            slabs_reassign(src, dest);
        }

        if (slab_rebal.done) {
            slab_rebalance_finish();
        }

        /* Sleep a bit if no work to do, or waiting on busy objects */
        if (was_busy || !slab_rebalance_signal)
            sleep(1);
    }
    return NULL;
}

static enum reassign_result_type do_slabs_reassign(int src, int dst) {
    if (slab_rebalance_signal != 0)
        return REASSIGN_RUNNING;

    if (src == dst)
        return REASSIGN_SRC_DST_SAME;

    if (src < POWER_SMALLEST || src > power_largest ||
        dst < POWER_SMALLEST || dst > power_largest)
        return REASSIGN_BADCLASS;

    if (slabclass[src].slabs < 2)
        return REASSIGN_NOSPARE;

    if (slabclass[dst].end_page_ptr)
        return REASSIGN_DEST_NOT_FULL;

    if (slabclass[src].end_page_ptr)
        return REASSIGN_SRC_NOT_SAFE;

    slab_rebal.s_clsid = src;
    slab_rebal.d_clsid = dst;

    slab_rebalance_signal = 1;

    return REASSIGN_OK;
}

enum reassign_result_type slabs_reassign(int src, int dst) {
    enum reassign_result_type ret;
    mutex_lock(&slabs_lock);
    ret = do_slabs_reassign(src, dst);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

static pthread_t maintenance_tid;

int start_slab_maintenance_thread(void) {
    int ret;
    slab_rebalance_signal = 0;
    slab_rebal.slab_start = NULL;
    char *env = getenv("MEMCACHED_SLAB_BULK_CHECK");
    if (env != NULL) {
        slab_bulk_check = atoi(env);
        if (slab_bulk_check == 0) {
            slab_bulk_check = DEFAULT_SLAB_BULK_CHECK;
        }
    }
    if ((ret = pthread_create(&maintenance_tid, NULL,
                              slab_maintenance_thread, NULL)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n", strerror(ret));
        return -1;
    }
    return 0;
}

void stop_slab_maintenance_thread(void) {
    mutex_lock(&cache_lock);
    do_run_slab_thread = 0;
    pthread_cond_signal(&maintenance_cond);
    pthread_mutex_unlock(&cache_lock);

    /* Wait for the maintenance thread to stop */
    pthread_join(maintenance_tid, NULL);
}

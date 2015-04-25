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
#include <unistd.h>

/* Forward Declarations */
static void item_link_q(item *it);
static void item_unlink_q(item *it);

#define HOT_LRU 0
#define WARM_LRU 64
#define COLD_LRU 128
#define NOEXP_LRU 192
static unsigned int lru_type_map[4] = {HOT_LRU, WARM_LRU, COLD_LRU, NOEXP_LRU};

#define CLEAR_LRU(id) (id & ~(3<<6))

#define LARGEST_ID POWER_LARGEST
typedef struct {
    uint64_t evicted;
    uint64_t evicted_nonzero;
    uint64_t reclaimed;
    uint64_t outofmemory;
    uint64_t tailrepairs;
    uint64_t expired_unfetched;
    uint64_t evicted_unfetched;
    uint64_t crawler_reclaimed;
    uint64_t crawler_items_checked;
    uint64_t lrutail_reflocked;
    uint64_t moves_to_cold;
    uint64_t moves_to_warm;
    uint64_t moves_within_lru;
    uint64_t direct_reclaims;
    rel_time_t evicted_time;
} itemstats_t;

typedef struct {
    uint64_t histo[60];
    uint64_t ttl_hourplus;
    uint64_t noexp;
    uint64_t reclaimed;
    uint64_t seen;
    rel_time_t start_time;
    rel_time_t end_time;
    bool run_complete;
} crawlerstats_t;

static item *heads[LARGEST_ID];
static item *tails[LARGEST_ID];
static crawler crawlers[LARGEST_ID];
static itemstats_t itemstats[LARGEST_ID];
static unsigned int sizes[LARGEST_ID];
static crawlerstats_t crawlerstats[MAX_NUMBER_OF_SLAB_CLASSES];

static int crawler_count = 0;
static volatile int do_run_lru_crawler_thread = 0;
static volatile int do_run_lru_maintainer_thread = 0;
static int lru_crawler_initialized = 0;
static int lru_maintainer_initialized = 0;
static int lru_maintainer_check_clsid = 0;
static pthread_mutex_t lru_crawler_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  lru_crawler_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t lru_crawler_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t lru_maintainer_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cas_id_lock = PTHREAD_MUTEX_INITIALIZER;

void item_stats_reset(void) {
    int i;
    for (i = 0; i < LARGEST_ID; i++) {
        pthread_mutex_lock(&lru_locks[i]);
        memset(&itemstats[i], 0, sizeof(itemstats_t));
        pthread_mutex_unlock(&lru_locks[i]);
    }
}

static int lru_pull_tail(const int orig_id, const int cur_lru,
        const unsigned int total_chunks, const bool do_evict, const uint32_t cur_hv);
static int lru_crawler_start(uint32_t id, uint32_t remaining);

/* Get the next CAS id for a new item. */
/* TODO: refactor some atomics for this. */
uint64_t get_cas_id(void) {
    static uint64_t cas_id = 0;
    pthread_mutex_lock(&cas_id_lock);
    uint64_t next_id = ++cas_id;
    pthread_mutex_unlock(&cas_id_lock);
    return next_id;
}

static int is_flushed(item *it) {
    rel_time_t oldest_live = settings.oldest_live;
    uint64_t cas = ITEM_get_cas(it);
    uint64_t oldest_cas = settings.oldest_cas;
    if (oldest_live == 0 || oldest_live > current_time)
        return 0;
    if ((it->time <= oldest_live)
            || (oldest_cas != 0 && cas != 0 && cas < oldest_cas)) {
        return 1;
    }
    return 0;
}

static unsigned int noexp_lru_size(int slabs_clsid) {
    int id = CLEAR_LRU(slabs_clsid);
    unsigned int ret;
    pthread_mutex_lock(&lru_locks[id]);
    ret = sizes[id];
    pthread_mutex_unlock(&lru_locks[id]);
    return ret;
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

/**
 * Generates the variable-sized part of the header for an object.
 *
 * key     - The key
 * nkey    - The length of the key
 * flags   - key flags
 * nbytes  - Number of bytes to hold value and addition CRLF terminator
 * suffix  - Buffer for the "VALUE" line suffix (flags, size).
 * nsuffix - The length of the suffix is stored here.
 *
 * Returns the total size of the header.
 */
static size_t item_make_header(const uint8_t nkey, const int flags, const int nbytes,
                     char *suffix, uint8_t *nsuffix) {
    /* suffix is defined at 40 chars elsewhere.. */
    *nsuffix = (uint8_t) snprintf(suffix, 40, " %d %d\r\n", flags, nbytes - 2);
    return sizeof(item) + nkey + *nsuffix + nbytes;
}

item *do_item_alloc(char *key, const size_t nkey, const int flags,
                    const rel_time_t exptime, const int nbytes,
                    const uint32_t cur_hv) {
    int i;
    uint8_t nsuffix;
    item *it = NULL;
    char suffix[40];
    unsigned int total_chunks;
    size_t ntotal = item_make_header(nkey + 1, flags, nbytes, suffix, &nsuffix);
    if (settings.use_cas) {
        ntotal += sizeof(uint64_t);
    }

    unsigned int id = slabs_clsid(ntotal);
    if (id == 0)
        return 0;

    /* If no memory is available, attempt a direct LRU juggle/eviction */
    /* This is a race in order to simplify lru_pull_tail; in cases where
     * locked items are on the tail, you want them to fall out and cause
     * occasional OOM's, rather than internally work around them.
     * This also gives one fewer code path for slab alloc/free
     */
    for (i = 0; i < 5; i++) {
        /* Try to reclaim memory first */
        if (!settings.lru_maintainer_thread) {
            lru_pull_tail(id, COLD_LRU, 0, false, cur_hv);
        }
        it = slabs_alloc(ntotal, id, &total_chunks);
        if (settings.expirezero_does_not_evict)
            total_chunks -= noexp_lru_size(id);
        if (it == NULL) {
            if (settings.lru_maintainer_thread) {
                lru_pull_tail(id, HOT_LRU, total_chunks, false, cur_hv);
                lru_pull_tail(id, WARM_LRU, total_chunks, false, cur_hv);
                lru_pull_tail(id, COLD_LRU, total_chunks, true, cur_hv);
            } else {
                lru_pull_tail(id, COLD_LRU, 0, true, cur_hv);
            }
        } else {
            break;
        }
    }

    if (i > 0) {
        pthread_mutex_lock(&lru_locks[id]);
        itemstats[id].direct_reclaims += i;
        pthread_mutex_unlock(&lru_locks[id]);
    }

    if (it == NULL) {
        pthread_mutex_lock(&lru_locks[id]);
        itemstats[id].outofmemory++;
        pthread_mutex_unlock(&lru_locks[id]);
        return NULL;
    }

    assert(it->slabs_clsid == 0);
    //assert(it != heads[id]);

    /* Refcount is seeded to 1 by slabs_alloc() */
    it->next = it->prev = it->h_next = 0;
    /* Items are initially loaded into the HOT_LRU. This is '0' but I want at
     * least a note here. Compiler (hopefully?) optimizes this out.
     */
    if (settings.lru_maintainer_thread) {
        if (exptime == 0 && settings.expirezero_does_not_evict) {
            id |= NOEXP_LRU;
        } else {
            id |= HOT_LRU;
        }
    } else {
        /* There is only COLD in compat-mode */
        id |= COLD_LRU;
    }
    it->slabs_clsid = id;

    DEBUG_REFCNT(it, '*');
    it->it_flags = settings.use_cas ? ITEM_CAS : 0;
    it->nkey = nkey;
    it->nbytes = nbytes;
    memcpy(ITEM_key(it), key, nkey);
    it->exptime = exptime;
    memcpy(ITEM_suffix(it), suffix, (size_t)nsuffix);
    it->nsuffix = nsuffix;
    return it;
}

void item_free(item *it) {
    size_t ntotal = ITEM_ntotal(it);
    unsigned int clsid;
    assert((it->it_flags & ITEM_LINKED) == 0);
    assert(it != heads[it->slabs_clsid]);
    assert(it != tails[it->slabs_clsid]);
    assert(it->refcount == 0);

    /* so slab size changer can tell later if item is already free or not */
    clsid = ITEM_clsid(it);
    DEBUG_REFCNT(it, 'F');
    slabs_free(it, ntotal, clsid);
}

/**
 * Returns true if an item will fit in the cache (its size does not exceed
 * the maximum for a cache entry.)
 */
bool item_size_ok(const size_t nkey, const int flags, const int nbytes) {
    char prefix[40];
    uint8_t nsuffix;

    size_t ntotal = item_make_header(nkey + 1, flags, nbytes,
                                     prefix, &nsuffix);
    if (settings.use_cas) {
        ntotal += sizeof(uint64_t);
    }

    return slabs_clsid(ntotal) != 0;
}

static void do_item_link_q(item *it) { /* item is the new head */
    item **head, **tail;
    assert((it->it_flags & ITEM_SLABBED) == 0);

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

static void item_link_q(item *it) {
    pthread_mutex_lock(&lru_locks[it->slabs_clsid]);
    do_item_link_q(it);
    pthread_mutex_unlock(&lru_locks[it->slabs_clsid]);
}

static void do_item_unlink_q(item *it) {
    item **head, **tail;
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

static void item_unlink_q(item *it) {
    pthread_mutex_lock(&lru_locks[it->slabs_clsid]);
    do_item_unlink_q(it);
    pthread_mutex_unlock(&lru_locks[it->slabs_clsid]);
}

int do_item_link(item *it, const uint32_t hv) {
    MEMCACHED_ITEM_LINK(ITEM_key(it), it->nkey, it->nbytes);
    assert((it->it_flags & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    it->it_flags |= ITEM_LINKED;
    it->time = current_time;

    STATS_LOCK();
    stats.curr_bytes += ITEM_ntotal(it);
    stats.curr_items += 1;
    stats.total_items += 1;
    STATS_UNLOCK();

    /* Allocate a new CAS ID on link. */
    ITEM_set_cas(it, (settings.use_cas) ? get_cas_id() : 0);
    assoc_insert(it, hv);
    item_link_q(it);
    refcount_incr(&it->refcount);

    return 1;
}

void do_item_unlink(item *it, const uint32_t hv) {
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->nkey, it->nbytes);
    if ((it->it_flags & ITEM_LINKED) != 0) {
        it->it_flags &= ~ITEM_LINKED;
        STATS_LOCK();
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(it), it->nkey, hv);
        item_unlink_q(it);
        do_item_remove(it);
    }
}

/* FIXME: Is it necessary to keep this copy/pasted code? */
void do_item_unlink_nolock(item *it, const uint32_t hv) {
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->nkey, it->nbytes);
    if ((it->it_flags & ITEM_LINKED) != 0) {
        it->it_flags &= ~ITEM_LINKED;
        STATS_LOCK();
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(it), it->nkey, hv);
        do_item_unlink_q(it);
        do_item_remove(it);
    }
}

void do_item_remove(item *it) {
    MEMCACHED_ITEM_REMOVE(ITEM_key(it), it->nkey, it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);
    assert(it->refcount > 0);

    if (refcount_decr(&it->refcount) == 0) {
        item_free(it);
    }
}

/* Copy/paste to avoid adding two extra branches for all common calls, since
 * _nolock is only used in an uncommon case where we want to relink. */
void do_item_update_nolock(item *it) {
    MEMCACHED_ITEM_UPDATE(ITEM_key(it), it->nkey, it->nbytes);
    if (it->time < current_time - ITEM_UPDATE_INTERVAL) {
        assert((it->it_flags & ITEM_SLABBED) == 0);

        if ((it->it_flags & ITEM_LINKED) != 0) {
            do_item_unlink_q(it);
            it->time = current_time;
            do_item_link_q(it);
        }
    }
}

/* Bump the last accessed time, or relink if we're in compat mode */
void do_item_update(item *it) {
    MEMCACHED_ITEM_UPDATE(ITEM_key(it), it->nkey, it->nbytes);
    if (it->time < current_time - ITEM_UPDATE_INTERVAL) {
        assert((it->it_flags & ITEM_SLABBED) == 0);

        if ((it->it_flags & ITEM_LINKED) != 0) {
            it->time = current_time;
            if (!settings.lru_maintainer_thread) {
                item_unlink_q(it);
                item_link_q(it);
            }
        }
    }
}

int do_item_replace(item *it, item *new_it, const uint32_t hv) {
    MEMCACHED_ITEM_REPLACE(ITEM_key(it), it->nkey, it->nbytes,
                           ITEM_key(new_it), new_it->nkey, new_it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);

    do_item_unlink(it, hv);
    return do_item_link(new_it, hv);
}

/*@null@*/
/* This is walking the line of violating lock order, but I think it's safe.
 * If the LRU lock is held, an item in the LRU cannot be wiped and freed.
 * The data could possibly be overwritten, but this is only accessing the
 * headers.
 * It may not be the best idea to leave it like this, but for now it's safe.
 * FIXME: only dumps the hot LRU with the new LRU's.
 */
char *item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes) {
    unsigned int memlimit = 2 * 1024 * 1024;   /* 2MB max response size */
    char *buffer;
    unsigned int bufcurr;
    item *it;
    unsigned int len;
    unsigned int shown = 0;
    char key_temp[KEY_MAX_LENGTH + 1];
    char temp[512];
    unsigned int id = slabs_clsid;
    if (!settings.lru_maintainer_thread)
        id |= COLD_LRU;

    pthread_mutex_lock(&lru_locks[id]);
    it = heads[id];

    buffer = malloc((size_t)memlimit);
    if (buffer == 0) {
        return NULL;
    }
    bufcurr = 0;

    while (it != NULL && (limit == 0 || shown < limit)) {
        assert(it->nkey <= KEY_MAX_LENGTH);
        if (it->nbytes == 0 && it->nkey == 0) {
            it = it->next;
            continue;
        }
        /* Copy the key since it may not be null-terminated in the struct */
        strncpy(key_temp, ITEM_key(it), it->nkey);
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
    pthread_mutex_unlock(&lru_locks[id]);
    return buffer;
}

void item_stats_evictions(uint64_t *evicted) {
    int n;
    for (n = 0; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        int i;
        int x;
        for (x = 0; x < 4; x++) {
            i = n | lru_type_map[x];
            pthread_mutex_lock(&lru_locks[i]);
            evicted[n] += itemstats[i].evicted;
            pthread_mutex_unlock(&lru_locks[i]);
        }
    }
}

void item_stats_totals(ADD_STAT add_stats, void *c) {
    itemstats_t totals;
    memset(&totals, 0, sizeof(itemstats_t));
    int n;
    for (n = 0; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        int x;
        int i;
        for (x = 0; x < 4; x++) {
            i = n | lru_type_map[x];
            pthread_mutex_lock(&lru_locks[i]);
            totals.expired_unfetched += itemstats[i].expired_unfetched;
            totals.evicted_unfetched += itemstats[i].evicted_unfetched;
            totals.evicted += itemstats[i].evicted;
            totals.reclaimed += itemstats[i].reclaimed;
            totals.crawler_reclaimed += itemstats[i].crawler_reclaimed;
            totals.crawler_items_checked += itemstats[i].crawler_items_checked;
            totals.lrutail_reflocked += itemstats[i].lrutail_reflocked;
            totals.moves_to_cold += itemstats[i].moves_to_cold;
            totals.moves_to_warm += itemstats[i].moves_to_warm;
            totals.moves_within_lru += itemstats[i].moves_within_lru;
            totals.direct_reclaims += itemstats[i].direct_reclaims;
            pthread_mutex_unlock(&lru_locks[i]);
        }
    }
    APPEND_STAT("expired_unfetched", "%llu",
                (unsigned long long)totals.expired_unfetched);
    APPEND_STAT("evicted_unfetched", "%llu",
                (unsigned long long)totals.evicted_unfetched);
    APPEND_STAT("evictions", "%llu",
                (unsigned long long)totals.evicted);
    APPEND_STAT("reclaimed", "%llu",
                (unsigned long long)totals.reclaimed);
    APPEND_STAT("crawler_reclaimed", "%llu",
                (unsigned long long)totals.crawler_reclaimed);
    APPEND_STAT("crawler_items_checked", "%llu",
                (unsigned long long)totals.crawler_items_checked);
    APPEND_STAT("lrutail_reflocked", "%llu",
                (unsigned long long)totals.lrutail_reflocked);
    if (settings.lru_maintainer_thread) {
        APPEND_STAT("moves_to_cold", "%llu",
                    (unsigned long long)totals.moves_to_cold);
        APPEND_STAT("moves_to_warm", "%llu",
                    (unsigned long long)totals.moves_to_warm);
        APPEND_STAT("moves_within_lru", "%llu",
                    (unsigned long long)totals.moves_within_lru);
        APPEND_STAT("direct_reclaims", "%llu",
                    (unsigned long long)totals.direct_reclaims);
    }
}

void item_stats(ADD_STAT add_stats, void *c) {
    itemstats_t totals;
    int n;
    for (n = 0; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        memset(&totals, 0, sizeof(itemstats_t));
        int x;
        int i;
        unsigned int size = 0;
        unsigned int age  = 0;
        unsigned int lru_size_map[4];
        const char *fmt = "items:%d:%s";
        char key_str[STAT_KEY_LEN];
        char val_str[STAT_VAL_LEN];
        int klen = 0, vlen = 0;
        for (x = 0; x < 4; x++) {
            i = n | lru_type_map[x];
            pthread_mutex_lock(&lru_locks[i]);
            totals.evicted += itemstats[i].evicted;
            totals.evicted_nonzero += itemstats[i].evicted_nonzero;
            totals.outofmemory += itemstats[i].outofmemory;
            totals.tailrepairs += itemstats[i].tailrepairs;
            totals.reclaimed += itemstats[i].reclaimed;
            totals.expired_unfetched += itemstats[i].expired_unfetched;
            totals.evicted_unfetched += itemstats[i].evicted_unfetched;
            totals.crawler_reclaimed += itemstats[i].crawler_reclaimed;
            totals.crawler_items_checked += itemstats[i].crawler_items_checked;
            totals.lrutail_reflocked += itemstats[i].lrutail_reflocked;
            totals.moves_to_cold += itemstats[i].moves_to_cold;
            totals.moves_to_warm += itemstats[i].moves_to_warm;
            totals.moves_within_lru += itemstats[i].moves_within_lru;
            totals.direct_reclaims += itemstats[i].direct_reclaims;
            size += sizes[i];
            lru_size_map[x] = sizes[i];
            if (lru_type_map[x] == COLD_LRU && tails[i] != NULL)
                age = current_time - tails[i]->time;
            pthread_mutex_unlock(&lru_locks[i]);
        }
        if (size == 0)
            continue;
        APPEND_NUM_FMT_STAT(fmt, n, "number", "%u", size);
        if (settings.lru_maintainer_thread) {
            APPEND_NUM_FMT_STAT(fmt, n, "number_hot", "%u", lru_size_map[0]);
            APPEND_NUM_FMT_STAT(fmt, n, "number_warm", "%u", lru_size_map[1]);
            APPEND_NUM_FMT_STAT(fmt, n, "number_cold", "%u", lru_size_map[2]);
            if (settings.expirezero_does_not_evict)
                APPEND_NUM_FMT_STAT(fmt, n, "number_noexp", "%u", lru_size_map[3]);
        }
        APPEND_NUM_FMT_STAT(fmt, n, "age", "%u", age);
        APPEND_NUM_FMT_STAT(fmt, n, "evicted",
                            "%llu", (unsigned long long)totals.evicted);
        APPEND_NUM_FMT_STAT(fmt, n, "evicted_nonzero",
                            "%llu", (unsigned long long)totals.evicted_nonzero);
        APPEND_NUM_FMT_STAT(fmt, n, "evicted_time",
                            "%u", totals.evicted_time);
        APPEND_NUM_FMT_STAT(fmt, n, "outofmemory",
                            "%llu", (unsigned long long)totals.outofmemory);
        APPEND_NUM_FMT_STAT(fmt, n, "tailrepairs",
                            "%llu", (unsigned long long)totals.tailrepairs);
        APPEND_NUM_FMT_STAT(fmt, n, "reclaimed",
                            "%llu", (unsigned long long)totals.reclaimed);
        APPEND_NUM_FMT_STAT(fmt, n, "expired_unfetched",
                            "%llu", (unsigned long long)totals.expired_unfetched);
        APPEND_NUM_FMT_STAT(fmt, n, "evicted_unfetched",
                            "%llu", (unsigned long long)totals.evicted_unfetched);
        APPEND_NUM_FMT_STAT(fmt, n, "crawler_reclaimed",
                            "%llu", (unsigned long long)totals.crawler_reclaimed);
        APPEND_NUM_FMT_STAT(fmt, n, "crawler_items_checked",
                            "%llu", (unsigned long long)totals.crawler_items_checked);
        APPEND_NUM_FMT_STAT(fmt, n, "lrutail_reflocked",
                            "%llu", (unsigned long long)totals.lrutail_reflocked);
        if (settings.lru_maintainer_thread) {
            APPEND_NUM_FMT_STAT(fmt, n, "moves_to_cold",
                                "%llu", (unsigned long long)totals.moves_to_cold);
            APPEND_NUM_FMT_STAT(fmt, n, "moves_to_warm",
                                "%llu", (unsigned long long)totals.moves_to_warm);
            APPEND_NUM_FMT_STAT(fmt, n, "moves_within_lru",
                                "%llu", (unsigned long long)totals.moves_within_lru);
            APPEND_NUM_FMT_STAT(fmt, n, "direct_reclaims",
                                "%llu", (unsigned long long)totals.direct_reclaims);
        }
    }

    /* getting here means both ascii and binary terminators fit */
    add_stats(NULL, 0, NULL, 0, c);
}

/** dumps out a list of objects of each size, with granularity of 32 bytes */
/*@null@*/
/* Locks are correct based on a technicality. Holds LRU lock while doing the
 * work, so items can't go invalid, and it's only looking at header sizes
 * which don't change.
 */
void item_stats_sizes(ADD_STAT add_stats, void *c) {

    /* max 1MB object, divided into 32 bytes size buckets */
    const int num_buckets = 32768;
    unsigned int *histogram = calloc(num_buckets, sizeof(int));

    if (histogram != NULL) {
        int i;

        /* build the histogram */
        for (i = 0; i < LARGEST_ID; i++) {
            pthread_mutex_lock(&lru_locks[i]);
            item *iter = heads[i];
            while (iter) {
                int ntotal = ITEM_ntotal(iter);
                int bucket = ntotal / 32;
                if ((ntotal % 32) != 0) bucket++;
                if (bucket < num_buckets) histogram[bucket]++;
                iter = iter->next;
            }
            pthread_mutex_unlock(&lru_locks[i]);
        }

        /* write the buffer */
        for (i = 0; i < num_buckets; i++) {
            if (histogram[i] != 0) {
                char key[8];
                snprintf(key, sizeof(key), "%d", i * 32);
                APPEND_STAT(key, "%u", histogram[i]);
            }
        }
        free(histogram);
    }
    add_stats(NULL, 0, NULL, 0, c);
}

/** wrapper around assoc_find which does the lazy expiration logic */
item *do_item_get(const char *key, const size_t nkey, const uint32_t hv) {
    item *it = assoc_find(key, nkey, hv);
    if (it != NULL) {
        refcount_incr(&it->refcount);
        /* Optimization for slab reassignment. prevents popular items from
         * jamming in busy wait. Can only do this here to satisfy lock order
         * of item_lock, slabs_lock. */
        /* This was made unsafe by removal of the cache_lock:
         * slab_rebalance_signal and slab_rebal.* are modified in a separate
         * thread under slabs_lock. If slab_rebalance_signal = 1, slab_start =
         * NULL (0), but slab_end is still equal to some value, this would end
         * up unlinking every item fetched.
         * This is either an acceptable loss, or if slab_rebalance_signal is
         * true, slab_start/slab_end should be put behind the slabs_lock.
         * Which would cause a huge potential slowdown.
         * Could also use a specific lock for slab_rebal.* and
         * slab_rebalance_signal (shorter lock?)
         */
        /*if (slab_rebalance_signal &&
            ((void *)it >= slab_rebal.slab_start && (void *)it < slab_rebal.slab_end)) {
            do_item_unlink(it, hv);
            do_item_remove(it);
            it = NULL;
        }*/
    }
    int was_found = 0;

    if (settings.verbose > 2) {
        int ii;
        if (it == NULL) {
            fprintf(stderr, "> NOT FOUND ");
        } else {
            fprintf(stderr, "> FOUND KEY ");
            was_found++;
        }
        for (ii = 0; ii < nkey; ++ii) {
            fprintf(stderr, "%c", key[ii]);
        }
    }

    if (it != NULL) {
        if (is_flushed(it)) {
            do_item_unlink(it, hv);
            do_item_remove(it);
            it = NULL;
            if (was_found) {
                fprintf(stderr, " -nuked by flush");
            }
        } else if (it->exptime != 0 && it->exptime <= current_time) {
            do_item_unlink(it, hv);
            do_item_remove(it);
            it = NULL;
            if (was_found) {
                fprintf(stderr, " -nuked by expire");
            }
        } else {
            it->it_flags |= ITEM_FETCHED|ITEM_ACTIVE;
            DEBUG_REFCNT(it, '+');
        }
    }

    if (settings.verbose > 2)
        fprintf(stderr, "\n");

    return it;
}

item *do_item_touch(const char *key, size_t nkey, uint32_t exptime,
                    const uint32_t hv) {
    item *it = do_item_get(key, nkey, hv);
    if (it != NULL) {
        it->exptime = exptime;
    }
    return it;
}

/*** LRU MAINTENANCE THREAD ***/

/* Returns number of items remove, expired, or evicted.
 * Callable from worker threads or the LRU maintainer thread */
static int lru_pull_tail(const int orig_id, const int cur_lru,
        const unsigned int total_chunks, const bool do_evict, const uint32_t cur_hv) {
    item *it = NULL;
    int id = orig_id;
    int removed = 0;
    if (id == 0)
        return 0;

    int tries = 5;
    item *search;
    item *next_it;
    void *hold_lock = NULL;
    unsigned int move_to_lru = 0;
    uint64_t limit;

    id |= cur_lru;
    pthread_mutex_lock(&lru_locks[id]);
    search = tails[id];
    /* We walk up *only* for locked items, and if bottom is expired. */
    for (; tries > 0 && search != NULL; tries--, search=next_it) {
        /* we might relink search mid-loop, so search->prev isn't reliable */
        next_it = search->prev;
        if (search->nbytes == 0 && search->nkey == 0 && search->it_flags == 1) {
            /* We are a crawler, ignore it. */
            tries++;
            continue;
        }
        uint32_t hv = hash(ITEM_key(search), search->nkey);
        /* Attempt to hash item lock the "search" item. If locked, no
         * other callers can incr the refcount. Also skip ourselves. */
        if (hv == cur_hv || (hold_lock = item_trylock(hv)) == NULL)
            continue;
        /* Now see if the item is refcount locked */
        if (refcount_incr(&search->refcount) != 2) {
            /* Note pathological case with ref'ed items in tail.
             * Can still unlink the item, but it won't be reusable yet */
            itemstats[id].lrutail_reflocked++;
            /* In case of refcount leaks, enable for quick workaround. */
            /* WARNING: This can cause terrible corruption */
            if (settings.tail_repair_time &&
                    search->time + settings.tail_repair_time < current_time) {
                itemstats[id].tailrepairs++;
                search->refcount = 1;
                /* This will call item_remove -> item_free since refcnt is 1 */
                do_item_unlink_nolock(search, hv);
                item_trylock_unlock(hold_lock);
                continue;
            }
        }

        /* Expired or flushed */
        if ((search->exptime != 0 && search->exptime < current_time)
            || is_flushed(search)) {
            itemstats[id].reclaimed++;
            if ((search->it_flags & ITEM_FETCHED) == 0) {
                itemstats[id].expired_unfetched++;
            }
            /* refcnt 2 -> 1 */
            do_item_unlink_nolock(search, hv);
            /* refcnt 1 -> 0 -> item_free */
            do_item_remove(search);
            item_trylock_unlock(hold_lock);
            removed++;

            /* If all we're finding are expired, can keep going */
            continue;
        }

        /* If we're HOT_LRU or WARM_LRU and over size limit, send to COLD_LRU.
         * If we're COLD_LRU, send to WARM_LRU unless we need to evict
         */
        switch (cur_lru) {
            case HOT_LRU:
                limit = total_chunks * settings.hot_lru_pct / 100;
            case WARM_LRU:
                limit = total_chunks * settings.warm_lru_pct / 100;
                if (sizes[id] > limit) {
                    itemstats[id].moves_to_cold++;
                    move_to_lru = COLD_LRU;
                    do_item_unlink_q(search);
                    it = search;
                    removed++;
                    break;
                } else if ((search->it_flags & ITEM_ACTIVE) != 0) {
                    /* Only allow ACTIVE relinking if we're not too large. */
                    itemstats[id].moves_within_lru++;
                    search->it_flags &= ~ITEM_ACTIVE;
                    do_item_update_nolock(search);
                    do_item_remove(search);
                    item_trylock_unlock(hold_lock);
                } else {
                    /* Don't want to move to COLD, not active, bail out */
                    it = search;
                }
                break;
            case COLD_LRU:
                it = search; /* No matter what, we're stopping */
                if (do_evict) {
                    if (settings.evict_to_free == 0) {
                        /* Don't think we need a counter for this. It'll OOM.  */
                        break;
                    }
                    itemstats[id].evicted++;
                    itemstats[id].evicted_time = current_time - search->time;
                    if (search->exptime != 0)
                        itemstats[id].evicted_nonzero++;
                    if ((search->it_flags & ITEM_FETCHED) == 0) {
                        itemstats[id].evicted_unfetched++;
                    }
                    do_item_unlink_nolock(search, hv);
                    removed++;
                } else if ((search->it_flags & ITEM_ACTIVE) != 0
                        && settings.lru_maintainer_thread) {
                    itemstats[id].moves_to_warm++;
                    search->it_flags &= ~ITEM_ACTIVE;
                    move_to_lru = WARM_LRU;
                    do_item_unlink_q(search);
                    removed++;
                }
                break;
        }
        if (it != NULL)
            break;
    }

    pthread_mutex_unlock(&lru_locks[id]);

    if (it != NULL) {
        if (move_to_lru) {
            it->slabs_clsid = ITEM_clsid(it);
            it->slabs_clsid |= move_to_lru;
            item_link_q(it);
        }
        do_item_remove(it);
        item_trylock_unlock(hold_lock);
    }

    return removed;
}

/* Loop up to N times:
 * If too many items are in HOT_LRU, push to COLD_LRU
 * If too many items are in WARM_LRU, push to COLD_LRU
 * If too many items are in COLD_LRU, poke COLD_LRU tail
 * 1000 loops with 1ms min sleep gives us under 1m items shifted/sec. The
 * locks can't handle much more than that. Leaving a TODO for how to
 * autoadjust in the future.
 */
static int lru_maintainer_juggle(const int slabs_clsid) {
    int i;
    int did_moves = 0;
    bool mem_limit_reached = false;
    unsigned int total_chunks = 0;
    /* TODO: if free_chunks below high watermark, increase aggressiveness */
    slabs_available_chunks(slabs_clsid, &mem_limit_reached, &total_chunks);
    if (settings.expirezero_does_not_evict)
        total_chunks -= noexp_lru_size(slabs_clsid);

    /* Juggle HOT/WARM up to N times */
    for (i = 0; i < 1000; i++) {
        int do_more = 0;
        if (lru_pull_tail(slabs_clsid, HOT_LRU, total_chunks, false, 0) ||
            lru_pull_tail(slabs_clsid, WARM_LRU, total_chunks, false, 0)) {
            do_more++;
        }
        do_more += lru_pull_tail(slabs_clsid, COLD_LRU, total_chunks, false, 0);
        if (do_more == 0)
            break;
        did_moves++;
    }
    return did_moves;
}

/* Will crawl all slab classes a minimum of once per hour */
#define MAX_MAINTCRAWL_WAIT 60 * 60

/* Hoping user input will improve this function. This is all a wild guess.
 * Operation: Kicks crawler for each slab id. Crawlers take some statistics as
 * to items with nonzero expirations. It then buckets how many items will
 * expire per minute for the next hour.
 * This function checks the results of a run, and if it things more than 1% of
 * expirable objects are ready to go, kick the crawler again to reap.
 * It will also kick the crawler once per minute regardless, waiting a minute
 * longer for each time it has no work to do, up to an hour wait time.
 * The latter is to avoid newly started daemons from waiting too long before
 * retrying a crawl.
 */
static void lru_maintainer_crawler_check(void) {
    int i;
    static rel_time_t last_crawls[MAX_NUMBER_OF_SLAB_CLASSES];
    static rel_time_t next_crawl_wait[MAX_NUMBER_OF_SLAB_CLASSES];
    for (i = POWER_SMALLEST; i < MAX_NUMBER_OF_SLAB_CLASSES; i++) {
        crawlerstats_t *s = &crawlerstats[i];
        /* We've not successfully kicked off a crawl yet. */
        if (last_crawls[i] == 0) {
            if (lru_crawler_start(i, 0) > 0) {
                last_crawls[i] = current_time;
            }
        }
        pthread_mutex_lock(&lru_crawler_stats_lock);
        if (s->run_complete) {
            int x;
            /* Should we crawl again? */
            uint64_t possible_reclaims = s->seen - s->noexp;
            uint64_t available_reclaims = 0;
            /* Need to think we can free at least 1% of the items before
             * crawling. */
            /* FIXME: Configurable? */
            uint64_t low_watermark = (s->seen / 100) + 1;
            rel_time_t since_run = current_time - s->end_time;
            /* Don't bother if the payoff is too low. */
            if (settings.verbose > 1)
                fprintf(stderr, "maint crawler: low_watermark: %llu, possible_reclaims: %llu, since_run: %u\n",
                        (unsigned long long)low_watermark, (unsigned long long)possible_reclaims,
                        (unsigned int)since_run);
            for (x = 0; x < 60; x++) {
                if (since_run < (x * 60) + 60)
                    break;
                available_reclaims += s->histo[x];
            }
            if (available_reclaims > low_watermark) {
                last_crawls[i] = 0;
                if (next_crawl_wait[i] > 60)
                    next_crawl_wait[i] -= 60;
            } else if (since_run > 5 && since_run > next_crawl_wait[i]) {
                last_crawls[i] = 0;
                if (next_crawl_wait[i] < MAX_MAINTCRAWL_WAIT)
                    next_crawl_wait[i] += 60;
            }
            if (settings.verbose > 1)
                fprintf(stderr, "maint crawler: available reclaims: %llu, next_crawl: %u\n", (unsigned long long)available_reclaims, next_crawl_wait[i]);
        }
        pthread_mutex_unlock(&lru_crawler_stats_lock);
    }
}

static pthread_t lru_maintainer_tid;

#define MAX_LRU_MAINTAINER_SLEEP 1000000
#define MIN_LRU_MAINTAINER_SLEEP 1000

static void *lru_maintainer_thread(void *arg) {
    int i;
    useconds_t to_sleep = MIN_LRU_MAINTAINER_SLEEP;
    rel_time_t last_crawler_check = 0;

    pthread_mutex_lock(&lru_maintainer_lock);
    if (settings.verbose > 2)
        fprintf(stderr, "Starting LRU maintainer background thread\n");
    while (do_run_lru_maintainer_thread) {
        int did_moves = 0;
        pthread_mutex_unlock(&lru_maintainer_lock);
        usleep(to_sleep);
        pthread_mutex_lock(&lru_maintainer_lock);

        STATS_LOCK();
        stats.lru_maintainer_juggles++;
        STATS_UNLOCK();
        /* We were asked to immediately wake up and poke a particular slab
         * class due to a low watermark being hit */
        if (lru_maintainer_check_clsid != 0) {
            did_moves = lru_maintainer_juggle(lru_maintainer_check_clsid);
            lru_maintainer_check_clsid = 0;
        } else {
            for (i = POWER_SMALLEST; i < MAX_NUMBER_OF_SLAB_CLASSES; i++) {
                did_moves += lru_maintainer_juggle(i);
            }
        }
        if (did_moves == 0) {
            if (to_sleep < MAX_LRU_MAINTAINER_SLEEP)
                to_sleep += 1000;
        } else {
            to_sleep /= 2;
            if (to_sleep < MIN_LRU_MAINTAINER_SLEEP)
                to_sleep = MIN_LRU_MAINTAINER_SLEEP;
        }
        /* Once per second at most */
        if (settings.lru_crawler && last_crawler_check != current_time) {
            lru_maintainer_crawler_check();
            last_crawler_check = current_time;
        }
    }
    pthread_mutex_unlock(&lru_maintainer_lock);
    if (settings.verbose > 2)
        fprintf(stderr, "LRU maintainer thread stopping\n");

    return NULL;
}
int stop_lru_maintainer_thread(void) {
    int ret;
    pthread_mutex_lock(&lru_maintainer_lock);
    /* LRU thread is a sleep loop, will die on its own */
    do_run_lru_maintainer_thread = 0;
    pthread_mutex_unlock(&lru_maintainer_lock);
    if ((ret = pthread_join(lru_maintainer_tid, NULL)) != 0) {
        fprintf(stderr, "Failed to stop LRU maintainer thread: %s\n", strerror(ret));
        return -1;
    }
    settings.lru_maintainer_thread = false;
    return 0;
}

int start_lru_maintainer_thread(void) {
    int ret;

    pthread_mutex_lock(&lru_maintainer_lock);
    do_run_lru_maintainer_thread = 1;
    settings.lru_maintainer_thread = true;
    if ((ret = pthread_create(&lru_maintainer_tid, NULL,
        lru_maintainer_thread, NULL)) != 0) {
        fprintf(stderr, "Can't create LRU maintainer thread: %s\n",
            strerror(ret));
        pthread_mutex_unlock(&lru_maintainer_lock);
        return -1;
    }
    pthread_mutex_unlock(&lru_maintainer_lock);

    return 0;
}

/* If we hold this lock, crawler can't wake up or move */
void lru_maintainer_pause(void) {
    pthread_mutex_lock(&lru_maintainer_lock);
}

void lru_maintainer_resume(void) {
    pthread_mutex_unlock(&lru_maintainer_lock);
}

int init_lru_maintainer(void) {
    if (lru_maintainer_initialized == 0) {
        pthread_mutex_init(&lru_maintainer_lock, NULL);
        lru_maintainer_initialized = 1;
    }
    return 0;
}

/*** ITEM CRAWLER THREAD ***/

static void crawler_link_q(item *it) { /* item is the new tail */
    item **head, **tail;
    assert(it->it_flags == 1);
    assert(it->nbytes == 0);

    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];
    assert(*tail != 0);
    assert(it != *tail);
    assert((*head && *tail) || (*head == 0 && *tail == 0));
    it->prev = *tail;
    it->next = 0;
    if (it->prev) {
        assert(it->prev->next == 0);
        it->prev->next = it;
    }
    *tail = it;
    if (*head == 0) *head = it;
    return;
}

static void crawler_unlink_q(item *it) {
    item **head, **tail;
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
    return;
}

/* This is too convoluted, but it's a difficult shuffle. Try to rewrite it
 * more clearly. */
static item *crawler_crawl_q(item *it) {
    item **head, **tail;
    assert(it->it_flags == 1);
    assert(it->nbytes == 0);
    assert(it->slabs_clsid < LARGEST_ID);
    head = &heads[it->slabs_clsid];
    tail = &tails[it->slabs_clsid];

    /* We've hit the head, pop off */
    if (it->prev == 0) {
        assert(*head == it);
        if (it->next) {
            *head = it->next;
            assert(it->next->prev == it);
            it->next->prev = 0;
        }
        return NULL; /* Done */
    }

    /* Swing ourselves in front of the next item */
    /* NB: If there is a prev, we can't be the head */
    assert(it->prev != it);
    if (it->prev) {
        if (*head == it->prev) {
            /* Prev was the head, now we're the head */
            *head = it;
        }
        if (*tail == it) {
            /* We are the tail, now they are the tail */
            *tail = it->prev;
        }
        assert(it->next != it);
        if (it->next) {
            assert(it->prev->next == it);
            it->prev->next = it->next;
            it->next->prev = it->prev;
        } else {
            /* Tail. Move this above? */
            it->prev->next = 0;
        }
        /* prev->prev's next is it->prev */
        it->next = it->prev;
        it->prev = it->next->prev;
        it->next->prev = it;
        /* New it->prev now, if we're not at the head. */
        if (it->prev) {
            it->prev->next = it;
        }
    }
    assert(it->next != it);
    assert(it->prev != it);

    return it->next; /* success */
}

/* I pulled this out to make the main thread clearer, but it reaches into the
 * main thread's values too much. Should rethink again.
 */
static void item_crawler_evaluate(item *search, uint32_t hv, int i) {
    int slab_id = CLEAR_LRU(i);
    crawlerstats_t *s = &crawlerstats[slab_id];
    itemstats[i].crawler_items_checked++;
    if ((search->exptime != 0 && search->exptime < current_time)
        || is_flushed(search)) {
        itemstats[i].crawler_reclaimed++;
        s->reclaimed++;

        if (settings.verbose > 1) {
            int ii;
            char *key = ITEM_key(search);
            fprintf(stderr, "LRU crawler found an expired item (flags: %d, slab: %d): ",
                search->it_flags, search->slabs_clsid);
            for (ii = 0; ii < search->nkey; ++ii) {
                fprintf(stderr, "%c", key[ii]);
            }
            fprintf(stderr, "\n");
        }
        if ((search->it_flags & ITEM_FETCHED) == 0) {
            itemstats[i].expired_unfetched++;
        }
        do_item_unlink_nolock(search, hv);
        do_item_remove(search);
        assert(search->slabs_clsid == 0);
    } else {
        s->seen++;
        refcount_decr(&search->refcount);
        if (search->exptime == 0) {
            s->noexp++;
        } else if (search->exptime - current_time > 3599) {
            s->ttl_hourplus++;
        } else {
            rel_time_t ttl_remain = search->exptime - current_time;
            int bucket = ttl_remain / 60;
            s->histo[bucket]++;
        }
    }
}

static void *item_crawler_thread(void *arg) {
    int i;
    int crawls_persleep = settings.crawls_persleep;

    pthread_mutex_lock(&lru_crawler_lock);
    if (settings.verbose > 2)
        fprintf(stderr, "Starting LRU crawler background thread\n");
    while (do_run_lru_crawler_thread) {
    pthread_cond_wait(&lru_crawler_cond, &lru_crawler_lock);

    while (crawler_count) {
        item *search = NULL;
        void *hold_lock = NULL;

        for (i = POWER_SMALLEST; i < LARGEST_ID; i++) {
            if (crawlers[i].it_flags != 1) {
                continue;
            }
            pthread_mutex_lock(&lru_locks[i]);
            search = crawler_crawl_q((item *)&crawlers[i]);
            if (search == NULL ||
                (crawlers[i].remaining && --crawlers[i].remaining < 1)) {
                if (settings.verbose > 2)
                    fprintf(stderr, "Nothing left to crawl for %d\n", i);
                crawlers[i].it_flags = 0;
                crawler_count--;
                crawler_unlink_q((item *)&crawlers[i]);
                pthread_mutex_unlock(&lru_locks[i]);
                pthread_mutex_lock(&lru_crawler_stats_lock);
                crawlerstats[CLEAR_LRU(i)].end_time = current_time;
                crawlerstats[CLEAR_LRU(i)].run_complete = true;
                pthread_mutex_unlock(&lru_crawler_stats_lock);
                continue;
            }
            uint32_t hv = hash(ITEM_key(search), search->nkey);
            /* Attempt to hash item lock the "search" item. If locked, no
             * other callers can incr the refcount
             */
            if ((hold_lock = item_trylock(hv)) == NULL) {
                pthread_mutex_unlock(&lru_locks[i]);
                continue;
            }
            /* Now see if the item is refcount locked */
            if (refcount_incr(&search->refcount) != 2) {
                refcount_decr(&search->refcount);
                if (hold_lock)
                    item_trylock_unlock(hold_lock);
                pthread_mutex_unlock(&lru_locks[i]);
                continue;
            }

            /* Frees the item or decrements the refcount. */
            /* Interface for this could improve: do the free/decr here
             * instead? */
            pthread_mutex_lock(&lru_crawler_stats_lock);
            item_crawler_evaluate(search, hv, i);
            pthread_mutex_unlock(&lru_crawler_stats_lock);

            if (hold_lock)
                item_trylock_unlock(hold_lock);
            pthread_mutex_unlock(&lru_locks[i]);

            if (crawls_persleep <= 0 && settings.lru_crawler_sleep) {
                usleep(settings.lru_crawler_sleep);
                crawls_persleep = settings.crawls_persleep;
            }
        }
    }
    if (settings.verbose > 2)
        fprintf(stderr, "LRU crawler thread sleeping\n");
    STATS_LOCK();
    stats.lru_crawler_running = false;
    STATS_UNLOCK();
    }
    pthread_mutex_unlock(&lru_crawler_lock);
    if (settings.verbose > 2)
        fprintf(stderr, "LRU crawler thread stopping\n");

    return NULL;
}

static pthread_t item_crawler_tid;

int stop_item_crawler_thread(void) {
    int ret;
    pthread_mutex_lock(&lru_crawler_lock);
    do_run_lru_crawler_thread = 0;
    pthread_cond_signal(&lru_crawler_cond);
    pthread_mutex_unlock(&lru_crawler_lock);
    if ((ret = pthread_join(item_crawler_tid, NULL)) != 0) {
        fprintf(stderr, "Failed to stop LRU crawler thread: %s\n", strerror(ret));
        return -1;
    }
    settings.lru_crawler = false;
    return 0;
}

int start_item_crawler_thread(void) {
    int ret;

    if (settings.lru_crawler)
        return -1;
    pthread_mutex_lock(&lru_crawler_lock);
    do_run_lru_crawler_thread = 1;
    settings.lru_crawler = true;
    if ((ret = pthread_create(&item_crawler_tid, NULL,
        item_crawler_thread, NULL)) != 0) {
        fprintf(stderr, "Can't create LRU crawler thread: %s\n",
            strerror(ret));
        pthread_mutex_unlock(&lru_crawler_lock);
        return -1;
    }
    pthread_mutex_unlock(&lru_crawler_lock);

    return 0;
}

/* 'remaining' is passed in so the LRU maintainer thread can scrub the whole
 * LRU every time.
 */
static int do_lru_crawler_start(uint32_t id, uint32_t remaining) {
    int i;
    uint32_t sid;
    uint32_t tocrawl[3];
    int starts = 0;
    tocrawl[0] = id | HOT_LRU;
    tocrawl[1] = id | WARM_LRU;
    tocrawl[2] = id | COLD_LRU;

    for (i = 0; i < 3; i++) {
        sid = tocrawl[i];
        pthread_mutex_lock(&lru_locks[sid]);
        if (tails[sid] != NULL) {
            if (settings.verbose > 2)
                fprintf(stderr, "Kicking LRU crawler off for LRU %d\n", sid);
            crawlers[sid].nbytes = 0;
            crawlers[sid].nkey = 0;
            crawlers[sid].it_flags = 1; /* For a crawler, this means enabled. */
            crawlers[sid].next = 0;
            crawlers[sid].prev = 0;
            crawlers[sid].time = 0;
            crawlers[sid].remaining = remaining;
            crawlers[sid].slabs_clsid = sid;
            crawler_link_q((item *)&crawlers[sid]);
            crawler_count++;
            starts++;
        }
        pthread_mutex_unlock(&lru_locks[sid]);
    }
    if (starts) {
        STATS_LOCK();
        stats.lru_crawler_running = true;
        stats.lru_crawler_starts++;
        STATS_UNLOCK();
        pthread_mutex_lock(&lru_crawler_stats_lock);
        memset(&crawlerstats[id], 0, sizeof(crawlerstats_t));
        crawlerstats[id].start_time = current_time;
        pthread_mutex_unlock(&lru_crawler_stats_lock);
    }
    return starts;
}

static int lru_crawler_start(uint32_t id, uint32_t remaining) {
    int starts;
    if (pthread_mutex_trylock(&lru_crawler_lock) != 0) {
        return 0;
    }
    starts = do_lru_crawler_start(id, remaining);
    if (starts) {
        pthread_cond_signal(&lru_crawler_cond);
    }
    pthread_mutex_unlock(&lru_crawler_lock);
    return starts;
}

/* FIXME: Split this into two functions: one to kick a crawler for a sid, and one to
 * parse the string. LRU maintainer code is generating a string to set up a
 * sid.
 * Also only clear the crawlerstats once per sid.
 */
enum crawler_result_type lru_crawler_crawl(char *slabs) {
    char *b = NULL;
    uint32_t sid = 0;
    int starts = 0;
    uint8_t tocrawl[MAX_NUMBER_OF_SLAB_CLASSES];
    if (pthread_mutex_trylock(&lru_crawler_lock) != 0) {
        return CRAWLER_RUNNING;
    }

    /* FIXME: I added this while debugging. Don't think it's needed? */
    memset(tocrawl, 0, sizeof(uint8_t) * MAX_NUMBER_OF_SLAB_CLASSES);
    if (strcmp(slabs, "all") == 0) {
        for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
            tocrawl[sid] = 1;
        }
    } else {
        for (char *p = strtok_r(slabs, ",", &b);
             p != NULL;
             p = strtok_r(NULL, ",", &b)) {

            if (!safe_strtoul(p, &sid) || sid < POWER_SMALLEST
                    || sid >= MAX_NUMBER_OF_SLAB_CLASSES-1) {
                pthread_mutex_unlock(&lru_crawler_lock);
                return CRAWLER_BADCLASS;
            }
            tocrawl[sid] = 1;
        }
    }

    for (sid = POWER_SMALLEST; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
        if (tocrawl[sid])
            starts += do_lru_crawler_start(sid, settings.lru_crawler_tocrawl);
    }
    if (starts) {
        pthread_cond_signal(&lru_crawler_cond);
        pthread_mutex_unlock(&lru_crawler_lock);
        return CRAWLER_OK;
    } else {
        pthread_mutex_unlock(&lru_crawler_lock);
        return CRAWLER_NOTSTARTED;
    }
}

/* If we hold this lock, crawler can't wake up or move */
void lru_crawler_pause(void) {
    pthread_mutex_lock(&lru_crawler_lock);
}

void lru_crawler_resume(void) {
    pthread_mutex_unlock(&lru_crawler_lock);
}

int init_lru_crawler(void) {
    if (lru_crawler_initialized == 0) {
        memset(&crawlerstats, 0, sizeof(crawlerstats_t) * MAX_NUMBER_OF_SLAB_CLASSES);
        if (pthread_cond_init(&lru_crawler_cond, NULL) != 0) {
            fprintf(stderr, "Can't initialize lru crawler condition\n");
            return -1;
        }
        pthread_mutex_init(&lru_crawler_lock, NULL);
        lru_crawler_initialized = 1;
    }
    return 0;
}

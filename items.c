/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* $Id$ */
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

/* Forward Declarations */
static void item_link_q(item *it);
static void item_unlink_q(item *it);
static uint64_t get_cas_id();

/*
 * We only reposition items in the LRU queue if they haven't been repositioned
 * in this many seconds. That saves us from churning on frequently-accessed
 * items.
 */
#define ITEM_UPDATE_INTERVAL 60

#define LARGEST_ID 255
typedef struct {
    unsigned int evicted;
    unsigned int outofmemory;
} itemstats_t;

static item *heads[LARGEST_ID];
static item *tails[LARGEST_ID];
static itemstats_t itemstats[LARGEST_ID];
static unsigned int sizes[LARGEST_ID];

void item_init(void) {
    int i;
    memset(itemstats, 0, sizeof(itemstats_t) * LARGEST_ID);
    for(i = 0; i < LARGEST_ID; i++) {
        heads[i] = NULL;
        tails[i] = NULL;
        sizes[i] = 0;
    }
}

/* Get the next CAS id for a new item. */
uint64_t get_cas_id() {
    static uint64_t cas_id = 0;
    return ++cas_id;
}

/* Enable this for reference-count debugging. */
#if 0
# define DEBUG_REFCNT(it,op) \
                fprintf(stderr, "item %x refcnt(%c) %d %c%c%c\n", \
                        it, op, it->refcount, \
                        (it->it_flags & ITEM_LINKED) ? 'L' : ' ', \
                        (it->it_flags & ITEM_SLABBED) ? 'S' : ' ', \
                        (it->it_flags & ITEM_DELETED) ? 'D' : ' ')
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

/*@null@*/
item *do_item_alloc(char *key, const size_t nkey, const int flags, const rel_time_t exptime, const int nbytes) {
    uint8_t nsuffix;
    item *it;
    char suffix[40];
    size_t ntotal = item_make_header(nkey + 1, flags, nbytes, suffix, &nsuffix);

    unsigned int id = slabs_clsid(ntotal);
    if (id == 0)
        return 0;

    it = slabs_alloc(ntotal, id);
    if (it == 0) {
        int tries = 50;
        item *search;

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
                if (search->exptime == 0 || search->exptime > current_time) {
                    itemstats[id].evicted++;
                    STATS_LOCK();
                    stats.evictions++;
                    STATS_UNLOCK();
                }
                do_item_unlink(search);
                break;
            }
        }
        it = slabs_alloc(ntotal, id);
        if (it == 0) {
            itemstats[id].outofmemory++;
            return NULL;
        }
    }

    assert(it->slabs_clsid == 0);

    it->slabs_clsid = id;

    assert(it != heads[it->slabs_clsid]);

    it->next = it->prev = it->h_next = 0;
    it->refcount = 1;     /* the caller will have a reference */
    DEBUG_REFCNT(it, '*');
    it->it_flags = 0;
    it->nkey = nkey;
    it->nbytes = nbytes;
    strcpy(ITEM_key(it), key);
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
    clsid = it->slabs_clsid;
    it->slabs_clsid = 0;
    it->it_flags |= ITEM_SLABBED;
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

    return slabs_clsid(item_make_header(nkey + 1, flags, nbytes,
                                        prefix, &nsuffix)) != 0;
}

static void item_link_q(item *it) { /* item is the new head */
    item **head, **tail;
    /* always true, warns: assert(it->slabs_clsid <= LARGEST_ID); */
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

static void item_unlink_q(item *it) {
    item **head, **tail;
    /* always true, warns: assert(it->slabs_clsid <= LARGEST_ID); */
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

int do_item_link(item *it) {
    MEMCACHED_ITEM_LINK(ITEM_key(it), it->nbytes);
    assert((it->it_flags & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    assert(it->nbytes < (1024 * 1024));  /* 1MB max size */
    it->it_flags |= ITEM_LINKED;
    it->time = current_time;
    assoc_insert(it);

    STATS_LOCK();
    stats.curr_bytes += ITEM_ntotal(it);
    stats.curr_items += 1;
    stats.total_items += 1;
    STATS_UNLOCK();

    /* Allocate a new CAS ID on link. */
    it->cas_id = get_cas_id();

    item_link_q(it);

    return 1;
}

void do_item_unlink(item *it) {
    MEMCACHED_ITEM_UNLINK(ITEM_key(it), it->nbytes);
    if ((it->it_flags & ITEM_LINKED) != 0) {
        it->it_flags &= ~ITEM_LINKED;
        STATS_LOCK();
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        STATS_UNLOCK();
        assoc_delete(ITEM_key(it), it->nkey);
        item_unlink_q(it);
        if (it->refcount == 0) item_free(it);
    }
}

void do_item_remove(item *it) {
    MEMCACHED_ITEM_REMOVE(ITEM_key(it), it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);
    if (it->refcount != 0) {
        it->refcount--;
        DEBUG_REFCNT(it, '-');
    }
    assert((it->it_flags & ITEM_DELETED) == 0 || it->refcount != 0);
    if (it->refcount == 0 && (it->it_flags & ITEM_LINKED) == 0) {
        item_free(it);
    }
}

void do_item_update(item *it) {
    MEMCACHED_ITEM_UPDATE(ITEM_key(it), it->nbytes);
    if (it->time < current_time - ITEM_UPDATE_INTERVAL) {
        assert((it->it_flags & ITEM_SLABBED) == 0);

        if ((it->it_flags & ITEM_LINKED) != 0) {
            item_unlink_q(it);
            it->time = current_time;
            item_link_q(it);
        }
    }
}

int do_item_replace(item *it, item *new_it) {
    MEMCACHED_ITEM_REPLACE(ITEM_key(it), it->nbytes,
                           ITEM_key(new_it), new_it->nbytes);
    assert((it->it_flags & ITEM_SLABBED) == 0);

    do_item_unlink(it);
    return do_item_link(new_it);
}

/*@null@*/
char *do_item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes) {
    unsigned int memlimit = 2 * 1024 * 1024;   /* 2MB max response size */
    char *buffer;
    unsigned int bufcurr;
    item *it;
    unsigned int len;
    unsigned int shown = 0;
    char temp[512];

    if (slabs_clsid > LARGEST_ID) return NULL;
    it = heads[slabs_clsid];

    buffer = malloc((size_t)memlimit);
    if (buffer == 0) return NULL;
    bufcurr = 0;

    while (it != NULL && (limit == 0 || shown < limit)) {
        len = snprintf(temp, sizeof(temp), "ITEM %s [%d b; %lu s]\r\n", ITEM_key(it), it->nbytes - 2, it->exptime + stats.started);
        if (bufcurr + len + 6 > memlimit)  /* 6 is END\r\n\0 */
            break;
        strcpy(buffer + bufcurr, temp);
        bufcurr += len;
        shown++;
        it = it->next;
    }

    memcpy(buffer + bufcurr, "END\r\n", 6);
    bufcurr += 5;

    *bytes = bufcurr;
    return buffer;
}

char *do_item_stats(int *bytes) {
    size_t bufleft = (size_t) LARGEST_ID * 160;
    char *buffer = malloc(bufleft);
    char *bufcurr = buffer;
    rel_time_t now = current_time;
    int i;
    int linelen;

    if (buffer == NULL) {
        return NULL;
    }

    for (i = 0; i < LARGEST_ID; i++) {
        if (tails[i] != NULL) {
            linelen = snprintf(bufcurr, bufleft,
                "STAT items:%d:number %u\r\n"
                "STAT items:%d:age %u\r\n"
                "STAT items:%d:evicted %u\r\n"
                "STAT items:%d:outofmemory %u\r\n",
                    i, sizes[i], i, now - tails[i]->time, i,
                    itemstats[i].evicted, i, itemstats[i].outofmemory);
            if (linelen + sizeof("END\r\n") < bufleft) {
                bufcurr += linelen;
                bufleft -= linelen;
            }
            else {
                /* The caller didn't allocate enough buffer space. */
                break;
            }
        }
    }
    memcpy(bufcurr, "END\r\n", 6);
    bufcurr += 5;

    *bytes = bufcurr - buffer;
    return buffer;
}

/** dumps out a list of objects of each size, with granularity of 32 bytes */
/*@null@*/
char* do_item_stats_sizes(int *bytes) {
    const int num_buckets = 32768;   /* max 1MB object, divided into 32 bytes size buckets */
    unsigned int *histogram = (unsigned int *)malloc((size_t)num_buckets * sizeof(int));
    char *buf = (char *)malloc(2 * 1024 * 1024); /* 2MB max response size */
    int i;

    if (histogram == 0 || buf == 0) {
        if (histogram) free(histogram);
        if (buf) free(buf);
        return NULL;
    }

    /* build the histogram */
    memset(histogram, 0, (size_t)num_buckets * sizeof(int));
    for (i = 0; i < LARGEST_ID; i++) {
        item *iter = heads[i];
        while (iter) {
            int ntotal = ITEM_ntotal(iter);
            int bucket = ntotal / 32;
            if ((ntotal % 32) != 0) bucket++;
            if (bucket < num_buckets) histogram[bucket]++;
            iter = iter->next;
        }
    }

    /* write the buffer */
    *bytes = 0;
    for (i = 0; i < num_buckets; i++) {
        if (histogram[i] != 0) {
            *bytes += sprintf(&buf[*bytes], "%d %u\r\n", i * 32, histogram[i]);
        }
    }
    *bytes += sprintf(&buf[*bytes], "END\r\n");
    free(histogram);
    return buf;
}

/** returns true if a deleted item's delete-locked-time is over, and it
    should be removed from the namespace */
bool item_delete_lock_over (item *it) {
    assert(it->it_flags & ITEM_DELETED);
    return (current_time >= it->exptime);
}

/** wrapper around assoc_find which does the lazy expiration/deletion logic */
item *do_item_get_notedeleted(const char *key, const size_t nkey, bool *delete_locked) {
    item *it = assoc_find(key, nkey);
    if (delete_locked) *delete_locked = false;
    if (it != NULL && (it->it_flags & ITEM_DELETED)) {
        /* it's flagged as delete-locked.  let's see if that condition
           is past due, and the 5-second delete_timer just hasn't
           gotten to it yet... */
        if (!item_delete_lock_over(it)) {
            if (delete_locked) *delete_locked = true;
            it = NULL;
        }
    }
    if (it != NULL && settings.oldest_live != 0 && settings.oldest_live <= current_time &&
        it->time <= settings.oldest_live) {
        do_item_unlink(it);           /* MTSAFE - cache_lock held */
        it = NULL;
    }
    if (it != NULL && it->exptime != 0 && it->exptime <= current_time) {
        do_item_unlink(it);           /* MTSAFE - cache_lock held */
        it = NULL;
    }

    if (it != NULL) {
        it->refcount++;
        DEBUG_REFCNT(it, '+');
    }
    return it;
}

item *item_get(const char *key, const size_t nkey) {
    return item_get_notedeleted(key, nkey, 0);
}

/** returns an item whether or not it's delete-locked or expired. */
item *do_item_get_nocheck(const char *key, const size_t nkey) {
    item *it = assoc_find(key, nkey);
    if (it) {
        it->refcount++;
        DEBUG_REFCNT(it, '+');
    }
    return it;
}

/* expires items that are more recent than the oldest_live setting. */
void do_item_flush_expired(void) {
    int i;
    item *iter, *next;
    if (settings.oldest_live == 0)
        return;
    for (i = 0; i < LARGEST_ID; i++) {
        /* The LRU is sorted in decreasing time order, and an item's timestamp
         * is never newer than its last access time, so we only need to walk
         * back until we hit an item older than the oldest_live time.
         * The oldest_live checking will auto-expire the remaining items.
         */
        for (iter = heads[i]; iter != NULL; iter = next) {
            if (iter->time >= settings.oldest_live) {
                next = iter->next;
                if ((iter->it_flags & ITEM_SLABBED) == 0) {
                    do_item_unlink(iter);
                }
            } else {
                /* We've hit the first old item. Continue to the next queue. */
                break;
            }
        }
    }
}

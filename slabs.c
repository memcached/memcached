/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Slabs memory allocation, based on powers-of-N. Slabs are up to 1MB in size
 * and are divided into chunks. The chunk sizes start off at the size of the
 * "item" structure plus space for a small key and value. They increase by
 * a multiplier factor from there, up to half the maximum slab size. The last
 * slab size is always 1MB, since that's the maximum item size allowed by the
 * memcached protocol.
 *
 * $Id$
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <event.h>
#include <assert.h>

#include "memcached.h"

#define POWER_SMALLEST 1
#define POWER_LARGEST  200
#define POWER_BLOCK 1048576
#define CHUNK_ALIGN_BYTES (sizeof(void *))

/* powers-of-N allocation structures */

typedef struct {
    unsigned int size;      /* sizes of items */
    unsigned int perslab;   /* how many items per slab */

    void **slots;           /* list of item ptrs */
    unsigned int sl_total;  /* size of previous array */
    unsigned int sl_curr;   /* first free slot */

    void *end_page_ptr;         /* pointer to next free item at end of page, or 0 */
    unsigned int end_page_free; /* number of items remaining at end of last alloced page */

    unsigned int slabs;     /* how many slabs were allocated for this class */

    void **slab_list;       /* array of slab pointers */
    unsigned int list_size; /* size of prev array */

    unsigned int killing;  /* index+1 of dying slab, or zero if none */
} slabclass_t;

static slabclass_t slabclass[POWER_LARGEST+1];
static size_t mem_limit = 0;
static size_t mem_malloced = 0;
static int power_largest;

/*
 * Figures out which slab class (chunk size) is required to store an item of
 * a given size.
 */
unsigned int slabs_clsid(size_t size) {
    int res = POWER_SMALLEST;

    if(size==0)
        return 0;
    while (size > slabclass[res].size)
        if (res++ == power_largest)     /* won't fit in the biggest slab */
            return 0;
    return res;
}

/*
 * Determines the chunk sizes and initializes the slab class descriptors
 * accordingly.
 */
void slabs_init(size_t limit, double factor) {
    int i = POWER_SMALLEST - 1;
    unsigned int size = sizeof(item) + settings.chunk_size;

    /* Factor of 2.0 means use the default memcached behavior */
    if (factor == 2.0 && size < 128)
        size = 128;

    mem_limit = limit;
    memset(slabclass, 0, sizeof(slabclass));

    while (++i < POWER_LARGEST && size <= POWER_BLOCK / 2) {
        /* Make sure items are always n-byte aligned */
        if (size % CHUNK_ALIGN_BYTES)
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

        slabclass[i].size = size;
        slabclass[i].perslab = POWER_BLOCK / slabclass[i].size;
        size *= factor;
        if (settings.verbose > 1) {
            fprintf(stderr, "slab class %3d: chunk size %6d perslab %5d\n",
                    i, slabclass[i].size, slabclass[i].perslab);
        }
    }

    power_largest = i;
    slabclass[power_largest].size = POWER_BLOCK;
    slabclass[power_largest].perslab = 1;

    /* for the test suite:  faking of how much we've already malloc'd */
    {
        char *t_initial_malloc = getenv("T_MEMD_INITIAL_MALLOC");
        if (t_initial_malloc) {
            mem_malloced = atol(getenv("T_MEMD_INITIAL_MALLOC"));
        }

    }

#ifndef DONT_PREALLOC_SLABS
    {
        char *pre_alloc = getenv("T_MEMD_SLABS_ALLOC");
        if (!pre_alloc || atoi(pre_alloc)) {
            slabs_preallocate(limit / POWER_BLOCK);
        }
    }
#endif
}

void slabs_preallocate (unsigned int maxslabs) {
    int i;
    unsigned int prealloc = 0;

    /* pre-allocate a 1MB slab in every size class so people don't get
       confused by non-intuitive "SERVER_ERROR out of memory"
       messages.  this is the most common question on the mailing
       list.  if you really don't want this, you can rebuild without
       these three lines.  */

    for(i=POWER_SMALLEST; i<=POWER_LARGEST; i++) {
        if (++prealloc > maxslabs)
            return;
        slabs_newslab(i);
    }

}

static int grow_slab_list (unsigned int id) {
    slabclass_t *p = &slabclass[id];
    if (p->slabs == p->list_size) {
        size_t new_size =  p->list_size ? p->list_size * 2 : 16;
        void *new_list = realloc(p->slab_list, new_size*sizeof(void*));
        if (new_list == 0) return 0;
        p->list_size = new_size;
        p->slab_list = new_list;
    }
    return 1;
}

int slabs_newslab(unsigned int id) {
    slabclass_t *p = &slabclass[id];
#ifdef ALLOW_SLABS_REASSIGN
    int len = POWER_BLOCK;
#else
    int len = p->size * p->perslab;
#endif
    char *ptr;

    if (mem_limit && mem_malloced + len > mem_limit && p->slabs > 0)
        return 0;

    if (! grow_slab_list(id)) return 0;

    ptr = malloc(len);
    if (ptr == 0) return 0;

    memset(ptr, 0, len);
    p->end_page_ptr = ptr;
    p->end_page_free = p->perslab;

    p->slab_list[p->slabs++] = ptr;
    mem_malloced += len;
    return 1;
}

void *slabs_alloc(size_t size) {
    slabclass_t *p;

    unsigned char id = slabs_clsid(size);
    if (id < POWER_SMALLEST || id > power_largest)
        return 0;

    p = &slabclass[id];
    assert(p->sl_curr == 0 || ((item*)p->slots[p->sl_curr-1])->slabs_clsid == 0);

#ifdef USE_SYSTEM_MALLOC
    if (mem_limit && mem_malloced + size > mem_limit)
        return 0;
    mem_malloced += size;
    return malloc(size);
#endif

    /* fail unless we have space at the end of a recently allocated page,
       we have something on our freelist, or we could allocate a new page */
    if (! (p->end_page_ptr || p->sl_curr || slabs_newslab(id)))
        return 0;

    /* return off our freelist, if we have one */
    if (p->sl_curr)
        return p->slots[--p->sl_curr];

    /* if we recently allocated a whole page, return from that */
    if (p->end_page_ptr) {
        void *ptr = p->end_page_ptr;
        if (--p->end_page_free) {
            p->end_page_ptr += p->size;
        } else {
            p->end_page_ptr = 0;
        }
        return ptr;
    }

    return 0;  /* shouldn't ever get here */
}

void slabs_free(void *ptr, size_t size) {
    unsigned char id = slabs_clsid(size);
    slabclass_t *p;

    assert(((item *)ptr)->slabs_clsid==0);
    assert(id >= POWER_SMALLEST && id <= power_largest);
    if (id < POWER_SMALLEST || id > power_largest)
        return;

    p = &slabclass[id];

#ifdef USE_SYSTEM_MALLOC
    mem_malloced -= size;
    free(ptr);
    return;
#endif

    if (p->sl_curr == p->sl_total) { /* need more space on the free list */
        int new_size = p->sl_total ? p->sl_total*2 : 16;  /* 16 is arbitrary */
        void **new_slots = realloc(p->slots, new_size*sizeof(void *));
        if (new_slots == 0)
            return;
        p->slots = new_slots;
        p->sl_total = new_size;
    }
    p->slots[p->sl_curr++] = ptr;
    return;
}

char* slabs_stats(int *buflen) {
    int i, total;
    char *buf = (char*) malloc(power_largest * 200 + 100);
    char *bufcurr = buf;

    *buflen = 0;
    if (!buf) return 0;

    total = 0;
    for(i = POWER_SMALLEST; i <= power_largest; i++) {
        slabclass_t *p = &slabclass[i];
        if (p->slabs) {
            unsigned int perslab, slabs;

            slabs = p->slabs;
            perslab = p->perslab;

            bufcurr += sprintf(bufcurr, "STAT %d:chunk_size %u\r\n", i, p->size);
            bufcurr += sprintf(bufcurr, "STAT %d:chunks_per_page %u\r\n", i, perslab);
            bufcurr += sprintf(bufcurr, "STAT %d:total_pages %u\r\n", i, slabs);
            bufcurr += sprintf(bufcurr, "STAT %d:total_chunks %u\r\n", i, slabs*perslab);
            bufcurr += sprintf(bufcurr, "STAT %d:used_chunks %u\r\n", i, slabs*perslab - p->sl_curr);
            bufcurr += sprintf(bufcurr, "STAT %d:free_chunks %u\r\n", i, p->sl_curr);
            bufcurr += sprintf(bufcurr, "STAT %d:free_chunks_end %u\r\n", i, p->end_page_free);
            total++;
        }
    }
    bufcurr += sprintf(bufcurr, "STAT active_slabs %d\r\nSTAT total_malloced %llu\r\n", total, (unsigned long long) mem_malloced);
    bufcurr += sprintf(bufcurr, "END\r\n");
    *buflen = bufcurr - buf;
    return buf;
}

#ifdef ALLOW_SLABS_REASSIGN
/* Blows away all the items in a slab class and moves its slabs to another
   class. This is only used by the "slabs reassign" command, for manual tweaking
   of memory allocation. It's disabled by default since it requires that all
   slabs be the same size (which can waste space for chunk size mantissas of
   other than 2.0).
   1 = success
   0 = fail
   -1 = tried. busy. send again shortly. */
int slabs_reassign(unsigned char srcid, unsigned char dstid) {
    void *slab, *slab_end;
    slabclass_t *p, *dp;
    void *iter;
    int was_busy = 0;

    if (srcid < POWER_SMALLEST || srcid > power_largest ||
        dstid < POWER_SMALLEST || dstid > power_largest)
        return 0;

    p = &slabclass[srcid];
    dp = &slabclass[dstid];

    /* fail if src still populating, or no slab to give up in src */
    if (p->end_page_ptr || ! p->slabs)
        return 0;

    /* fail if dst is still growing or we can't make room to hold its new one */
    if (dp->end_page_ptr || ! grow_slab_list(dstid))
        return 0;

    if (p->killing == 0) p->killing = 1;

    slab = p->slab_list[p->killing-1];
    slab_end = slab + POWER_BLOCK;

    for (iter=slab; iter<slab_end; iter+=p->size) {
        item *it = (item *) iter;
        if (it->slabs_clsid) {
            if (it->refcount) was_busy = 1;
            item_unlink(it);
        }
    }

    /* go through free list and discard items that are no longer part of this slab */
    {
        int fi;
        for (fi=p->sl_curr-1; fi>=0; fi--) {
            if (p->slots[fi] >= slab && p->slots[fi] < slab_end) {
                p->sl_curr--;
                if (p->sl_curr > fi) p->slots[fi] = p->slots[p->sl_curr];
            }
        }
    }

    if (was_busy) return -1;

    /* if good, now move it to the dst slab class */
    p->slab_list[p->killing-1] = p->slab_list[p->slabs-1];
    p->slabs--;
    p->killing = 0;
    dp->slab_list[dp->slabs++] = slab;
    dp->end_page_ptr = slab;
    dp->end_page_free = dp->perslab;
    /* this isn't too critical, but other parts of the code do asserts to
       make sure this field is always 0.  */
    for (iter=slab; iter<slab_end; iter+=dp->size) {
        ((item *)iter)->slabs_clsid = 0;
    }
    return 1;
}
#endif

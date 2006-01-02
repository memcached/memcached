/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Slabs memory allocation, based on powers-of-2
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

#define POWER_SMALLEST 3
#define POWER_LARGEST  20
#define POWER_BLOCK 1048576

/* powers-of-2 allocation structures */

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
static unsigned int mem_limit = 0;
static unsigned int mem_malloced = 0;

unsigned int slabs_clsid(unsigned int size) {
    int res = 1;

    if(size==0)
        return 0;
    size--;
    while(size >>= 1)
        res++;
    if (res < POWER_SMALLEST) 
        res = POWER_SMALLEST;
    if (res > POWER_LARGEST)
        res = 0;
    return res;
}

void slabs_init(unsigned int limit) {
    int i;
    int size=1;

    mem_limit = limit;
    for(i=0; i<=POWER_LARGEST; i++, size*=2) {
        slabclass[i].size = size;
        slabclass[i].perslab = POWER_BLOCK / size;
        slabclass[i].slots = 0;
        slabclass[i].sl_curr = slabclass[i].sl_total = slabclass[i].slabs = 0;
        slabclass[i].end_page_ptr = 0;
        slabclass[i].end_page_free = 0;
        slabclass[i].slab_list = 0;
        slabclass[i].list_size = 0;
        slabclass[i].killing = 0;
    }

    slabs_preallocate(limit / POWER_BLOCK);
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
        unsigned int new_size =  p->list_size ? p->list_size * 2 : 16;
        void *new_list = realloc(p->slab_list, new_size*sizeof(void*));
        if (new_list == 0) return 0;
        p->list_size = new_size;
        p->slab_list = new_list;
    }
    return 1;
}

int slabs_newslab(unsigned int id) {
    slabclass_t *p = &slabclass[id];
    int num = p->perslab;
    int len = POWER_BLOCK;
    char *ptr;

    if (mem_limit && mem_malloced + len > mem_limit)
        return 0;

    if (! grow_slab_list(id)) return 0;
   
    ptr = malloc(len);
    if (ptr == 0) return 0;

    memset(ptr, 0, len);
    p->end_page_ptr = ptr;
    p->end_page_free = num;

    p->slab_list[p->slabs++] = ptr;
    mem_malloced += len;
    return 1;
}

void *slabs_alloc(unsigned int size) {
    slabclass_t *p;

    unsigned char id = slabs_clsid(size);
    if (id < POWER_SMALLEST || id > POWER_LARGEST)
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

void slabs_free(void *ptr, unsigned int size) {
    unsigned char id = slabs_clsid(size);
    slabclass_t *p;

    assert(((item *)ptr)->slabs_clsid==0);
    assert(id >= POWER_SMALLEST && id <= POWER_LARGEST);
    if (id < POWER_SMALLEST || id > POWER_LARGEST)
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
    char *buf = (char*) malloc(8192);
    char *bufcurr = buf;

    *buflen = 0;
    if (!buf) return 0;

    total = 0;
    for(i = POWER_SMALLEST; i <= POWER_LARGEST; i++) {
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
    bufcurr += sprintf(bufcurr, "STAT active_slabs %d\r\nSTAT total_malloced %u\r\n", total, mem_malloced);
    bufcurr += sprintf(bufcurr, "END\r\n");
    *buflen = bufcurr - buf;
    return buf;
}

/* 1 = success
   0 = fail
   -1 = tried. busy. send again shortly. */
int slabs_reassign(unsigned char srcid, unsigned char dstid) {
    void *slab, *slab_end;
    slabclass_t *p, *dp;
    void *iter;
    int was_busy = 0;

    if (srcid < POWER_SMALLEST || srcid > POWER_LARGEST ||
        dstid < POWER_SMALLEST || dstid > POWER_LARGEST)
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

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
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <errno.h>
#include <event.h>
#include <malloc.h>

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
    }
}

int slabs_newslab(unsigned int id) {
    slabclass_t *p = &slabclass[id];
    int num = p->perslab;
    int len = POWER_BLOCK;
    int i;
    void **cur;
    void **new_slots;
    char *ptr;

    if (mem_limit && mem_malloced + len > mem_limit)
        return 0;

    ptr = malloc(len);
    if (ptr == 0) return 0;

    p->end_page_ptr = ptr;
    p->end_page_free = num;

    p->slabs++;
    mem_malloced += len;
    return 1;
}

void *slabs_alloc(unsigned int id) {
    slabclass_t *p;

    if (id < POWER_SMALLEST || id > POWER_LARGEST)
        return 0;

    p = &slabclass[id];

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

void slabs_free(void *ptr, unsigned int id) {
    slabclass_t *p;
    void **new_slots;

    if (id < POWER_SMALLEST || id > POWER_LARGEST)
        return;

    p = &slabclass[id];

    if (p->sl_curr == p->sl_total) { /* need more space on the free list */
        int new_size = p->sl_total ? p->sl_total*2 : 16;  /* 16 is arbitrary */
        new_slots = realloc(p->slots, new_size*sizeof(void *));
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

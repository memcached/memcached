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
#include <Judy.h>

#include "memcached.h"

#define POWER_SMALLEST 6
#define POWER_LARGEST  20
#define POWER_BLOCK 1048576

/* powers-of-2 allocation structures */

typedef struct {
    unsigned int size;      /* sizes of items */
    unsigned int perslab;   /* how many items per slab */
    void **slots;           /* list of item ptrs */
    unsigned int sl_total;  /* size of previous array */
    unsigned int sl_curr;   /* first free slot */
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

    if (p->sl_total < num) {
        new_slots = realloc(p->slots, num*sizeof(void *));
        if (new_slots == 0)
            return 0;
        p->slots = new_slots;
        p->sl_total = num;
    }

    ptr = malloc(len);
    if (ptr == 0) return 0;
    for (i=0, cur = p->slots; i<num; i++, cur++, ptr+=p->size) {
            *cur = ptr;
    }
    p->sl_curr+=num;
    p->slabs++;
    mem_malloced += len;

    return 1;
}

void *slabs_alloc(unsigned int id) {
    slabclass_t *p;

    if (id < POWER_SMALLEST || id > POWER_LARGEST)
        return 0;

    p = &slabclass[id];

    if (p->sl_curr == 0 && !slabs_newslab(id)) return 0;

    return p->slots[--p->sl_curr];
}

void slabs_free(void *ptr, unsigned int id) {
    slabclass_t *p;
    void **new_slots;

    if (id < POWER_SMALLEST || id > POWER_LARGEST)
        return;

    p = &slabclass[id];

    if (p->sl_curr == p->sl_total) { /* need more space on the free list */
        new_slots = realloc(p->slots, p->sl_total*2*sizeof(void *));
        if (new_slots == 0)
            return;
        p->slots = new_slots;
        p->sl_total *= 2;
    }
    p->slots[p->sl_curr++] = ptr;
    return;
}

void slabs_stats(char *buffer, int buflen) {
    int i, total;
    char *bufcurr = buffer;

    if (buflen < 4096) {
        strcpy(buffer, "ERROR buffer too small");
        return;
    }

    for(i = POWER_SMALLEST; i <= POWER_LARGEST; i++) {
        if (slabclass[i].slabs) {
            unsigned int perslab, slabs;

            slabs = slabclass[i].slabs;
            perslab = slabclass[i].perslab;

            bufcurr += sprintf(bufcurr, "STAT %d:chunk_size %u\r\n", i, slabclass[i].size);
            bufcurr += sprintf(bufcurr, "STAT %d:chunks_per_page %u\r\n", i, perslab);
            bufcurr += sprintf(bufcurr, "STAT %d:total_pages %u\r\n", i, slabs);
            bufcurr += sprintf(bufcurr, "STAT %d:total_chunks %u\r\n", i, slabs*perslab);
            bufcurr += sprintf(bufcurr, "STAT %d:used_chunks %u\r\n", i, slabs*perslab - slabclass[i].sl_curr);
            bufcurr += sprintf(bufcurr, "STAT %d:free_chunks %u\r\n", i, slabclass[i].sl_curr);
            total++;
        }
    }
    bufcurr += sprintf(bufcurr, "STAT active_slabs %d\r\nSTAT total_malloced %u\r\n", total, mem_malloced);
    strcpy(bufcurr, "END");
    return;
}

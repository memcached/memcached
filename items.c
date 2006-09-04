/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* $Id$ */
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
#include <time.h>
#include <event.h>
#include <assert.h>
#include "memcached.h"
#define LARGEST_ID 255
static item *heads[LARGEST_ID];
static item *tails[LARGEST_ID];
unsigned int sizes[LARGEST_ID];
void item_init(void) {
    int i;
    for(i=0; i<LARGEST_ID; i++) {
        heads[i]=0;
        tails[i]=0;
        sizes[i]=0;
    }
}
/*
 * Generates the variable-sized part of the header for an object.
 *
 * suffix  - Buffer for the "VALUE" line suffix (flags, size).
 * nsuffix - The length of the suffix is stored here.
 * keylen  - The length of the key plus any padding required to word-align the
 *           "VALUE" suffix (which is done to speed up copying.)
 *
 * Returns the total size of the header.
 */
int item_make_header(char *key, int flags, int nbytes,
                     char *suffix, int *nsuffix, int *keylen) {
    *keylen = strlen(key) + 1; if(*keylen % 4) *keylen += 4 - (*keylen % 4);
    *nsuffix = sprintf(suffix, " %u %u\r\n", flags, nbytes - 2);
    return sizeof(item) + *keylen + *nsuffix + nbytes;
}
item *item_alloc(char *key, int flags, rel_time_t exptime, int nbytes) {
    int nsuffix, ntotal, len;
    item *it;
    unsigned int id;
    char suffix[40];
    ntotal = item_make_header(key, flags, nbytes, suffix, &nsuffix, &len);
    id = slabs_clsid(ntotal);
    if (id == 0)
        return 0;
    it = slabs_alloc(ntotal);
    if (it == 0) {
        int tries = 50;
        item *search;
        /* If requested to not push old items out of cache when memory runs out,
         * we're out of luck at this point...
         */
        if (!settings.evict_to_free) return 0;
        /*
         * try to get one off the right LRU
         * don't necessariuly unlink the tail because it may be locked: refcount>0
         * search up from tail an item with refcount==0 and unlink it; give up after 50
         * tries
         */
        if (id > LARGEST_ID) return 0;
        if (tails[id]==0) return 0;
        for (search = tails[id]; tries>0 && search; tries--, search=search->prev) {
            if (search->refcount==0) {
                item_unlink(search);
                break;
            }
        }
        it = slabs_alloc(ntotal);
        if (it==0) return 0;
    }
    assert(it->slabs_clsid == 0);
    it->slabs_clsid = id;
    assert(it != heads[it->slabs_clsid]);
    it->next = it->prev = it->h_next = 0;
    it->refcount = 0;
    it->it_flags = 0;
    it->nkey = len;
    it->nbytes = nbytes;
    strcpy(ITEM_key(it), key);
    it->exptime = exptime;
    memcpy(ITEM_suffix(it), suffix, nsuffix);
    it->nsuffix = nsuffix;
    return it;
}
void item_free(item *it) {
    unsigned int ntotal = ITEM_ntotal(it);
    assert((it->it_flags & ITEM_LINKED) == 0);
    assert(it != heads[it->slabs_clsid]);
    assert(it != tails[it->slabs_clsid]);
    assert(it->refcount == 0);
    /* so slab size changer can tell later if item is already free or not */
    it->slabs_clsid = 0;
    it->it_flags |= ITEM_SLABBED;
    slabs_free(it, ntotal);
}
/*
 * Returns true if an item will fit in the cache (its size does not exceed
 * the maximum for a cache entry.)
 */
int item_size_ok(char *key, int flags, int nbytes) {
    char prefix[40];
    int keylen, nsuffix;
    return slabs_clsid(item_make_header(key, flags, nbytes,
                                        prefix, &nsuffix, &keylen)) != 0;
}
void item_link_q(item *it) { /* item is the new head */
    item **head, **tail;
    assert(it->slabs_clsid <= LARGEST_ID);
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
void item_unlink_q(item *it) {
    item **head, **tail;
    assert(it->slabs_clsid <= LARGEST_ID);
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
int item_link(item *it) {
    assert((it->it_flags & (ITEM_LINKED|ITEM_SLABBED)) == 0);
    assert(it->nbytes < 1048576);
    it->it_flags |= ITEM_LINKED;
    it->time = current_time;
    assoc_insert(ITEM_key(it), it);
    stats.curr_bytes += ITEM_ntotal(it);
    stats.curr_items += 1;
    stats.total_items += 1;
    item_link_q(it);
    return 1;
}
void item_unlink(item *it) {
    if (it->it_flags & ITEM_LINKED) {
        it->it_flags &= ~ITEM_LINKED;
        stats.curr_bytes -= ITEM_ntotal(it);
        stats.curr_items -= 1;
        assoc_delete(ITEM_key(it));
        item_unlink_q(it);
    }
    if (it->refcount == 0) item_free(it);
}
void item_remove(item *it) {
    assert((it->it_flags & ITEM_SLABBED) == 0);
    if (it->refcount) it->refcount--;
    assert((it->it_flags & ITEM_DELETED) == 0 || it->refcount);
    if (it->refcount == 0 && (it->it_flags & ITEM_LINKED) == 0) {
        item_free(it);
    }
}
void item_update(item *it) {
    assert((it->it_flags & ITEM_SLABBED) == 0);
    item_unlink_q(it);
    it->time = current_time;
    item_link_q(it);
}
int item_replace(item *it, item *new_it) {
    assert((it->it_flags & ITEM_SLABBED) == 0);
    item_unlink(it);
    return item_link(new_it);
}
char *item_cachedump(unsigned int slabs_clsid, unsigned int limit, unsigned int *bytes) {
    int memlimit = 2*1024*1024;
    char *buffer;
    int bufcurr;
    item *it;
    int len;
    int shown = 0;
    char temp[512];
    if (slabs_clsid > LARGEST_ID) return 0;
    it = heads[slabs_clsid];
    buffer = malloc(memlimit);
    if (buffer == 0) return 0;
    bufcurr = 0;
    while (it && (!limit || shown < limit)) {
        len = sprintf(temp, "ITEM %s [%u b; %lu s]\r\n", ITEM_key(it), it->nbytes - 2, it->time + stats.started);
        if (bufcurr + len + 6 > memlimit)  /* 6 is END\r\n\0 */
            break;
        strcpy(buffer + bufcurr, temp);
        bufcurr+=len;
        shown++;
        it = it->next;
    }
    strcpy(buffer+bufcurr, "END\r\n");
    bufcurr+=5;
    *bytes = bufcurr;
    return buffer;
}
void item_stats(char *buffer, int buflen) {
    int i;
    char *bufcurr = buffer;
    rel_time_t now = current_time;
    if (buflen < 4096) {
        strcpy(buffer, "SERVER_ERROR out of memory");
        return;
    }
    for (i=0; i<LARGEST_ID; i++) {
        if (tails[i])
            bufcurr += sprintf(bufcurr, "STAT items:%u:number %u\r\nSTAT items:%u:age %u\r\n",
                               i, sizes[i], i, now - tails[i]->time);
    }
    strcpy(bufcurr, "END");
    return;
}
/* dumps out a list of objects of each size, with granularity of 32 bytes */
char* item_stats_sizes(int *bytes) {
    int num_buckets = 32768;   /* max 1MB object, divided into 32 bytes size buckets */
    unsigned int *histogram = (unsigned int*) malloc(num_buckets * sizeof(int));
    char *buf = (char*) malloc(1024*1024*2*sizeof(char));
    int i;
    if (histogram == 0 || buf == 0) {
        if (histogram) free(histogram);
        if (buf) free(buf);
        return 0;
    }
    /* build the histogram */
    memset(histogram, 0, num_buckets * sizeof(int));
    for (i=0; i<LARGEST_ID; i++) {
        item *iter = heads[i];
        while (iter) {
            int ntotal = ITEM_ntotal(iter);
            int bucket = ntotal / 32;
            if (ntotal % 32) bucket++;
            if (bucket < num_buckets) histogram[bucket]++;
            iter = iter->next;
        }
    }
    /* write the buffer */
    *bytes = 0;
    for (i=0; i<num_buckets; i++) {
        if (histogram[i]) {
            *bytes += sprintf(&buf[*bytes], "%u %u\r\n", i*32, histogram[i]);
        }
    }
    *bytes += sprintf(&buf[*bytes], "END\r\n");
    free(histogram);
    return buf;
}
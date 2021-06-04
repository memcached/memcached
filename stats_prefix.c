/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* Author: Steven Grimm <sgrimm@facebook.com> */
#include "memcached.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* Hash table that uses the global hash function */
static PREFIX_STATS *prefix_stats[PREFIX_HASH_SIZE];

static char prefix_delimiter;
static int num_prefixes = 0;
static int total_prefix_size = 0;

void stats_prefix_init(char delimiter) {
    prefix_delimiter = delimiter;
    memset(prefix_stats, 0, sizeof(prefix_stats));
}

void stats_prefix_clear(void) {
    int i;

    for (i = 0; i < PREFIX_HASH_SIZE; i++) {
        PREFIX_STATS *cur, *next;
        for (cur = prefix_stats[i]; cur != NULL; cur = next) {
            next = cur->next;
            free(cur->prefix);
            free(cur);
        }
        prefix_stats[i] = NULL;
    }
    num_prefixes = 0;
    total_prefix_size = 0;
}

PREFIX_STATS *stats_prefix_find(const char *key, const size_t nkey) {
    PREFIX_STATS *pfs;
    uint32_t hashval;
    size_t length;
    bool bailout = true;

    assert(key != NULL);

    for (length = 0; length < nkey && key[length] != '\0'; length++) {
        if (key[length] == prefix_delimiter) {
            bailout = false;
            break;
        }
    }

    if (bailout) {
        return NULL;
    }

    hashval = hash(key, length) % PREFIX_HASH_SIZE;

    for (pfs = prefix_stats[hashval]; NULL != pfs; pfs = pfs->next) {
        if (strncmp(pfs->prefix, key, length) == 0)
            return pfs;
    }

    pfs = calloc(sizeof(PREFIX_STATS), 1);
    if (NULL == pfs) {
        perror("Can't allocate space for stats structure: calloc");
        return NULL;
    }

    pfs->prefix = malloc(length + 1);
    if (NULL == pfs->prefix) {
        perror("Can't allocate space for copy of prefix: malloc");
        free(pfs);
        return NULL;
    }

    strncpy(pfs->prefix, key, length);
    pfs->prefix[length] = '\0';      /* because strncpy() sucks */
    pfs->prefix_len = length;

    pfs->next = prefix_stats[hashval];
    prefix_stats[hashval] = pfs;

    num_prefixes++;
    total_prefix_size += length;

    return pfs;
}

void stats_prefix_record_get(const char *key, const size_t nkey, const bool is_hit) {
    PREFIX_STATS *pfs;

    STATS_LOCK();
    pfs = stats_prefix_find(key, nkey);
    if (NULL != pfs) {
        pfs->num_gets++;
        if (is_hit) {
            pfs->num_hits++;
        }
    }
    STATS_UNLOCK();
}

void stats_prefix_record_delete(const char *key, const size_t nkey) {
    PREFIX_STATS *pfs;

    STATS_LOCK();
    pfs = stats_prefix_find(key, nkey);
    if (NULL != pfs) {
        pfs->num_deletes++;
    }
    STATS_UNLOCK();
}

void stats_prefix_record_set(const char *key, const size_t nkey) {
    PREFIX_STATS *pfs;

    STATS_LOCK();
    pfs = stats_prefix_find(key, nkey);
    if (NULL != pfs) {
        pfs->num_sets++;
    }
    STATS_UNLOCK();
}

char *stats_prefix_dump(int *length) {
    const char *format = "PREFIX %s get %llu hit %llu set %llu del %llu\r\n";
    PREFIX_STATS *pfs;
    char *buf;
    int i, pos;
    size_t size = 0, written = 0;
#ifndef NDEBUG
    size_t total_written = 0;
#endif
    /*
     * Figure out how big the buffer needs to be. This is the sum of the
     * lengths of the prefixes themselves, plus the size of one copy of
     * the per-prefix output with 20-digit values for all the counts,
     * plus space for the "END" at the end.
     */
    STATS_LOCK();
    size = strlen(format) + total_prefix_size +
           num_prefixes * (strlen(format) - 2 /* %s */
                           + 4 * (20 - 4)) /* %llu replaced by 20-digit num */
                           + sizeof("END\r\n");
    buf = malloc(size);
    if (NULL == buf) {
        perror("Can't allocate stats response: malloc");
        STATS_UNLOCK();
        return NULL;
    }

    pos = 0;
    for (i = 0; i < PREFIX_HASH_SIZE; i++) {
        for (pfs = prefix_stats[i]; NULL != pfs; pfs = pfs->next) {
            written = snprintf(buf + pos, size-pos, format,
                           pfs->prefix, pfs->num_gets, pfs->num_hits,
                           pfs->num_sets, pfs->num_deletes);
            pos += written;
#ifndef NDEBUG
            total_written += written;
            assert(total_written < size);
#endif
        }
    }

    STATS_UNLOCK();
    memcpy(buf + pos, "END\r\n", 6);

    *length = pos + 5;
    return buf;
}

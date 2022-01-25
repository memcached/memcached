/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#ifndef NDEBUG
#include <signal.h>
#endif

#include "cache.h"

#ifndef NDEBUG
const uint64_t redzone_pattern = 0xdeadbeefcafedeed;
int cache_error = 0;
#endif

cache_t* cache_create(const char *name, size_t bufsize, size_t align) {
    cache_t* ret = calloc(1, sizeof(cache_t));
    char* nm = strdup(name);
    if (ret == NULL || nm == NULL ||
        pthread_mutex_init(&ret->mutex, NULL) == -1) {
        free(ret);
        free(nm);
        return NULL;
    }

    ret->name = nm;
    STAILQ_INIT(&ret->head);

#ifndef NDEBUG
    ret->bufsize = bufsize + 2 * sizeof(redzone_pattern);
#else
    ret->bufsize = bufsize;
#endif
    assert(ret->bufsize >= sizeof(struct cache_free_s));

    return ret;
}

void cache_set_limit(cache_t *cache, int limit) {
    pthread_mutex_lock(&cache->mutex);
    cache->limit = limit;
    pthread_mutex_unlock(&cache->mutex);
}

static inline void* get_object(void *ptr) {
#ifndef NDEBUG
    uint64_t *pre = ptr;
    return pre + 1;
#else
    return ptr;
#endif
}

void cache_destroy(cache_t *cache) {
    while (!STAILQ_EMPTY(&cache->head)) {
        struct cache_free_s *o = STAILQ_FIRST(&cache->head);
        STAILQ_REMOVE_HEAD(&cache->head, c_next);
        free(o);
    }
    free(cache->name);
    pthread_mutex_destroy(&cache->mutex);
    free(cache);
}

void* cache_alloc(cache_t *cache) {
    void *ret;
    pthread_mutex_lock(&cache->mutex);
    ret = do_cache_alloc(cache);
    pthread_mutex_unlock(&cache->mutex);
    return ret;
}

void* do_cache_alloc(cache_t *cache) {
    void *ret;
    void *object;
    if (cache->freecurr > 0) {
        ret = STAILQ_FIRST(&cache->head);
        STAILQ_REMOVE_HEAD(&cache->head, c_next);
        object = get_object(ret);
        cache->freecurr--;
    } else if (cache->limit == 0 || cache->total < cache->limit) {
        object = ret = malloc(cache->bufsize);
        if (ret != NULL) {
            object = get_object(ret);

            cache->total++;
        }
    } else {
        object = NULL;
    }

#ifndef NDEBUG
    if (object != NULL) {
        /* add a simple form of buffer-check */
        uint64_t *pre = ret;
        *pre = redzone_pattern;
        ret = pre+1;
        memcpy(((char*)ret) + cache->bufsize - (2 * sizeof(redzone_pattern)),
               &redzone_pattern, sizeof(redzone_pattern));
    }
#endif

    return object;
}

void cache_free(cache_t *cache, void *ptr) {
    pthread_mutex_lock(&cache->mutex);
    do_cache_free(cache, ptr);
    pthread_mutex_unlock(&cache->mutex);
}

void do_cache_free(cache_t *cache, void *ptr) {
#ifndef NDEBUG
    /* validate redzone... */
    if (memcmp(((char*)ptr) + cache->bufsize - (2 * sizeof(redzone_pattern)),
               &redzone_pattern, sizeof(redzone_pattern)) != 0) {
        raise(SIGABRT);
        cache_error = 1;
        return;
    }
    uint64_t *pre = ptr;
    --pre;
    if (*pre != redzone_pattern) {
        raise(SIGABRT);
        cache_error = -1;
        return;
    }
    ptr = pre;
#endif
    if (cache->limit != 0 && cache->limit < cache->total) {
        free(ptr);
        cache->total--;
    } else {
        STAILQ_INSERT_HEAD(&cache->head, (struct cache_free_s *)ptr, c_next);
        cache->freecurr++;
    }
}


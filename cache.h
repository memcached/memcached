/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef CACHE_H
#define CACHE_H
#include <pthread.h>
#include "queue.h"

#ifndef NDEBUG
/* may be used for debug purposes */
extern int cache_error;
#endif

struct cache_free_s {
    STAILQ_ENTRY(cache_free_s) c_next;
};

/**
 * 结构体，用于跟踪缓存分配器的内部细节。
 * 触摸这些变量中的任何一个都会导致未定义行为。
 */
typedef struct {
    /** 用于保护对结构的访问的互斥锁 */
    pthread_mutex_t mutex;
    /** 缓存对象的名称（由调用者提供） */
    char *name;
    /** 可用缓冲区的自由列表 */
    STAILQ_HEAD(cache_head, cache_free_s) head;
    /** 每个元素在此缓存中的大小 */
    size_t bufsize;
    /** 元素列表的容量 */
    int freetotal;
    /** 分配的对象总数 */
    int total;
    /** 当前空闲元素的数量 */
    int freecurr;
    /** 元素总数的限制 */
    int limit;
} cache_t;


/**
 * Create an object cache.
 *
 * The object cache will let you allocate objects of the same size. It is fully
 * MT safe, so you may allocate objects from multiple threads without having to
 * do any synchronization in the application code.
 *
 * @param name the name of the object cache. This name may be used for debug purposes
 *             and may help you track down what kind of object you have problems with
 *             (buffer overruns, leakage etc)
 * @param bufsize the size of each object in the cache
 * @param align the alignment requirements of the objects in the cache.
 * @param constructor the function to be called to initialize memory when we need
 *                    to allocate more memory from the os.
 * @param destructor the function to be called before we release the memory back
 *                   to the os.
 * @return a handle to an object cache if successful, NULL otherwise.
 */
cache_t* cache_create(const char* name, size_t bufsize, size_t align);

/**
 * Destroy an object cache.
 *
 * Destroy and invalidate an object cache. You should return all buffers allocated
 * with cache_alloc by using cache_free before calling this function. Not doing
 * so results in undefined behavior (the buffers may or may not be invalidated)
 *
 * @param handle the handle to the object cache to destroy.
 */
void cache_destroy(cache_t* handle);
/**
 * Allocate an object from the cache.
 *
 * @param handle the handle to the object cache to allocate from
 * @return a pointer to an initialized object from the cache, or NULL if
 *         the allocation cannot be satisfied.
 */
void* cache_alloc(cache_t* handle);
void* do_cache_alloc(cache_t* handle);
/**
 * Return an object back to the cache.
 *
 * The caller should return the object in an initialized state so that
 * the object may be returned in an expected state from cache_alloc.
 *
 * @param handle handle to the object cache to return the object to
 * @param ptr pointer to the object to return.
 */
void cache_free(cache_t* handle, void* ptr);
void do_cache_free(cache_t* handle, void* ptr);
/**
 * Set or adjust a limit for the number of objects to malloc
 *
 * @param handle handle to the object cache to adjust
 * @param limit the number of objects to cache before returning NULL
 */
void cache_set_limit(cache_t* handle, int limit);

#endif

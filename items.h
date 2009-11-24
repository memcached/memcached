#ifndef ITEMS_H
#define ITEMS_H

/*
 * You should not try to aquire any of the item locks before calling these
 * functions.
 */
typedef struct _hash_item {
    struct _hash_item *next;
    struct _hash_item *prev;
    struct _hash_item *h_next;    /* hash chain next */
    rel_time_t time;       /* least recent access */
    unsigned short refcount;
    uint8_t slabs_clsid;/* which slab class we're in */
    item item;
} hash_item;

/**
 * Allocate and initialize a new item structure
 * @param engine handle to the storage engine
 * @param key the key for the new item
 * @param nkey the number of bytes in the key
 * @param flags the flags in the new item
 * @param exptime when the object should expire
 * @param nbytes the number of bytes in the body for the item
 * @return a pointer to an item on success NULL otherwise
 */
hash_item *item_alloc(struct default_engine *engine,
                      const void *key, size_t nkey, int flags,
                      rel_time_t exptime, int nbytes);

/**
 * Get an item from the cache
 *
 * @param engine handle to the storage engine
 * @param key the key for the item to get
 * @param nkey the number of bytes in the key
 * @return pointer to the item if it exists or NULL otherwise
 */
hash_item *item_get(struct default_engine *engine,
                    const void *key, const size_t nkey);

/**
 * Reset the item statistics
 * @param engine handle to the storage engine
 */
void item_stats_reset(struct default_engine *engine);

/**
 * Get item statitistics
 * @param engine handle to the storage engine
 * @param add_stat callback provided by the core used to
 *                 push statistics into the response
 * @param cookie cookie provided by the core to identify the client
 */
void item_stats(struct default_engine *engine,
                ADD_STAT add_stat,
                const void *cookie);

/**
 * Get detaild item statitistics
 * @param engine handle to the storage engine
 * @param add_stat callback provided by the core used to
 *                 push statistics into the response
 * @param cookie cookie provided by the core to identify the client
 */
void item_stats_sizes(struct default_engine *engine,
                      ADD_STAT add_stat, const void *cookie);

/**
 * Dump items from the cache
 * @param engine handle to the storage engine
 * @param slabs_clsid the slab class to get items from
 * @param limit the maximum number of items to receive
 * @param bytes the number of bytes in the return message (OUT)
 * @return pointer to a string containint the data
 *
 * @todo we need to rewrite this to use callbacks!!!! currently disabled
 */
char *item_cachedump(struct default_engine *engine,
                     const unsigned int slabs_clsid,
                     const unsigned int limit,
                     unsigned int *bytes);

/**
 * Flush expired items from the cache
 * @param engine handle to the storage engine
 */
void  item_flush_expired(struct default_engine *engine);

/**
 * Release our reference to the current item
 * @param engine handle to the storage engine
 * @param it the item to release
 */
void item_release(struct default_engine *engine, hash_item *it);

/**
 * Unlink the item from the hash table (make it inaccessible)
 * @param engine handle to the storage engine
 * @param it the item to unlink
 */
void item_unlink(struct default_engine *engine, hash_item *it);

/**
 * Store an item in the cache
 * @param engine handle to the storage engine
 * @param item the item to store
 * @param cas the cas value (OUT)
 * @param operation what kind of store operation is this (ADD/SET etc)
 * @return ENGINE_SUCCESS on success
 *
 * @todo should we refactor this into hash_item ** and remove the cas
 *       there so that we can get it from the item instead?
 */
ENGINE_ERROR_CODE store_item(struct default_engine *engine,
                             hash_item *item,
                             uint64_t *cas,
                             ENGINE_STORE_OPERATION operation);

/**
 * Add a delta to an item
 * @param engine handle to the storage engine
 * @param item the item to operate on
 * @param incr true if we want to increment, false for decrement
 * @param delta the amount to incr/decr
 * @param cas the new cas value (OUT)
 * @param result the new value for the item (OUT)
 * @return ENGINE_SUCCESS on success
 *
 * @todo perhaps we should do the same refactor as suggested for
 *       store_item
 */
ENGINE_ERROR_CODE add_delta(struct default_engine *engine,
                            hash_item *item, const bool incr,
                            const int64_t delta, uint64_t *cas,
                            uint64_t *result);
#endif

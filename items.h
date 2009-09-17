#ifndef ITEMS_H
#define ITEMS_H

typedef struct _hash_item {
    struct _hash_item *next;
    struct _hash_item *prev;
    struct _hash_item *h_next;    /* hash chain next */
    rel_time_t time;       /* least recent access */
    unsigned short refcount;
    uint8_t slabs_clsid;/* which slab class we're in */
    item item;
} hash_item;

/* See items.c */
uint64_t get_cas_id(void);

/*@null@*/
hash_item *do_item_alloc(const void *key, const size_t nkey,
                         const int flags, const rel_time_t exptime,
                         const int nbytes);
void item_free(hash_item *it);
bool item_size_ok(const size_t nkey, const int flags, const int nbytes);

int  do_item_link(hash_item *it);     /** may fail if transgresses limits */
void do_item_unlink(hash_item *it);
void do_item_remove(hash_item *it);
void do_item_update(hash_item *it);   /** update LRU time to current and reposition */
int  do_item_replace(hash_item *it, hash_item *new_it);

/*@null@*/
char *do_item_cachedump(const unsigned int slabs_clsid,
                        const unsigned int limit, unsigned int *bytes);
void do_item_stats(ADD_STAT add_stats, void *c);
/*@null@*/
void do_item_stats_sizes(ADD_STAT add_stats, void *c);
void do_item_flush_expired(void);

hash_item *do_item_get(const char *key, const size_t nkey);
hash_item *do_item_get_nocheck(const char *key, const size_t nkey);
void item_stats_reset(void);

hash_item *item_alloc(const void *key, size_t nkey, int flags,
                      rel_time_t exptime, int nbytes);
char *item_cachedump(const unsigned int slabs_clsid, const unsigned int limit, unsigned int *bytes);
void  item_flush_expired(void);
hash_item *item_get(const void *key, const size_t nkey);
int   item_link(hash_item *it);
void  item_remove(hash_item *it);
int   item_replace(hash_item *it, hash_item *new_it);
void  hash_item_stats(ADD_STAT add_stats, void *c);
void  item_stats(ADD_STAT add_stats, void *c);
void  item_stats_sizes(ADD_STAT add_stats, void *c);
void  item_unlink(hash_item *it);
void  item_update(hash_item *it);

ENGINE_ERROR_CODE store_item(hash_item *item, uint64_t *cas, ENGINE_STORE_OPERATION operation);
#include "memcached.h"
ENGINE_ERROR_CODE add_delta(conn *c, hash_item *item, const bool incr,
                            const int64_t delta, uint64_t *cas,
                            uint64_t *result);


#endif

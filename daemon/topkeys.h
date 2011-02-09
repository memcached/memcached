#ifndef TOPKEYS_H
#define TOPKEYS_H 1

#include <memcached/engine.h>
#include <memcached/genhash.h>

/* A list of operations for which we have int stats */
#define TK_OPS(C) C(get_hits) C(get_misses) C(cmd_set) C(incr_hits) \
                   C(incr_misses) C(decr_hits) C(decr_misses) \
                   C(delete_hits) C(delete_misses) C(evictions) \
                   C(cas_hits) C(cas_badval) C(cas_misses)

#define TK_MAX_VAL_LEN 250

/* Update the correct stat for a given operation */
#define TK(tk, op, key, nkey, ctime) { \
    if (tk) { \
        assert(key); \
        assert(nkey > 0); \
        pthread_mutex_lock(&tk->mutex); \
        topkey_item_t *tmp = topkeys_item_get_or_create( \
            (tk), (key), (nkey), (ctime)); \
        tmp->op++; \
        pthread_mutex_unlock(&tk->mutex); \
    } \
}

typedef struct dlist {
    struct dlist *next;
    struct dlist *prev;
} dlist_t;

typedef struct topkey_item {
    dlist_t list; /* Must be at the beginning because we downcast! */
    int nkey;
    rel_time_t ctime, atime; /* Time this item was created/last accessed */
#define TK_CUR(name) int name;
    TK_OPS(TK_CUR)
#undef TK_CUR
    char key[]; /* A variable length array in the struct itself */
} topkey_item_t;

typedef struct topkeys {
    dlist_t list;
    pthread_mutex_t mutex;
    genhash_t *hash;
    int nkeys;
    int max_keys;
} topkeys_t;

topkeys_t *topkeys_init(int max_keys);
void topkeys_free(topkeys_t *topkeys);
topkey_item_t *topkeys_item_get_or_create(topkeys_t *tk, const void *key, size_t nkey, const rel_time_t ctime);
ENGINE_ERROR_CODE topkeys_stats(topkeys_t *tk, const void *cookie, const rel_time_t current_time, ADD_STAT add_stat);

#endif

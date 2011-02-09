#include <sys/types.h>
#include <stdlib.h>
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <memcached/genhash.h>
#include "topkeys.h"

static topkey_item_t *topkey_item_init(const void *key, int nkey, rel_time_t ctime) {
    topkey_item_t *item = calloc(sizeof(topkey_item_t) + nkey, 1);
    assert(item);
    assert(key);
    assert(nkey > 0);
    item->nkey = nkey;
    item->ctime = ctime;
    item->atime = ctime;
    /* Copy the key into the part trailing the struct */
    memcpy(item->key, key, nkey);
    return item;
}

static inline size_t topkey_item_size(const topkey_item_t *item) {
    return sizeof(topkey_item_t) + item->nkey;
}

static inline topkey_item_t* topkeys_tail(topkeys_t *tk) {
    return (topkey_item_t*)(tk->list.prev);
}

static int my_hash_eq(const void *k1, size_t nkey1,
                      const void *k2, size_t nkey2) {
    return nkey1 == nkey2 && memcmp(k1, k2, nkey1) == 0;
}

topkeys_t *topkeys_init(int max_keys) {
    topkeys_t *tk = calloc(sizeof(topkeys_t), 1);
    if (tk == NULL) {
        return NULL;
    }

    pthread_mutex_init(&tk->mutex, NULL);
    tk->max_keys = max_keys;
    tk->list.next = &tk->list;
    tk->list.prev = &tk->list;

    static struct hash_ops my_hash_ops = {
        .hashfunc = genhash_string_hash,
        .hasheq = my_hash_eq,
        .dupKey = NULL,
        .dupValue = NULL,
        .freeKey = NULL,
        .freeValue = NULL,
    };

    tk->hash = genhash_init(max_keys, my_hash_ops);
    if (tk->hash == NULL) {
        return NULL;
    }
    return tk;
}

void topkeys_free(topkeys_t *tk) {
    pthread_mutex_destroy(&tk->mutex);
    genhash_free(tk->hash);
    dlist_t *p = tk->list.next;
    while (p != &tk->list) {
        dlist_t *tmp = p->next;
        free(p);
        p = tmp;
    }
}

static inline void dlist_remove(dlist_t *list) {
    assert(list->prev->next == list);
    assert(list->next->prev == list);
    list->prev->next = list->next;
    list->next->prev = list->prev;
}

static inline void dlist_insert_after(dlist_t *list, dlist_t *new) {
    new->next = list->next;
    new->prev = list;
    list->next->prev = new;
    list->next = new;
}

static inline void dlist_iter(dlist_t *list,
                              void (*iterfunc)(dlist_t *item, void *arg),
                              void *arg)
{
    dlist_t *p = list;
    while ((p = p->next) != list) {
        iterfunc(p, arg);
    }
}

static inline void topkeys_item_delete(topkeys_t *tk, topkey_item_t *item) {
    genhash_delete(tk->hash, item->key, item->nkey);
    dlist_remove(&item->list);
    --tk->nkeys;
    free(item);
}

topkey_item_t *topkeys_item_get_or_create(topkeys_t *tk, const void *key, size_t nkey, const rel_time_t ctime) {
    topkey_item_t *item = genhash_find(tk->hash, key, nkey);
    if (item == NULL) {
        item = topkey_item_init(key, nkey, ctime);
        if (item != NULL) {
            if (++tk->nkeys > tk->max_keys) {
                topkeys_item_delete(tk, topkeys_tail(tk));
            }
            genhash_update(tk->hash, item->key, item->nkey,
                           item, topkey_item_size(item));
        } else {
            return NULL;
        }
    } else {
        dlist_remove(&item->list);
    }
    dlist_insert_after(&tk->list, &item->list);
    return item;
}

static inline void append_stat(const void *cookie,
                               const char *name,
                               size_t namelen,
                               const char *key,
                               size_t nkey,
                               int value,
                               ADD_STAT add_stats) {
    char key_str[128];
    char val_str[128];
    int klen, vlen;

    klen = sizeof(key_str) - namelen - 2;
    if (nkey < klen) {
        klen = nkey;
    }
    memcpy(key_str, key, klen);
    key_str[klen] = '.';
    memcpy(&key_str[klen+1], name, namelen + 1);
    klen += namelen + 1;
    vlen = snprintf(val_str, sizeof(val_str) - 1, "%d", value);
    add_stats(key_str, klen, val_str, vlen, cookie);
}

struct tk_context {
    const void *cookie;
    ADD_STAT add_stat;
    rel_time_t current_time;
};

#define TK_FMT(name) #name "=%d,"
#define TK_ARGS(name) item->name,

static void tk_iterfunc(dlist_t *list, void *arg) {
    struct tk_context *c = arg;
    topkey_item_t *item = (topkey_item_t*)list;
    char val_str[TK_MAX_VAL_LEN];
    /* This line is magical. The missing comma before item->ctime is because the TK_ARGS macro ends with a comma. */
    int vlen = snprintf(val_str, sizeof(val_str) - 1, TK_OPS(TK_FMT)"ctime=%"PRIu32",atime=%"PRIu32, TK_OPS(TK_ARGS)
                        c->current_time - item->ctime, c->current_time - item->atime);
    c->add_stat(item->key, item->nkey, val_str, vlen, c->cookie);
}

ENGINE_ERROR_CODE topkeys_stats(topkeys_t *tk,
                                const void *cookie,
                                const rel_time_t current_time,
                                ADD_STAT add_stat) {
    struct tk_context context;
    context.cookie = cookie;
    context.add_stat = add_stat;
    context.current_time = current_time;
    assert(tk);
    pthread_mutex_lock(&tk->mutex);
    dlist_iter(&tk->list, tk_iterfunc, &context);
    pthread_mutex_unlock(&tk->mutex);
    return ENGINE_SUCCESS;
}

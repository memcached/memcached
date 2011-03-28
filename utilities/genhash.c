#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <assert.h>

#include <memcached/genhash.h>
#include "genhash_int.h"

/* Table of 32 primes by their distance from the nearest power of two */
static int prime_size_table[]={
    3, 7, 13, 23, 47, 97, 193, 383, 769, 1531, 3067, 6143, 12289, 24571, 49157,
    98299, 196613, 393209, 786433, 1572869, 3145721, 6291449, 12582917,
    25165813, 50331653, 100663291, 201326611, 402653189, 805306357,
    1610612741
};

static inline void*
dup_key(genhash_t *h, const void *key, size_t klen)
{
    if (h->ops.dupKey != NULL) {
        return h->ops.dupKey(key, klen);
    } else {
        return (void*)key;
    }
}

static inline void*
dup_value(genhash_t *h, const void *value, size_t vlen)
{
    if (h->ops.dupValue != NULL) {
        return h->ops.dupValue(value, vlen);
    } else {
        return (void*)value;
    }
}

static inline void
free_key(genhash_t *h, void *key)
{
    if (h->ops.freeKey != NULL) {
        h->ops.freeKey(key);
    }
}

static inline void
free_value(genhash_t *h, void *value)
{
    if (h->ops.freeValue != NULL) {
        h->ops.freeValue(value);
    }
}

static int
estimate_table_size(int est)
{
    int rv=0;
    int magn=0;
    assert(est > 0);
    magn=(int)log((double)est)/log(2);
    magn--;
    magn = (magn < 0) ? 0 : magn;
    assert(magn < (sizeof(prime_size_table) / sizeof(int)));
    rv=prime_size_table[magn];
    return rv;
}

genhash_t* genhash_init(int est, struct hash_ops ops)
{
    genhash_t* rv=NULL;
    int size=0;
    if (est < 1) {
        return NULL;
    }

    assert(ops.hashfunc != NULL);
    assert(ops.hasheq != NULL);
    assert((ops.dupKey != NULL && ops.freeKey != NULL) || ops.freeKey == NULL);
    assert((ops.dupValue != NULL && ops.freeValue != NULL) || ops.freeValue == NULL);

    size=estimate_table_size(est);
    rv=calloc(1, sizeof(genhash_t)
              + (size * sizeof(struct genhash_entry_t *)));
    assert(rv != NULL);
    rv->size=size;
    rv->ops=ops;

    return rv;
}

void
genhash_free(genhash_t* h)
{
    if(h != NULL) {
        genhash_clear(h);
        free(h);
    }
}

void
genhash_store(genhash_t *h, const void* k, size_t klen,
              const void* v, size_t vlen)
{
    int n=0;
    struct genhash_entry_t *p;

    assert(h != NULL);

    n=h->ops.hashfunc(k, klen) % h->size;
    assert(n >= 0);
    assert(n < h->size);

    p=calloc(1, sizeof(struct genhash_entry_t));
    assert(p);

    p->key=dup_key(h, k, klen);
    p->nkey = klen;
    p->value=dup_value(h, v, vlen);
    p->nvalue = vlen;

    p->next=h->buckets[n];
    h->buckets[n]=p;
}

static struct genhash_entry_t *
genhash_find_entry(genhash_t *h, const void* k, size_t klen)
{
    int n=0;
    struct genhash_entry_t *p;

    assert(h != NULL);
    n=h->ops.hashfunc(k, klen) % h->size;
    assert(n >= 0);
    assert(n < h->size);

    p=h->buckets[n];
    for(p=h->buckets[n]; p && !h->ops.hasheq(k, klen, p->key, p->nkey); p=p->next);
    return p;
}

void*
genhash_find(genhash_t *h, const void* k, size_t klen)
{
    struct genhash_entry_t *p;
    void *rv=NULL;

    p=genhash_find_entry(h, k, klen);

    if(p) {
        rv=p->value;
    }
    return rv;
}

enum update_type
genhash_update(genhash_t* h, const void* k, size_t klen,
               const void* v, size_t vlen)
{
    struct genhash_entry_t *p;
    enum update_type rv=0;

    p=genhash_find_entry(h, k, klen);

    if(p) {
        free_value(h, p->value);
        p->value=dup_value(h, v, vlen);
        rv=MODIFICATION;
    } else {
        genhash_store(h, k, klen, v, vlen);
        rv=NEW;
    }

    return rv;
}

enum update_type
genhash_fun_update(genhash_t* h, const void* k, size_t klen,
                   void *(*upd)(const void *, const void *, size_t *, void *),
                   void (*fr)(void*),
                   void *arg,
                   const void *def, size_t deflen)
{
    struct genhash_entry_t *p;
    enum update_type rv=0;
    size_t newSize = 0;

    p=genhash_find_entry(h, k, klen);

    if(p) {
        void *newValue=upd(k, p->value, &newSize, arg);
        free_value(h, p->value);
        p->value=dup_value(h, newValue, newSize);
        fr(newValue);
        rv=MODIFICATION;
    } else {
        void *newValue=upd(k, def, &newSize, arg);
        genhash_store(h, k, klen, newValue, newSize);
        fr(newValue);
        rv=NEW;
    }

    return rv;
}

static void
free_item(genhash_t *h, struct genhash_entry_t *i)
{
    assert(i);
    free_key(h, i->key);
    free_value(h, i->value);
    free(i);
}

int
genhash_delete(genhash_t* h, const void* k, size_t klen)
{
    struct genhash_entry_t *deleteme=NULL;
    int n=0;
    int rv=0;

    assert(h != NULL);
    n=h->ops.hashfunc(k, klen) % h->size;
    assert(n >= 0);
    assert(n < h->size);

    if(h->buckets[n] != NULL) {
        /* Special case the first one */
        if(h->ops.hasheq(h->buckets[n]->key, h->buckets[n]->nkey, k, klen)) {
            deleteme=h->buckets[n];
            h->buckets[n]=deleteme->next;
        } else {
            struct genhash_entry_t *p=NULL;
            for(p=h->buckets[n]; deleteme==NULL && p->next != NULL; p=p->next) {
                if(h->ops.hasheq(p->next->key, p->next->nkey, k, klen)) {
                    deleteme=p->next;
                    p->next=deleteme->next;
                }
            }
        }
    }
    if(deleteme != NULL) {
        free_item(h, deleteme);
        rv++;
    }

    return rv;
}

int
genhash_delete_all(genhash_t* h, const void* k, size_t klen)
{
    int rv=0;
    while(genhash_delete(h, k, klen) == 1) {
        rv++;
    }
    return rv;
}

void
genhash_iter(genhash_t* h,
             void (*iterfunc)(const void* key, size_t nkey,
                              const void* val, size_t nval,
                              void *arg), void *arg)
{
    int i=0;
    struct genhash_entry_t *p=NULL;
    assert(h != NULL);

    for(i=0; i<h->size; i++) {
        for(p=h->buckets[i]; p!=NULL; p=p->next) {
            iterfunc(p->key, p->nkey, p->value, p->nvalue, arg);
        }
    }
}

int
genhash_clear(genhash_t *h)
{
    int i = 0, rv = 0;
    assert(h != NULL);

    for(i = 0; i < h->size; i++) {
        while(h->buckets[i]) {
            struct genhash_entry_t *p = NULL;
            p = h->buckets[i];
            h->buckets[i] = p->next;
            free_item(h, p);
        }
    }

    return rv;
}

static void
count_entries(const void *key, size_t klen,
              const void *val, size_t vlen, void *arg)
{
    int *count=(int *)arg;
    (*count)++;
}

int
genhash_size(genhash_t* h) {
    int rv=0;
    assert(h != NULL);
    genhash_iter(h, count_entries, &rv);
    return rv;
}

int
genhash_size_for_key(genhash_t* h, const void* k, size_t klen)
{
    int rv=0;
    assert(h != NULL);
    genhash_iter_key(h, k, klen, count_entries, &rv);
    return rv;
}

void
genhash_iter_key(genhash_t* h, const void* key, size_t klen,
                 void (*iterfunc)(const void* key, size_t klen,
                                  const void* val, size_t vlen,
                                  void *arg), void *arg)
{
    int n=0;
    struct genhash_entry_t *p=NULL;

    assert(h != NULL);
    n=h->ops.hashfunc(key, klen) % h->size;
    assert(n >= 0);
    assert(n < h->size);

    for(p=h->buckets[n]; p!=NULL; p=p->next) {
        if(h->ops.hasheq(key, klen, p->key, p->nkey)) {
            iterfunc(p->key, p->nkey, p->value, p->nvalue, arg);
        }
    }
}

int
genhash_string_hash(const void* p, size_t nkey)
{
    int rv=5381;
    int i=0;
    char *str=(char *)p;

    for(i=0; i < nkey; i++) {
        rv = ((rv << 5) + rv) ^ str[i];
    }

    return rv;
}

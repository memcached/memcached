/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "basic_engine_testsuite.h"

struct test_harness test_harness;

/*
 * Make sure that get_info returns something and that repeated calls to it
 * return the same something.
 */
static enum test_result get_info_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    const engine_info *info = h1->get_info(h);
    assert(info != NULL);
    assert(info == h1->get_info(h));
    return SUCCESS;
}

/*
 * Make sure that the structure returned by get_info has a non-null description.
 */
static enum test_result get_info_description_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    const engine_info *info = h1->get_info(h);
    assert(info->description != NULL);
    return SUCCESS;
}

/*
 * Make sure that the structure returned by get_info has a valid number of
 * features and that the size of the feautes array equals that value
 */
static enum test_result get_info_features_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    const engine_info *info = h1->get_info(h);
    uint32_t nfeats = info->num_features;
    assert (nfeats > 0);
    const feature_info *fi = info->features;
    while (nfeats-- > 0) {
        assert(fi++ != NULL);
    }

    return SUCCESS;
}

/*
 * Make sure we can successfully allocate an item, allocate op returns success
 * and that item struct is populated
 */
static enum test_result allocate_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    void *key = "akey";
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1,1,1) == ENGINE_SUCCESS);
    assert(test_item != NULL);
    h1->release(h,NULL,test_item);
    return SUCCESS;
}

/*
 * Make sure when we can successfully store an item after it has been allocated
 * and that the cas for the stored item has been generated.
 */
static enum test_result store_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    void *key = "bkey";
    uint64_t cas = 0;
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1,1,1) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    assert(cas != 0);
    h1->release(h,NULL,test_item);
    return SUCCESS;
}

/*
 * Make sure when we can successfully retrieve an item that has been stored in
 * the engine
 */
static enum test_result get_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    item *test_item_get = NULL;
    void *key = "get_test_key";
    uint64_t cas = 0;
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1,0, 0) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    assert(h1->get(h,NULL,&test_item_get,key,strlen(key),0) == ENGINE_SUCCESS);
    h1->release(h,NULL,test_item);
    h1->release(h,NULL,test_item_get);
    return SUCCESS;
}

/*
 * Make sure that we can release an item. For the most part all this test does
 * is ensure that thinds dont go splat when we call release. It does nothing to
 * ensure that release did much of anything.
 */
static enum test_result release_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    void *key = "release_test_key";
    uint64_t cas = 0;
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1, 0, 0) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    h1->release(h, NULL, test_item);
    return SUCCESS;
}

/*
 * Make sure that we can remove an item and that after the item has been
 * removed it can not be retrieved.
 */
static enum test_result remove_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    void *key = "remove_test_key";
    uint64_t cas = 0;
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1,0, 0) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    assert(h1->remove(h, NULL, key, strlen(key), cas, 0) == ENGINE_SUCCESS);
    item *check_item = test_item;
    assert(h1->get(h, NULL, &check_item, key, strlen(key), 0) ==  ENGINE_KEY_ENOENT);
    assert(check_item == NULL);
    h1->release(h, NULL, test_item);
    return SUCCESS;
}

/*
 * Make sure we can arithmetic operations to set the initial value of a key and
 * to then later increment that value
 */
static enum test_result incr_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    void *key = "incr_test_key";
    uint64_t cas = 0;
    uint64_t res = 0;
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1, 0, 0) == ENGINE_SUCCESS);
    assert(h1->arithmetic(h, NULL, key, strlen(key), true, true, 0, 1,
           0, &cas, &res, 0 ) == ENGINE_SUCCESS);
    assert(res == 1);
    assert(h1->arithmetic(h, NULL, key, strlen(key), true, false, 1, 0,
           0, &cas, &res, 0 ) == ENGINE_SUCCESS);
    assert(res == 2);
    h1->release(h, NULL, test_item);
    return SUCCESS;
}

static void *incr_test_main(void *arg) {
    ENGINE_HANDLE *h = arg;
    ENGINE_HANDLE_V1 *h1 = arg;
    void *key = "incr_test_key";
    uint64_t cas = 0;
    uint64_t res = 0;

    for (int ii = 0; ii < 1000; ++ii) {
        assert(h1->arithmetic(h, NULL, key, strlen(key), false, false, 1, 0,
                              0, &cas, &res, 0 ) == ENGINE_SUCCESS);

    }

    return NULL;
}


/*
 * Make sure we can arithmetic operations to set the initial value of a key and
 * to then later increment that value
 */
static enum test_result mt_incr_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
#ifdef __arm__
    const int max_threads = 1;
#else
    const int max_threads = 30;
#endif
    pthread_t tid[max_threads];

    if (max_threads < 2) {
        return SKIPPED;
    }

    item *test_item = NULL;
    void *key = "incr_test_key";
    uint64_t cas = 0;
    uint64_t res = 0;
    assert(h1->allocate(h, NULL, &test_item, key,
                        strlen(key), 1, 0, 0) == ENGINE_SUCCESS);
    assert(h1->arithmetic(h, NULL, key, strlen(key), true, true, 0, 1,
                          0, &cas, &res, 0 ) == ENGINE_SUCCESS);
    h1->release(h, NULL, test_item);

    for (int ii = 0; ii < max_threads; ++ii) {
        assert(pthread_create(&tid[ii], NULL, incr_test_main, h) == 0);
    }

    for (int ii = 0; ii < max_threads; ++ii) {
        void *ret;
        assert(pthread_join(tid[ii], &ret) == 0);
        assert(ret == NULL);
    }

    return SUCCESS;
}

/*
 * Make sure we can arithmetic operations to set the initial value of a key and
 * to then later decrement that value
 */
static enum test_result decr_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    void *key = "decr_test_key";
    uint64_t cas = 0;
    uint64_t res = 0;
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1,0, 0) == ENGINE_SUCCESS);
    assert(h1->arithmetic(h, NULL, key, strlen(key), false, true, 0, 1,
           0, &cas, &res, 0 ) == ENGINE_SUCCESS);
    assert(res == 1);
    assert(h1->arithmetic(h, NULL, key, strlen(key), false, false, 1, 0,
           0, &cas, &res, 0 ) == ENGINE_SUCCESS);
    assert(res == 0);
    h1->release(h, NULL, test_item);
    return SUCCESS;
}

/*
 * Make sure we can successfully perform a flush operation and that any item
 * stored before the flush can not be retrieved
 */
static enum test_result flush_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    void *key = "flush_test_key";
    uint64_t cas = 0;
    test_harness.time_travel(3);
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1, 0, 0) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    assert(h1->flush(h, NULL, 0) == ENGINE_SUCCESS);
    item *check_item = test_item;
    assert(h1->get(h, NULL, &check_item, key, strlen(key), 0) ==  ENGINE_KEY_ENOENT);
    assert(check_item == NULL);
    h1->release(h, NULL, test_item);
    return SUCCESS;
}

/*
 * Make sure we can successfully retrieve the item info struct for an item and
 * that the contents of the item_info are as expected.
 */
static enum test_result get_item_info_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    char *key = "get_item_info_test_key";
    uint64_t cas = 0;
    const rel_time_t exp = 1;
    item_info ii = { .nvalue = 1 };
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1,0, exp) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    /* Had this been actual code, there'd be a connection here */
    assert(h1->get_item_info(h, NULL, test_item, &ii) == true);
    assert(ii.cas == cas);
    assert(ii.flags == 0);
    assert(strcmp(key,ii.key) == 0);
    assert(ii.nkey == strlen(key));
    assert(ii.nbytes == 1);
    assert(ii.exptime == exp);
    h1->release(h, NULL, test_item);
    return SUCCESS;
}

static enum test_result item_set_cas_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    char *key = "item_set_cas_test_key";
    uint64_t cas = 0;
    const rel_time_t exp = 1;
    item_info ii = { .nvalue = 1 };
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1,0, exp) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    uint64_t newcas = cas + 1;
    h1->item_set_cas(h, NULL, test_item, newcas);
    assert(h1->get_item_info(h, NULL, test_item, &ii) == true);
    assert(ii.cas == newcas);
    h1->release(h, NULL, test_item);
    return SUCCESS;
}

static void eviction_stats_handler(const char *key, const uint16_t klen,
                                   const char *val, const uint32_t vlen,
                                   const void *cookie) {
    if (memcmp(key, "evictions", klen) == 0) {
        char buffer[vlen + 1];
        memcpy(buffer, val, vlen);
        buffer[vlen] = '\0';
        *((uint32_t*)cookie) = atoi(buffer);
    }
}

static enum test_result lru_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    const char *hot_key = "hot_key";
    uint64_t cas = 0;
    assert(h1->allocate(h, NULL, &test_item,
                        hot_key, strlen(hot_key), 4096, 0, 0) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item,
                     &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
    h1->release(h, NULL, test_item);

    int ii;
    for (ii = 0; ii < 250; ++ii) {
        assert(h1->get(h, NULL, &test_item,
                       hot_key, strlen(hot_key), 0) ==  ENGINE_SUCCESS);
        h1->release(h, NULL, test_item);
        char key[1024];
        size_t keylen = snprintf(key, sizeof(key), "lru_test_key_%08d", ii);
        assert(h1->allocate(h, NULL, &test_item,
                            key, keylen, 4096, 0, 0) == ENGINE_SUCCESS);
        assert(h1->store(h, NULL, test_item,
                         &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
        h1->release(h, NULL, test_item);

        uint32_t evictions = 0;
        assert(h1->get_stats(h, &evictions, NULL, 0,
                             eviction_stats_handler) == ENGINE_SUCCESS);
        if (evictions == 2) {
            break;
        }
    }

    assert(ii < 250);
    for (int jj = 0; jj <= ii; ++jj) {
        char key[1024];
        size_t keylen = snprintf(key, sizeof(key), "lru_test_key_%08d", jj);
        if (jj == 0 || jj == 1) {
            assert(h1->get(h, NULL, &test_item,
                           key, keylen, 0) == ENGINE_KEY_ENOENT);
        } else {
            assert(h1->get(h, NULL, &test_item,
                           key, keylen, 0) == ENGINE_SUCCESS);
            assert(test_item != NULL);
            h1->release(h, NULL, test_item);
        }
    }

    return SUCCESS;
}

static enum test_result get_stats_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    return PENDING;
}

static enum test_result reset_stats_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    return PENDING;
}

static enum test_result get_stats_struct_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    return PENDING;
}

static enum test_result aggregate_stats_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    return PENDING;
}

static enum test_result unknown_command_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    return PENDING;
}

MEMCACHED_PUBLIC_API
engine_test_t* get_tests(void) {
    static engine_test_t tests[]  = {
        {"get info test", get_info_test, NULL, NULL, NULL},
        {"get info description test", get_info_description_test, NULL, NULL, NULL},
        {"get info features test", get_info_features_test, NULL, NULL, NULL},
        {"allocate test", allocate_test, NULL, NULL, NULL},
        {"store test", store_test, NULL, NULL, NULL},
        {"get test", get_test, NULL, NULL, NULL},
        {"remove test", remove_test, NULL, NULL, NULL},
        {"release test", release_test, NULL, NULL, NULL},
        {"incr test", incr_test, NULL, NULL, NULL},
        {"mt incr test", mt_incr_test, NULL, NULL, NULL},
        {"decr test", decr_test, NULL, NULL, NULL},
        {"flush test", flush_test, NULL, NULL, NULL},
        {"get item info test", get_item_info_test, NULL, NULL, NULL},
        {"set cas test", item_set_cas_test, NULL, NULL, NULL},
        {"LRU test", lru_test, NULL, NULL, "cache_size=48"},
        {"get stats test", get_stats_test, NULL, NULL, NULL},
        {"reset stats test", reset_stats_test, NULL, NULL, NULL},
        {"get stats struct test", get_stats_struct_test, NULL, NULL, NULL},
        {"aggregate stats test", aggregate_stats_test, NULL, NULL, NULL},
        {"unknown command test", unknown_command_test, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL, NULL}
    };
    return tests;
}

MEMCACHED_PUBLIC_API
bool setup_suite(struct test_harness *th) {
    test_harness = *th;
    return true;
}

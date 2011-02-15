/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#undef NDEBUG
#include "config.h"
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
 * Verify set behavior
 */
static enum test_result set_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *it;
    void *key = "key";
    assert(h1->allocate(h, NULL, &it, key,
                        strlen(key), 1, 1, 0) == ENGINE_SUCCESS);

    uint64_t prev_cas;
    uint64_t cas = 0;

    for (int ii = 0; ii < 10; ++ii) {
        prev_cas = cas;
        assert(h1->store(h, NULL, it, &cas, OPERATION_SET,0) == ENGINE_SUCCESS);
        assert(cas != prev_cas);
    }
    h1->release(h, NULL, it);
    return SUCCESS;
}

/*
 * Verify add behavior
 */
static enum test_result add_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *it;
    void *key = "key";
    assert(h1->allocate(h, NULL, &it, key,
                        strlen(key), 1, 1, 0) == ENGINE_SUCCESS);
    uint64_t cas;

    for (int ii = 0; ii < 10; ++ii) {
        ENGINE_ERROR_CODE ret = h1->store(h, NULL, it, &cas, OPERATION_ADD, 0);
        if (ii == 0) {
            assert(ret == ENGINE_SUCCESS);
            assert(cas != 0);
        } else {
            assert(ret == ENGINE_NOT_STORED);
        }
    }
    h1->release(h, NULL, it);
    return SUCCESS;
}

/*
 * Verify replace behavior
 */
static enum test_result replace_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *it;
    void *key = "key";
    assert(set_test(h, h1) == SUCCESS);

    assert(h1->allocate(h, NULL, &it, key,
                        strlen(key), sizeof(int), 1, 0) == ENGINE_SUCCESS);
    item_info item_info = { .nvalue = 1 };
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);

    uint64_t prev_cas;
    uint64_t cas = 0;

    for (int ii = 0; ii < 10; ++ii) {
        prev_cas = cas;
        *(int*)(item_info.value[0].iov_base) = ii;
        assert(h1->store(h, NULL, it, &cas, OPERATION_REPLACE,0) == ENGINE_SUCCESS);
        assert(cas != prev_cas);
    }
    h1->release(h, NULL, it);

    assert(h1->get(h, NULL, &it, key, strlen(key), 0) == ENGINE_SUCCESS);
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);
    assert(item_info.value[0].iov_len == sizeof(int));
    assert(*(int*)(item_info.value[0].iov_base) == 9);
    h1->release(h, NULL, it);

    return SUCCESS;
}

/*
 * Verify append behavior
 */
static enum test_result append_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *it;
    void *key = "key";
    uint64_t cas;

    assert(h1->allocate(h, NULL, &it, key,
                        strlen(key), 5, 1, 0) == ENGINE_SUCCESS);
    item_info item_info = { .nvalue = 1 };
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);
    memcpy(item_info.value[0].iov_base, "HELLO", 5);
    assert(h1->store(h, NULL, it, &cas, OPERATION_SET, 0) == ENGINE_SUCCESS);
    h1->release(h, NULL, it);
    assert(h1->allocate(h, NULL, &it, key,
                        strlen(key), 6, 1, 0) == ENGINE_SUCCESS);
    item_info.nvalue = 1;
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);
    memcpy(item_info.value[0].iov_base, " WORLD", 6);
    assert(h1->store(h, NULL, it, &cas, OPERATION_APPEND, 0) == ENGINE_SUCCESS);
    h1->release(h, NULL, it);

    assert(h1->get(h, NULL, &it, key, strlen(key), 0) == ENGINE_SUCCESS);
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);
    assert(item_info.value[0].iov_len == 11);
    assert(memcmp(item_info.value[0].iov_base, "HELLO WORLD", 11) == 0);
    h1->release(h, NULL, it);

    return SUCCESS;
}

/*
 * Verify prepend behavior
 */
static enum test_result prepend_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *it;
    void *key = "key";
    uint64_t cas;

    assert(h1->allocate(h, NULL, &it, key,
                        strlen(key), 5, 1, 0) == ENGINE_SUCCESS);
    item_info item_info = { .nvalue = 1 };
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);
    memcpy(item_info.value[0].iov_base, "HELLO", 5);
    assert(h1->store(h, NULL, it, &cas, OPERATION_SET, 0) == ENGINE_SUCCESS);
    h1->release(h, NULL, it);
    assert(h1->allocate(h, NULL, &it, key,
                        strlen(key), 6, 1, 0) == ENGINE_SUCCESS);
    item_info.nvalue = 1;
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);
    memcpy(item_info.value[0].iov_base, " WORLD", 6);
    assert(h1->store(h, NULL, it, &cas, OPERATION_PREPEND, 0) == ENGINE_SUCCESS);
    h1->release(h, NULL, it);

    assert(h1->get(h, NULL, &it, key, strlen(key), 0) == ENGINE_SUCCESS);
    assert(h1->get_item_info(h, NULL, it, &item_info) == true);
    assert(item_info.value[0].iov_len == 11);
    assert(memcmp(item_info.value[0].iov_base, " WORLDHELLO", 11) == 0);
    h1->release(h, NULL, it);

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

static enum test_result expiry_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    item *test_item = NULL;
    item *test_item_get = NULL;
    void *key = "get_test_key";
    uint64_t cas = 0;
    assert(h1->allocate(h, NULL, &test_item, key, strlen(key), 1, 0, 10) == ENGINE_SUCCESS);
    assert(h1->store(h, NULL, test_item, &cas, OPERATION_SET, 0) == ENGINE_SUCCESS);
    test_harness.time_travel(11);
    assert(h1->get(h,NULL,&test_item_get,key,strlen(key),0) == ENGINE_KEY_ENOENT);
    h1->release(h,NULL,test_item);
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

uint32_t evictions;
static void eviction_stats_handler(const char *key, const uint16_t klen,
                                   const char *val, const uint32_t vlen,
                                   const void *cookie) {
    if (memcmp(key, "evictions", klen) == 0) {
        char buffer[vlen + 1];
        memcpy(buffer, val, vlen);
        buffer[vlen] = '\0';
        evictions = atoi(buffer);
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
        assert(h1->get_stats(h, NULL, NULL, 0,
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

static protocol_binary_response_header *last_response;

static void release_last_response(void) {
    free(last_response);
    last_response = NULL;
}

static bool response_handler(const void *key, uint16_t keylen,
                             const void *ext, uint8_t extlen,
                             const void *body, uint32_t bodylen,
                             uint8_t datatype, uint16_t status,
                             uint64_t cas, const void *cookie)
{
    assert(last_response == NULL);
    last_response = malloc(sizeof(*last_response) + keylen + extlen + bodylen);
    if (last_response == NULL) {
        return false;
    }
    protocol_binary_response_header *r = last_response;
    r->response.magic = PROTOCOL_BINARY_RES;
    r->response.opcode = 0xff; // we don't know this!
    r->response.keylen = htons(keylen);
    r->response.extlen = extlen;
    r->response.datatype = PROTOCOL_BINARY_RAW_BYTES;
    r->response.status = htons(status);
    r->response.bodylen = htonl(keylen + extlen + bodylen);
    r->response.opaque = 0xffffff; // we don't know this
    r->response.cas = cas;
    char *ptr = (void*)(r + 1);
    memcpy(ptr, ext, extlen);
    ptr += extlen;
    memcpy(ptr, key, keylen);
    ptr += keylen;
    memcpy(ptr, body, bodylen);

    return true;
}

static enum test_result touch_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    union request {
        protocol_binary_request_touch touch;
        char buffer[512];
    };

    void *key = "get_test_key";
    size_t keylen = strlen(key);
    union request r = {
        .touch = {
            .message = {
                .header.request = {
                    .magic = PROTOCOL_BINARY_REQ,
                    .opcode = PROTOCOL_BINARY_CMD_TOUCH,
                    .keylen = htons((uint16_t)keylen),
                    .extlen = 4,
                    .datatype = PROTOCOL_BINARY_RAW_BYTES,
                    .vbucket = 0,
                    .bodylen = htonl(keylen + 4),
                    .opaque = 0xdeadbeef,
                    .cas = 0
                },
                .body = {
                    .expiration = htonl(10)
                }
            }
        }
    };

    memcpy(r.buffer + sizeof(r.touch.bytes), key, keylen);
    ENGINE_ERROR_CODE ret;
    ret = h1->unknown_command(h, NULL, &r.touch.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    assert(last_response->response.keylen == 0);
    assert(last_response->response.extlen == 0);
    assert(last_response->response.bodylen == 0);
    release_last_response();

    // store and get a key
    assert(get_test(h, h1) == SUCCESS);

    // Set expiry time to 10 secs..
    ret = h1->unknown_command(h, NULL, &r.touch.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_SUCCESS);
    assert(last_response->response.keylen == 0);
    assert(last_response->response.extlen == 0);
    assert(last_response->response.bodylen == 0);
    release_last_response();

    // time-travel 11 secs..
    test_harness.time_travel(11);

    // The item should have expired now...
    item *item = NULL;
    assert(h1->get(h, NULL, &item, key, keylen, 0) == ENGINE_KEY_ENOENT);

    // Verify that it doesn't accept bogus packets. extlen is mandatory
    r.touch.message.header.request.extlen = 0;
    r.touch.message.header.request.bodylen = htonl(keylen);
    ret = h1->unknown_command(h, NULL, &r.touch.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_EINVAL);
    release_last_response();

    // key is mandatory!
    r.touch.message.header.request.extlen = 4;
    r.touch.message.header.request.keylen = 0;
    r.touch.message.header.request.bodylen = htonl(4);
    ret = h1->unknown_command(h, NULL, &r.touch.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_EINVAL);
    release_last_response();

    return SUCCESS;
}

static enum test_result gat_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    union request {
        protocol_binary_request_gat gat;
        char buffer[512];
    };

    void *key = "get_test_key";
    size_t keylen = strlen(key);
    union request r = {
        .gat = {
            .message = {
                .header.request = {
                    .magic = PROTOCOL_BINARY_REQ,
                    .opcode = PROTOCOL_BINARY_CMD_GAT,
                    .keylen = htons((uint16_t)keylen),
                    .extlen = 4,
                    .datatype = PROTOCOL_BINARY_RAW_BYTES,
                    .vbucket = 0,
                    .bodylen = htonl(keylen + 4),
                    .opaque = 0xdeadbeef,
                    .cas = 0
                },
                .body = {
                    .expiration = htonl(10)
                }
            }
        }
    };

    memcpy(r.buffer + sizeof(r.gat.bytes), key, keylen);
    ENGINE_ERROR_CODE ret;
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_KEY_ENOENT);
    assert(last_response->response.keylen == 0);
    assert(last_response->response.extlen == 0);
    assert(last_response->response.bodylen == 0);
    release_last_response();

    // store and get a key
    assert(get_test(h, h1) == SUCCESS);

    // Set expiry time to 10 secs..
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_SUCCESS);
    assert(last_response->response.keylen == 0);
    assert(last_response->response.extlen == 4);
    assert(ntohl(last_response->response.bodylen) == 5); // get_test sets 1 byte datalen
    release_last_response();

    // time-travel 11 secs..
    test_harness.time_travel(11);

    // The item should have expired now...
    item *item = NULL;
    assert(h1->get(h, NULL, &item, key, keylen, 0) == ENGINE_KEY_ENOENT);

    // Verify that it doesn't accept bogus packets. extlen is mandatory
    r.gat.message.header.request.extlen = 0;
    r.gat.message.header.request.bodylen = htonl(keylen);
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_EINVAL);
    release_last_response();

    // key is mandatory!
    r.gat.message.header.request.extlen = 4;
    r.gat.message.header.request.keylen = 0;
    r.gat.message.header.request.bodylen = htonl(4);
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_EINVAL);
    release_last_response();

    return SUCCESS;
}

static enum test_result gatq_test(ENGINE_HANDLE *h, ENGINE_HANDLE_V1 *h1) {
    union request {
        protocol_binary_request_gat gat;
        char buffer[512];
    };

    void *key = "get_test_key";
    size_t keylen = strlen(key);
    union request r = {
        .gat = {
            .message = {
                .header.request = {
                    .magic = PROTOCOL_BINARY_REQ,
                    .opcode = PROTOCOL_BINARY_CMD_GATQ,
                    .keylen = htons((uint16_t)keylen),
                    .extlen = 4,
                    .datatype = PROTOCOL_BINARY_RAW_BYTES,
                    .vbucket = 0,
                    .bodylen = htonl(keylen + 4),
                    .opaque = 0xdeadbeef,
                    .cas = 0
                },
                .body = {
                    .expiration = htonl(10)
                }
            }
        }
    };

    memcpy(r.buffer + sizeof(r.gat.bytes), key, keylen);
    ENGINE_ERROR_CODE ret;
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);

    // GATQ is quiet and should not produce any result
    assert(last_response == NULL);

    // store and get a key
    assert(get_test(h, h1) == SUCCESS);

    // Set expiry time to 10 secs..
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_SUCCESS);
    assert(last_response->response.keylen == 0);
    assert(last_response->response.extlen == 4);
    assert(ntohl(last_response->response.bodylen) == 5); // get_test sets 1 byte datalen
    release_last_response();

    // time-travel 11 secs..
    test_harness.time_travel(11);

    // The item should have expired now...
    item *item = NULL;
    assert(h1->get(h, NULL, &item, key, keylen, 0) == ENGINE_KEY_ENOENT);

    // Verify that it doesn't accept bogus packets. extlen is mandatory
    r.gat.message.header.request.extlen = 0;
    r.gat.message.header.request.bodylen = htonl(keylen);
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_EINVAL);
    release_last_response();

    // key is mandatory!
    r.gat.message.header.request.extlen = 4;
    r.gat.message.header.request.keylen = 0;
    r.gat.message.header.request.bodylen = htonl(4);
    ret = h1->unknown_command(h, NULL, &r.gat.message.header, response_handler);
    assert(ret == ENGINE_SUCCESS);
    assert(last_response != NULL);
    assert(ntohs(last_response->response.status) == PROTOCOL_BINARY_RESPONSE_EINVAL);
    release_last_response();

    return SUCCESS;
}

MEMCACHED_PUBLIC_API
engine_test_t* get_tests(void) {
    static engine_test_t tests[]  = {
        {"get info test", get_info_test, NULL, NULL, NULL},
        {"get info description test", get_info_description_test, NULL, NULL, NULL},
        {"get info features test", get_info_features_test, NULL, NULL, NULL},
        {"allocate test", allocate_test, NULL, NULL, NULL},
        {"set test", set_test, NULL, NULL, NULL},
        {"add test", add_test, NULL, NULL, NULL},
        {"replace test", replace_test, NULL, NULL, NULL},
        {"append test", append_test, NULL, NULL, NULL},
        {"prepend test", prepend_test, NULL, NULL, NULL},
        {"store test", store_test, NULL, NULL, NULL},
        {"get test", get_test, NULL, NULL, NULL},
        {"expiry test", expiry_test, NULL, NULL, NULL},
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
        {"touch", touch_test, NULL, NULL, NULL},
        {"Get And Touch", gat_test, NULL, NULL, NULL},
        {"Get And Touch Quiet", gatq_test, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL, NULL}
    };
    return tests;
}

MEMCACHED_PUBLIC_API
bool setup_suite(struct test_harness *th) {
    test_harness = *th;
    return true;
}


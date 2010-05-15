#include <assert.h>
#include <stdlib.h>
#include <memcached/engine_testapp.h>

MEMCACHED_PUBLIC_API
engine_test_t* get_tests(void);

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

engine_test_t* get_tests(void) {
    static engine_test_t tests[]  = {
        {"get info test", get_info_test, NULL, NULL, NULL},
        {"get info description test", get_info_description_test, NULL, NULL, NULL},
        {"get info features test", get_info_features_test, NULL, NULL, NULL},
        {NULL, NULL, NULL, NULL, NULL}
    };
    return tests;
}


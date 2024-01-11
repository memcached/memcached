//
// Created by rigon on 10.01.24.
//
#include "defs-testcomp.c"
#include "cache.h"
#include "assert.h"
#include <stdio.h>

extern size_t __VERIFIER_nondet_size_t();

enum test_return { TEST_SKIP, TEST_PASS, TEST_FAIL };

static enum test_return cache_bulkalloc(size_t datasize)
{
    size_t align = __VERIFIER_nondet_size_t();
    cache_t *cache = cache_create("test", datasize, sizeof(char*));
    if (cache == NULL) {
        return TEST_FAIL;
    }
#define ITERATIONS 1024
    void *ptr[ITERATIONS];

    for (int ii = 0; ii < ITERATIONS; ++ii) {
        ptr[ii] = cache_alloc(cache);
        assert(ptr[ii] != 0);
        memset(ptr[ii], 0xff, datasize);
    }

    for (int ii = 0; ii < ITERATIONS; ++ii) {
        cache_free(cache, ptr[ii]);
    }

#undef ITERATIONS
    cache_destroy(cache);
    return TEST_PASS;
}

int main() {
    size_t input = __VERIFIER_nondet_size_t();

    printf("size_t: %lu\n", input);

    cache_bulkalloc(input);

    //printf("test return: %i", cache_bulkalloc(input));
    return 1;
}
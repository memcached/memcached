//
// Created by rigon on 10.01.24.
//
#include "defs-testcomp.c"
#include "cache.h"
#include "assert.h"
#include <stdio.h>
#include "cache.c"

extern unsigned int __VERIFIER_nondet_uint();
extern unsigned char __VERIFIER_nondet_uchar();

enum test_return { TEST_SKIP, TEST_PASS, TEST_FAIL };

static enum test_return cache_bulkalloc(size_t datasize, int iterations)
{
    cache_t *cache = cache_create("test", datasize, sizeof(char*));
    if (cache == NULL) {
        return TEST_FAIL;
    }
#define ITERATIONS iterations
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
    unsigned int input = __VERIFIER_nondet_uint();
    unsigned char iterations = __VERIFIER_nondet_uchar();

    printf("int: %u iterations: %i\n", input, (int)iterations);

    cache_bulkalloc(input,(int)iterations);

    printf("test return: %d\n", cache_bulkalloc(input,(int)iterations));

    return 1;
}
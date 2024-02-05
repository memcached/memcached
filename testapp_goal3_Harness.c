//
// Created by rigon on 10.01.24.
//
#include "defs-testcomp.c"
#include "cache.h"
#include "assert.h"
#include <stdio.h>
#include "cache.c"

extern size_t __VERIFIER_nondet_size_t();
extern char __VERIFIER_nondet_char();

enum test_return { TEST_SKIP, TEST_PASS, TEST_FAIL };

static enum test_return cache_bulkalloc(size_t datasize, int value)
{
    cache_t *cache = cache_create("test", datasize, sizeof(char*));
    if (cache == NULL) {
        return TEST_FAIL;
    }
#define ITERATIONS 1024
    void *ptr[ITERATIONS];

    for (int ii = 0; ii < ITERATIONS; ++ii) {
        ptr[ii] = cache_alloc(cache);
        assert(ptr[ii] != 0);
        memset(ptr[ii], value, datasize);
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
    char value = __VERIFIER_nondet_char();

    printf("datasize: %lu value: %i\n", input, (int)value);

    cache_bulkalloc(input, (int)value);

    printf("test return: %d\n", cache_bulkalloc(input, (int)value));

    return 1;
}
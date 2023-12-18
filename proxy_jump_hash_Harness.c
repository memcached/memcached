//
// Created by rigon on 04.12.23.
//

#include <stdio.h>
#include <stdint.h>
#include "defs-testcomp.c"

extern unsigned long __VERIFIER_nondet_ulong();
extern unsigned int __VERIFIER_nondet_uint();

typedef uint32_t (*hash_selector_func)(uint64_t hash, void *ctx);
struct proxy_hash_caller {
    hash_selector_func selector_func;
    void *ctx;
};
typedef struct {
    struct proxy_hash_caller phc; // passed back to proxy API
    unsigned int buckets;
} mcplib_jump_hash_t;

static uint32_t mcplib_dist_jump_hash_get_server(uint64_t hash, void *ctx) {
    mcplib_jump_hash_t *jh = ctx;

    int64_t b = -1, j = 0;
    while (j < jh->buckets) {
        b = j;
        hash = hash * 2862933555777941757ULL + 1;
        j = (b + 1) * ((double)(1LL << 31) / (double)((hash >> 33) + 1));
    }
    return b;
}

int main() {
    uint64_t hash = __VERIFIER_nondet_ulong();
    mcplib_jump_hash_t jh;
    jh.buckets = __VERIFIER_nondet_uint();

    printf("hash: %lu, buckets: %u\n", hash, jh.buckets);

    mcplib_dist_jump_hash_get_server(hash, &jh);

    return 1;
}

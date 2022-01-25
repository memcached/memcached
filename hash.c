/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "memcached.h"
#include "jenkins_hash.h"
#include "murmur3_hash.h"
#define XXH_INLINE_ALL // modifier for xxh3's include below
#include "xxhash.h"

hash_func hash;

static uint32_t XXH3_hash(const void *key, size_t length) {
    return (uint32_t)XXH3_64bits(key, length);
}

int hash_init(enum hashfunc_type type) {
    switch(type) {
        case JENKINS_HASH:
            hash = jenkins_hash;
            settings.hash_algorithm = "jenkins";
            break;
        case MURMUR3_HASH:
            hash = MurmurHash3_x86_32;
            settings.hash_algorithm = "murmur3";
            break;
        case XXH3_HASH:
            hash = XXH3_hash;
            settings.hash_algorithm = "xxh3";
            break;
        default:
            return -1;
    }
    return 0;
}

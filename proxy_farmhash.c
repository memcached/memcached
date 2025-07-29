/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

static uint64_t farmhash_wrapper(const void *key, size_t len, uint64_t seed) {
    // The seed is ignored to match the behavior of farmhash.
    return farmhash_fingerprint64((const char *)key, len);
}

static struct proxy_hash_func mcplib_hash_farmhash = {
    farmhash_wrapper,
};

int mcplib_open_hash_farmhash(lua_State *L) {
    lua_pushlightuserdata(L, &mcplib_hash_farmhash);
    return 1;
}

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

static struct proxy_hash_func mcplib_hash_xxhash = {
    XXH3_64bits_withSeed,
};

int mcplib_open_hash_xxhash(lua_State *L) {
    lua_pushlightuserdata(L, &mcplib_hash_xxhash);
    return 1;
}

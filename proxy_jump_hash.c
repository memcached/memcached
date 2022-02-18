/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

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

// stack = [pool, option]
static int mcplib_dist_jump_hash_new(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_Unsigned buckets = lua_rawlen(L, 1);

    mcplib_jump_hash_t *jh = lua_newuserdatauv(L, sizeof(mcplib_jump_hash_t), 0);

    // don't need to loop through the table at all, just need its length.
    // could optimize startup time by adding hints to the module for how to
    // format pool (ie; just a total count or the full table)
    jh->buckets = buckets;
    jh->phc.ctx = jh;
    jh->phc.selector_func = mcplib_dist_jump_hash_get_server;

    lua_pushlightuserdata(L, &jh->phc);

    // - return [UD, lightuserdata]
    return 2;
}

int mcplib_open_dist_jump_hash(lua_State *L) {
    const struct luaL_Reg jump_f[] = {
        {"new", mcplib_dist_jump_hash_new},
        {NULL, NULL},
    };

    luaL_newlib(L, jump_f);

    return 1;
}

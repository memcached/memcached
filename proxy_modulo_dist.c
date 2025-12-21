/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

// The modulo distribution function is a simple distribution function that
// uses the modulo operator to distribute the hash to a backend.
//
// It optionally takes a hash_mask option to mask the hash before the modulo
// operation.
typedef struct {
    struct proxy_hash_caller phc; // passed back to proxy API.
    unsigned int buckets;
    uint64_t mask;
} modulo_dist_t;

static uint32_t modulo_dist_get_server(uint64_t hash, void *ctx) {
    modulo_dist_t *md = ctx;
    return (uint32_t)((hash & md->mask) % md->buckets);
}

// stack = [pool, option]
static int modulo_dist_new(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_Unsigned buckets = lua_rawlen(L, 1);

    // By default, use all bits of the hash.
    uint64_t mask_val = UINT64_MAX;

    if (lua_istable(L, 2)) {
        if (lua_getfield(L, 2, "hash_mask") != LUA_TNIL) {
            luaL_checktype(L, -1, LUA_TSTRING);
            const char *mask_str = lua_tostring(L, -1);

            int base = 10;
            if (strncmp(mask_str, "0x", 2) == 0 || strncmp(mask_str, "0X", 2) == 0) {
                base = 16;
            }

            char *endptr;
            errno = 0;
            mask_val = strtoull(mask_str, &endptr, base);
            if (!(errno == 0 && *endptr == '\0')) {
                proxy_lua_error(L, "mcp.dist_modulo: invalid hash_mask value");
            }
        }
        lua_pop(L, 1);
    }

    modulo_dist_t *md = lua_newuserdatauv(L, sizeof(modulo_dist_t), 0);
    md->phc.selector_func = modulo_dist_get_server;
    md->phc.ctx = md;
    md->buckets = buckets;
    md->mask = mask_val;

    lua_pushlightuserdata(L, &md->phc);

    // - return [UD, lightuserdata]
    return 2;
}

int mcplib_open_dist_modulo(lua_State *L) {
    const struct luaL_Reg modulo_f[] = {
        {"new", modulo_dist_new},
        {NULL, NULL},
    };

    luaL_newlib(L, modulo_f);

    return 1;
}

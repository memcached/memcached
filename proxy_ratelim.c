/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

// No GC necessary.
struct mcp_ratelim_tbf {
    uint32_t bucket;
    uint32_t limit;
    uint32_t fill_rate; // tokens to add per tick rate
    uint32_t tick_rate; // in milliseconds
    int64_t last_update; // time in milliseconds
};

#define TIMEVAL_TO_MILLIS(n) (n.tv_usec / 1000 + n.tv_sec * (uint64_t)1000)

static lua_Integer _tbf_check(lua_State *L, char *key) {
    lua_Integer n = 0;
    if (lua_getfield(L, 1, key) != LUA_TNIL) {
        n = lua_tointeger(L, -1);
        if (n < 0 || n > UINT_MAX-1) {
            proxy_lua_error(L, "mcp.ratelim_tbf: arguments must be unsigned 32 bit integer");
        }
    }
    lua_pop(L, 1); // pops value or nil.
    return n;
}

int mcplib_ratelim_tbf(lua_State *L) {
    struct mcp_ratelim_tbf *lim = lua_newuserdatauv(L, sizeof(*lim), 0);
    struct timeval now;
    memset(lim, 0, sizeof(*lim));
    luaL_setmetatable(L, "mcp.ratelim_tbf");

    luaL_checktype(L, 1, LUA_TTABLE);
    lim->limit = _tbf_check(L, "limit");
    lim->fill_rate = _tbf_check(L, "fillrate");
    lim->tick_rate = _tbf_check(L, "tickrate");

    // seed the token bucket filter.
    lim->bucket = lim->limit;
    gettimeofday(&now, NULL);
    lim->last_update = TIMEVAL_TO_MILLIS(now);
    return 1;
}

int mcplib_ratelim_tbf_call(lua_State *L) {
    struct mcp_ratelim_tbf *lim = luaL_checkudata(L, 1, "mcp.ratelim_tbf");
    luaL_checktype(L, 2, LUA_TNUMBER);
    int take = lua_tointeger(L, 2);
    struct timeval now;
    uint64_t now_millis = 0;
    uint64_t delta = 0;

    gettimeofday(&now, NULL);
    now_millis = TIMEVAL_TO_MILLIS(now);
    delta = now_millis - lim->last_update;

    if (delta > lim->tick_rate) {
        // find how many ticks to add to the bucket.
        uint32_t toadd = delta / lim->tick_rate;
        // advance time up to the most recent tick.
        lim->last_update += toadd * lim->tick_rate;
        // add tokens to the bucket
        lim->bucket += toadd * lim->fill_rate;
        if (lim->bucket > lim->limit) {
            lim->bucket = lim->limit;
        }
    }

    if (lim->bucket > take) {
        lim->bucket -= take;
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

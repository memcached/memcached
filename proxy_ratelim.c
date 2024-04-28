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

struct mcp_ratelim_global_tbf {
    struct mcp_globalobj_s g;
    struct mcp_ratelim_tbf tbf;
};

#define TIMEVAL_TO_MILLIS(n) (n.tv_usec / 1000 + n.tv_sec * (uint64_t)1000)

// global config VM object GC
int mcplib_ratelim_global_tbf_gc(lua_State *L) {
    struct mcp_ratelim_global_tbf *lim = luaL_checkudata(L, 1, "mcp.ratelim_global_tbf");
    assert(lim->g.refcount == 0);
    mcp_gobj_finalize(&lim->g);

    // no other memory to directly free, just kill the mutex.
    return 0;
}

// worker thread proxy object GC
int mcplib_ratelim_proxy_tbf_gc(lua_State *L) {
    struct mcp_ratelim_global_tbf **lim_p = luaL_checkudata(L, 1, "mcp.ratelim_proxy_tbf");
    struct mcp_ratelim_global_tbf *lim = *lim_p;
    proxy_ctx_t *ctx = PROXY_GET_THR_CTX(L);
    mcp_gobj_unref(ctx, &lim->g);

    return 0;
}

int mcp_ratelim_proxy_tbf(lua_State *from, lua_State *to) {
    // from, -3 should have the userdata.
    struct mcp_ratelim_global_tbf *lim = luaL_checkudata(from, -3, "mcp.ratelim_global_tbf");
    struct mcp_ratelim_global_tbf **lim_p = lua_newuserdatauv(to, sizeof(struct mcp_ratelim_global_tbf *), 0);
    luaL_setmetatable(to, "mcp.ratelim_proxy_tbf");

    *lim_p = lim;
    lua_pushvalue(from, -3); // copy ratelim obj to ref below
    mcp_gobj_ref(from, &lim->g); // pops obj copy

    return 0;
}

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

static void _setup_tbf(lua_State *L, struct mcp_ratelim_tbf *lim) {
    struct timeval now;
    luaL_checktype(L, 1, LUA_TTABLE);
    lim->limit = _tbf_check(L, "limit");
    lim->fill_rate = _tbf_check(L, "fillrate");
    lim->tick_rate = _tbf_check(L, "tickrate");

    // seed the token bucket filter.
    lim->bucket = lim->limit;
    gettimeofday(&now, NULL);
    lim->last_update = TIMEVAL_TO_MILLIS(now);
}

int mcplib_ratelim_tbf(lua_State *L) {
    struct mcp_ratelim_tbf *lim = lua_newuserdatauv(L, sizeof(*lim), 0);
    memset(lim, 0, sizeof(*lim));
    luaL_setmetatable(L, "mcp.ratelim_tbf");

    _setup_tbf(L, lim);
    return 1;
}

int mcplib_ratelim_global_tbf(lua_State *L) {
    struct mcp_ratelim_global_tbf *lim = lua_newuserdatauv(L, sizeof(*lim), 0);
    memset(lim, 0, sizeof(*lim));
    // TODO: during next refactor, add "globalobj init" phase, which probably
    // just does this.
    pthread_mutex_init(&lim->g.lock, NULL);
    luaL_setmetatable(L, "mcp.ratelim_global_tbf");

    _setup_tbf(L, &lim->tbf);
    return 1;
}

static int _update_tbf(struct mcp_ratelim_tbf *lim, int take, uint64_t now) {
    uint64_t delta = 0;
    delta = now - lim->last_update;

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
        return 1;
    } else {
        return 0;
    }
}

int mcplib_ratelim_tbf_call(lua_State *L) {
    struct mcp_ratelim_tbf *lim = luaL_checkudata(L, 1, "mcp.ratelim_tbf");
    luaL_checktype(L, 2, LUA_TNUMBER);
    int take = lua_tointeger(L, 2);
    struct timeval now;
    uint64_t now_millis = 0;

    gettimeofday(&now, NULL);
    now_millis = TIMEVAL_TO_MILLIS(now);
    lua_pushboolean(L, _update_tbf(lim, take, now_millis));

    return 1;
}

// NOTE: it should be possible to run a TBF using atomics, in the future when
// we start to support C11 atomics.
// Flip the concept of checking the time, updating, then subtracting the take
// to:
// - how much "time elapsed" is necessary for the take requested
// - atomically load the old time
// - if not enough time delta between old time and now, return false
// - else atomically swap the update time with the new time
//   - compare and update the oldtime to newtime
// - not sure how much perf this buys you. would have to test.
int mcplib_ratelim_proxy_tbf_call(lua_State *L) {
    struct mcp_ratelim_global_tbf **lim_p = luaL_checkudata(L, 1, "mcp.ratelim_proxy_tbf");
    // line was kinda long / hard to read.
    struct mcp_ratelim_global_tbf *lim = *lim_p;
    struct timeval now;
    luaL_checktype(L, 2, LUA_TNUMBER);
    int take = lua_tointeger(L, 2);
    gettimeofday(&now, NULL);
    uint64_t now_millis = 0;
    now_millis = TIMEVAL_TO_MILLIS(now);

    pthread_mutex_lock(&lim->g.lock);
    int res = _update_tbf(&lim->tbf, take, now_millis);
    pthread_mutex_unlock(&lim->g.lock);

    lua_pushboolean(L, res);
    return 1;
}

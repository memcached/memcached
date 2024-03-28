/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"
// TODO: worth making counter vs opaque bits configurable?
#define LOGICAL_BITS 15
#define LOGICAL_MAX ((1<<15)-1)
// can have 256 unique machines in a cluster
#define OPAQUE_BITS 8

// name: cas_hlc? time_hlc? order_hlc?
struct mcp_hlc {
    uint64_t physical_time; // last observed time in milliseconds
    uint16_t logical_time; // logical clock counter.
    uint8_t opaque; // opaque constant trailer
};

struct mcp_global_hlc {
    struct mcp_globalobj_s g;
    struct mcp_hlc t;
};

int mcplib_global_hlc_gc(lua_State *L) {
    struct mcp_global_hlc *hlc = luaL_checkudata(L, 1, "mcp.global_hlc");
    assert(hlc->g.refcount == 0);
    pthread_mutex_destroy(&hlc->g.lock);

    return 0;
}

int mcplib_proxy_hlc_gc(lua_State *L) {
    struct mcp_global_hlc **hlc_p = luaL_checkudata(L, 1, "mcp.proxy_hlc");
    struct mcp_global_hlc *hlc = *hlc_p;
    proxy_ctx_t *ctx = PROXY_GET_THR_CTX(L);

    pthread_mutex_lock(&hlc->g.lock);
    hlc->g.refcount--;
    if (hlc->g.refcount == 0) {
        pthread_mutex_lock(&ctx->manager_lock);
        STAILQ_INSERT_TAIL(&ctx->manager_head, &hlc->g, next);
        pthread_cond_signal(&ctx->manager_cond);
        pthread_mutex_unlock(&ctx->manager_lock);
    }
    pthread_mutex_unlock(&hlc->g.lock);

    return 0;
}

// create the proxy object.
int mcp_proxy_hlc(lua_State *from, lua_State *to) {
    struct mcp_global_hlc *hlc = luaL_checkudata(from, -3, "mcp.global_hlc");
    struct mcp_global_hlc **hlc_p = lua_newuserdatauv(to, sizeof(struct mcp_global_hlc *), 0);
    luaL_setmetatable(to, "mcp.proxy_hlc");

    *hlc_p = hlc;
    pthread_mutex_lock(&hlc->g.lock);
    // self reference on our first up-reference.
    if (hlc->g.self_ref == 0) {
        lua_pushvalue(from, -3); // copy the object
        hlc->g.self_ref = luaL_ref(from, LUA_REGISTRYINDEX); // pops
    }
    hlc->g.refcount++;
    pthread_mutex_unlock(&hlc->g.lock);

    return 0;
}

int mcplib_global_hlc(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    struct mcp_global_hlc *hlc = lua_newuserdatauv(L, sizeof(*hlc), 0);
    memset(hlc, 0, sizeof(*hlc));

    pthread_mutex_init(&hlc->g.lock, NULL);
    luaL_setmetatable(L, "mcp.global_hlc");

    if (lua_getfield(L, 1, "opaque") != LUA_TNIL) {
        hlc->t.opaque = lua_tointeger(L, -1) & 0xFF;
    }
    lua_pop(L, 1); // pop value or nil.

    return 1;
}

static int _hlc_time(struct mcp_global_hlc *hlc, lua_Integer *res, lua_Integer *opaque) {
    struct timeval now;
    gettimeofday(&now, NULL);
    uint64_t physical_time = TIMEVAL_TO_MILLIS(now);

    // 64 bits to use.
    // 41 MSB: time-millis
    // 15 bit counter
    // 8 bit opaque

    pthread_mutex_lock(&hlc->g.lock);
    *opaque = hlc->t.opaque;
    // ALGORITHM:
    // If now > last pt:
    // - set logical to 1
    // - assemble number, return value
    // If now <= last pt:
    // - increment logical
    // If logical at max (1<<15 - 1) then return nil
    if (physical_time > hlc->t.physical_time) {
        hlc->t.physical_time = physical_time;
        hlc->t.logical_time = 1;
    } else {
        // unlikely() would be nice here.
        if (hlc->t.logical_time == LOGICAL_MAX) {
            // Bail early because we couldn't make a new counter.
            pthread_mutex_unlock(&hlc->g.lock);
            return 0;
        } else {
            hlc->t.logical_time++;
        }
    }

    // Assemble the clock and logical time together.
    // We don't assemble with the OPAQUE here because we want to use all 64
    // bits, and lua integers are signed 64bit. Thus we only have 63 bits
    // usable unless we want to make user level numeric comparisons more
    // difficult.
    *res = (hlc->t.physical_time << LOGICAL_BITS) | hlc->t.logical_time;

    pthread_mutex_unlock(&hlc->g.lock);

    return 1;
}

// Function takes no inputs, returns a (likely) increasing time value
int mcplib_proxy_hlc_time(lua_State *L) {
    struct mcp_global_hlc **hlc_p = luaL_checkudata(L, 1, "mcp.proxy_hlc");
    struct mcp_global_hlc *hlc = *hlc_p;

    lua_Integer res = 0;
    lua_Integer opaque = 0;

    if (_hlc_time(hlc, &res, &opaque)) {
        lua_pushinteger(L, res);
        lua_pushinteger(L, opaque);
        return 2;
    } else {
        lua_pushnil(L);
        return 1;
    }
}

// Render full time + opaque as a string and return it.
// If a string is supplied, prepend the first character
int mcplib_proxy_hlc_time_string(lua_State *L) {
    char temp[22]; // space for 64bit num + a char + null 0
    char *p = temp;
    struct mcp_global_hlc **hlc_p = luaL_checkudata(L, 1, "mcp.proxy_hlc");
    struct mcp_global_hlc *hlc = *hlc_p;
    lua_Integer res = 0;
    lua_Integer opaque = 0;

    if (_hlc_time(hlc, &res, &opaque) == 0) {
        lua_pushnil(L);
        return 1;
    }

    if (lua_isstring(L, 2)) {
        size_t len = 0;
        const char *str = lua_tolstring(L, 1, &len);
        if (len > 0) {
            *p = str[0];
            p++;
        }
    }

    p = itoa_u64(((uint64_t)res << OPAQUE_BITS) | opaque, p);
    *p = 0;
    lua_pushstring(L, temp);

    return 1;
}

// TODO: func that takes a string and splits it into hlc/opaque numbers

int mcplib_proxy_hlc_add_to_req(lua_State *L) {
    struct mcp_global_hlc **hlc_p = luaL_checkudata(L, 1, "mcp.proxy_hlc");
    struct mcp_global_hlc *hlc = *hlc_p;
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    char temp[22];
    lua_Integer res = 0;
    lua_Integer opaque = 0;

    // Couldn't get a new time value, let caller know.
    if (_hlc_time(hlc, &res, &opaque) == 0) {
        lua_pushboolean(L, 0);
        return 1;
    }

    char *p = temp;
    p = itoa_u64(((uint64_t)res << OPAQUE_BITS) | opaque, p);
    *p = 0;

    // Find if we already have an E flag
    int x = mcp_request_find_flag_index(rq, 'E');
    if (x > 0) {
        // can fail due to request being too long/etc.
        if (mcp_request_render(rq, x, 'E', temp, p - temp) != 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
    } else {
        if (mcp_request_append(rq, 'E', temp, p - temp) != 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
    }

    lua_pushboolean(L, 1);
    return 1;
}

// Note: not currently using the HLC object itself. We will need to use it if
// I end up making the counter/opaque bits dynamic.
int mcplib_proxy_hlc_get_from_res(lua_State *L) {
    luaL_checkudata(L, 1, "mcp.proxy_hlc");
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    // res->buf and res->blen is the full response line.
    // res->resp.rline and res->resp.rlen is the start and end of the "meta
    // parameters" for flags/tokens.

    // check for rline/rlen
    if (r->resp.rlen) {
        lua_Integer res = 0;
        lua_Integer opaque = 0;
        uint64_t time = 0;

        // manually parse the string looking for 'cTOKEN'
        const char *p = r->resp.rline;
        const char *e = p + r->resp.rlen;
        while (p != e) {
            if (*p == ' ') {
                // skip one space.
                p++;
            } else if (*p == 'c') {
                // TODO: we need (soon) a strtoull that takes a length
                if (safe_strtoull(p+1, &time)) {
                    // doing the work directly inside the loop as I can't
                    // think of a way of doing this without an extra branch
                    // test outside of the loop, or a goto...
                    opaque = time & 0xFF;
                    time >>= OPAQUE_BITS;
                    res = time;

                    lua_pushinteger(L, res);
                    lua_pushinteger(L, opaque);
                    return 2;
                }
            } else {
                // skip a flag/token
                while (p != e && *p != ' ') {
                    p++;
                }
            }
        }
    }

    // got here because nothing found.
    lua_pushnil(L);
    return 1;
}

// Note: not currently using the HLC object itself. We will need to use it if
// I end up making the counter/opaque bits dynamic.
int mcplib_proxy_hlc_get_from_req(lua_State *L) {
    luaL_checkudata(L, 1, "mcp.proxy_hlc");
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    lua_Integer res = 0;
    lua_Integer opaque = 0;

    const char *token = NULL;
    size_t len = 0;
    int x = mcp_request_find_flag_token(rq, 'E', &token, &len);
    if (x > 0) {
        uint64_t time = 0;
        // strtoull the string -> number
        // then split off res from opaque and return both
        if (safe_strtoull(token, &time)) {
            // pull off the opaque value
            opaque = time & 0xFF;
            // shift res into place so lua won't eat the MSB.
            time >>= OPAQUE_BITS;
            res = time;

            lua_pushinteger(L, res);
            lua_pushinteger(L, opaque);
            return 2;
        } else {
            // failed to parse a number.
            lua_pushnil(L);
            return 1;
        }
    } else {
        // no flag found.
        lua_pushnil(L);
        return 1;
    }

    return 0;
}

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

// mcp.add_stat(index, name)
// creates a custom lua stats counter
int mcplib_add_stat(lua_State *L) {
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));
    if (t != NULL) {
        proxy_lua_error(L, "add_stat must be called from config_pools");
        return 0;
    }
    int idx = luaL_checkinteger(L, -2);
    const char *name = luaL_checkstring(L, -1);

    if (idx < 1) {
        proxy_lua_error(L, "stat index must be 1 or higher");
        return 0;
    }
    // max user counters? 1024? some weird number.
    if (idx > 1024) {
        proxy_lua_error(L, "stat index must be 1024 or less");
        return 0;
    }
    // max name length? avoids errors if something huge gets thrown in.
    if (strlen(name) > STAT_KEY_LEN - 6) {
        // we prepend "user_" to the output. + null byte.
        proxy_lua_ferror(L, "stat name too long: %s\n", name);
        return 0;
    }
    // restrict characters, at least no spaces/newlines.
    for (int x = 0; x < strlen(name); x++) {
        if (isspace(name[x])) {
            proxy_lua_error(L, "stat cannot contain spaces or newlines");
            return 0;
        }
    }

    proxy_ctx_t *ctx = settings.proxy_ctx; // TODO (v2): store ctx in upvalue.

    STAT_L(ctx);
    struct proxy_user_stats *us = &ctx->user_stats;

    // if num_stats is 0 we need to init sizes.
    // TODO (v2): malloc fail checking. (should be rare/impossible)
    if (us->num_stats < idx) {
        // don't allocate counters memory for the global ctx.
        char **nnames = calloc(idx, sizeof(char *));
        if (us->names != NULL) {
            for (int x = 0; x < us->num_stats; x++) {
                nnames[x] = us->names[x];
            }
            free(us->names);
        }
        us->names = nnames;
        us->num_stats = idx;
    }

    idx--; // real slot start as 0.
    // if slot has string in it, free first
    if (us->names[idx] != NULL) {
        free(us->names[idx]);
    }
    // strdup name into string slot
    // TODO (v2): malloc failure.
    us->names[idx] = strdup(name);
    STAT_UL(ctx);

    return 0;
}

int mcplib_stat(lua_State *L) {
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));
    if (t == NULL) {
        proxy_lua_error(L, "stat must be called from router handlers");
        return 0;
    }

    struct proxy_user_stats *tus = t->proxy_user_stats;
    if (tus == NULL) {
        proxy_lua_error(L, "no stats counters initialized");
        return 0;
    }

    int idx = luaL_checkinteger(L, -2);
    int change = luaL_checkinteger(L, -1);

    if (idx < 1 || idx > tus->num_stats) {
        proxy_lua_error(L, "stat index out of range");
        return 0;
    }

    idx--; // actual array is 0 indexed.
    WSTAT_L(t);
    tus->counters[idx] += change;
    WSTAT_UL(t);

    return 0;
}

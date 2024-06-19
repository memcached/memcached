/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

// mcp.add_stat(index, name)
// creates a custom lua stats counter
int mcplib_add_stat(lua_State *L) {
    int idx = luaL_checkinteger(L, -2);
    const char *name = luaL_checkstring(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    if (idx < 1) {
        proxy_lua_error(L, "stat index must be 1 or higher");
        return 0;
    }
    if (idx > ctx->tunables.max_ustats) {
        proxy_lua_ferror(L, "stat index must be %d or less", ctx->tunables.max_ustats);
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

    STAT_L(ctx);
    int stats_num = ctx->user_stats_num;
    struct proxy_user_stats_entry *entries = ctx->user_stats;

    // if num_stats is 0 we need to init sizes.
    // TODO (v2): malloc fail checking. (should be rare/impossible)
    if (stats_num < idx) {
        struct proxy_user_stats_entry *nentries = calloc(idx, sizeof(*entries));
        // funny realloc; start with zeroed memory and copy in original.
        if (entries) {
            memcpy(nentries, entries, sizeof(*entries) * stats_num);
            free(entries);
        }
        ctx->user_stats = nentries;
        ctx->user_stats_num = idx;
        entries = nentries;
    }

    idx--; // real slot start as 0.
    if (entries[idx].name != NULL) {
        // If name changed, we have to reset the counter in the slot.
        // Also only free/strdup the string if it's changed.
        if (strcmp(name, entries[idx].name) != 0) {
            entries[idx].reset = true;
            free(entries[idx].name);
            entries[idx].name = strdup(name);
        }
        // else the stat name didn't change, so don't do anything.
    } else if (entries[idx].cname) {
        char *oldname = ctx->user_stats_namebuf + entries[idx].cname;
        if (strcmp(name, oldname) != 0) {
            entries[idx].reset = true;
            entries[idx].name = strdup(name);
        }
    } else {
        entries[idx].name = strdup(name);
    }
    STAT_UL(ctx);

    return 0;
}

int mcplib_stat(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
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

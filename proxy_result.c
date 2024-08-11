/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

int mcplib_response_elapsed(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");
    lua_pushinteger(L, r->elapsed);
    return 1;
}

// resp:ok()
int mcplib_response_ok(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->status == MCMC_OK) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

int mcplib_response_hit(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->status == MCMC_OK && r->resp.code != MCMC_CODE_END) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

// Caller needs to discern if a vlen is 0 because of a failed response or an
// OK response that was actually zero. So we always return an integer value
// here.
int mcplib_response_vlen(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    // We do remove the "\r\n" from the value length, so if you're actually
    // processing the value nothing breaks.
    if (r->resp.vlen >= 2) {
        lua_pushinteger(L, r->resp.vlen-2);
    } else {
        lua_pushinteger(L, 0);
    }

    return 1;
}

// Refer to MCMC_CODE_* defines.
int mcplib_response_code(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    lua_pushinteger(L, r->resp.code);

    return 1;
}

// Get the unparsed response line for handling in lua.
int mcplib_response_line(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->resp.rline != NULL) {
        lua_pushlstring(L, r->resp.rline, r->resp.rlen);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

int mcplib_response_flag_blank(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, 1, "mcp.response");
    mcmc_resp_t reresp;
    size_t len = 0;
    const char *flagstr = luaL_checklstring(L, 2, &len);

    if (len != 1) {
        proxy_lua_error(L, "request: meta flag must be a single character");
        return 0;
    }
    if (flagstr[0] < 65 || flagstr[0] > 122) {
        proxy_lua_error(L, "request: invalid flag, must be A-Z,a-z");
        return 0;
    }

    mcmc_parse_buf(r->buf, r->blen, &reresp);

    if (reresp.type == MCMC_RESP_META) {
        // r->resp.rline is the start of the meta line... rlen is the length.
        // we cast away the const and do evil here.
        char *pos = (char *) reresp.rline;
        size_t rlen = reresp.rlen;

        char *end = pos + rlen;
        char flag = flagstr[0];

        while (pos != end) {
            // either flag is at the start of the line or it has a space
            // immediately before it.
            if (*pos == flag && (pos == reresp.rline || *(pos-1) == ' ')) {
                while (pos != end && !isspace(*pos)) {
                    *pos = ' ';
                    pos++;
                }
                lua_pushboolean(L, 1); // found and blanked.
                return 1;
            } else {
                pos++;
            }
        }

        // TODO: blank out r->tok?
    }
    lua_pushboolean(L, 0); // not found or not done.
    return 1;
}

void mcp_response_cleanup(LIBEVENT_THREAD *t, mcp_resp_t *r) {
    // On error/similar we might be holding the read buffer.
    // If the buf is handed off to mc_resp for return, this pointer is NULL
    if (r->buf != NULL) {
        pthread_mutex_lock(&t->proxy_limit_lock);
        t->proxy_buffer_memory_used -= r->blen + r->extra;
        pthread_mutex_unlock(&t->proxy_limit_lock);

        free(r->buf);
        r->buf = NULL;
    }
    r->tok.ntokens = 0;

    // release our temporary mc_resp sub-object.
    if (r->cresp != NULL) {
        mc_resp *cresp = r->cresp;
        assert(r->thread != NULL);
        if (cresp->item) {
            item_remove(cresp->item);
            cresp->item = NULL;
        }
        resp_free(r->thread, cresp);
        r->cresp = NULL;
    }
}

int mcplib_response_gc(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");
    mcp_response_cleanup(t, r);

    return 0;
}

// Note that this can be called multiple times for a single object, as opposed
// to _gc. The cleanup routine is armored against repeat accesses by NULL'ing
// th efields it checks.
int mcplib_response_close(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_resp_t *r = luaL_checkudata(L, 1, "mcp.response");
    mcp_response_cleanup(t, r);

    return 0;
}



/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"
#include "proto_parser.h"

// FIXME (v2): any reason to pass in command/cmdlen separately?
mcp_request_t *mcp_new_request(lua_State *L, mcp_parser_t *pr, const char *command, size_t cmdlen) {
    mcp_request_t *rq = lua_newuserdatauv(L, sizeof(mcp_request_t) + MCP_REQUEST_MAXLEN, 0);
    // TODO (v2): memset only the non-data part? as the rest gets memcpy'd
    // over.
    memset(rq, 0, sizeof(mcp_request_t));
    memcpy(&rq->pr, pr, sizeof(*pr));

    memcpy(rq->request, command, cmdlen);
    rq->pr.request = rq->request;
    rq->pr.reqlen = cmdlen;

    luaL_getmetatable(L, "mcp.request");
    lua_setmetatable(L, -2);

    // at this point we should know if we have to bounce through _nread to
    // get item data or not.
    return rq;
}

// fill a preallocated request object.
void mcp_set_request(mcp_parser_t *pr, mcp_request_t *rq, const char *command, size_t cmdlen) {
    memset(rq, 0, sizeof(mcp_request_t));
    memcpy(&rq->pr, pr, sizeof(*pr));

    memcpy(rq->request, command, cmdlen);
    rq->pr.request = rq->request;
    rq->pr.reqlen = cmdlen;
}

// Replaces a token inside a request and re-parses.
// Note that this has some optimization opportunities. Delaying until
// required.
// We should not guarantee order when updating meta flags, which would allow
// blanking tokens and appending new ones.
// TODO (v2): much of the length is the key, avoid copying it.
int mcp_request_render(mcp_request_t *rq, int idx, const char flag, const char *tok, size_t len) {
    char temp[MCP_REQUEST_MAXLEN+1];
    char *p = temp;
    mcp_parser_t *pr = &rq->pr;

    if (pr->reqlen + len + 2 > MCP_REQUEST_MAXLEN) {
        return -1;
    }
    // Cannot add/append tokens yet.
    if (idx >= pr->tok.ntokens) {
        return -1;
    }

    // FIXME: should use an accessor macro, at least.
    memcpy(p, pr->request, pr->tok.tokens[idx]);
    p += pr->tok.tokens[idx];

    if (flag) {
        *p = flag;
        p++;
    }
    if (tok) {
        memcpy(p, tok, len);
        p += len;
    }

    // Add a space and copy more tokens if there were more.
    if (idx+1 < pr->tok.ntokens) {
        if (flag || len != 0) {
            // Only pre-space if not deleting the token.
            *p = ' ';
            p++;
        }
        memcpy(p, &pr->request[pr->tok.tokens[idx+1]], pr->tok.tokens[pr->tok.ntokens] - pr->tok.tokens[idx+1]);
        p += pr->tok.tokens[pr->tok.ntokens] - pr->tok.tokens[idx+1];
    } else {
        // If we removed something from the end we might've left some spaces.
        while (*(p-1) == ' ') {
            p--;
        }
    }

    memcpy(p, "\r\n\0", 3);
    p += 2;

    memcpy(rq->request, temp, p - temp);

    // Hold the vlen/vbuf and restore after re-parsing. Since we can only edit
    // the command line, not the value here, we would otherwise allow sending
    // arbitrary memory over the network if someone modifies a SET.
    void *vbuf = pr->vbuf;
    int vlen = pr->vlen;

    memset(pr, 0, sizeof(mcp_parser_t)); // TODO: required?
    int ret = process_request(pr, rq->request, p - temp);
    if (ret != 0) {
        // FIXME: does this leak the vbuf?
        return ret;
    }
    pr->vbuf = vbuf;
    pr->vlen = vlen;
    return 0;
}

int mcp_request_append(mcp_request_t *rq, const char flag, const char *tok, size_t len) {
    mcp_parser_t *pr = &rq->pr;
    const char *start = pr->request;
    char *p = (char *)pr->request + pr->reqlen - 2; // start at the \r
    assert(*p == '\r');

    if (pr->reqlen + len + 2 > MCP_REQUEST_MAXLEN) {
        return -1;
    }

    *p = ' ';
    p++;

    if (flag) {
        *p = flag;
        p++;
    }
    if (tok) {
        memcpy(p, tok, len);
        p += len;
    }

    memcpy(p, "\r\n\0", 3);
    p += 2;

    // See note on mcp_request_render()
    void *vbuf = pr->vbuf;
    int vlen = pr->vlen;

    memset(pr, 0, sizeof(mcp_parser_t)); // TODO: required?
    int ret = process_request(pr, rq->request, p - start);
    if (ret != 0) {
        return ret;
    }
    pr->vbuf = vbuf;
    pr->vlen = vlen;

    return 0;
}

void mcp_request_attach(mcp_request_t *rq, io_pending_proxy_t *p) {
    mcp_parser_t *pr = &rq->pr;
    char *r = (char *) pr->request;
    size_t len = pr->reqlen;

    // The stringified request. This is also referencing into the coroutine
    // stack, which should be safe from gc.
    p->iov[0].iov_base = r;
    p->iov[0].iov_len = len;
    p->iovcnt = 1;
    p->iovbytes = len;
    if (pr->vlen != 0) {
        p->iov[1].iov_base = pr->vbuf;
        p->iov[1].iov_len = pr->vlen;
        p->iovcnt = 2;
        p->iovbytes += pr->vlen;
    }
}

// second argument is optional, for building set requests.
// TODO: append the \r\n for the VAL?
int mcplib_request(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    size_t len = 0;
    size_t vlen = 0;
    mcp_parser_t pr = {0};
    const char *cmd = luaL_checklstring(L, 1, &len);
    const char *val = NULL;
    int type = lua_type(L, 2);
    if (type == LUA_TSTRING) {
        val = luaL_optlstring(L, 2, NULL, &vlen);
        if (vlen < 2 || memcmp(val+vlen-2, "\r\n", 2) != 0) {
            proxy_lua_error(L, "value passed to mcp.request must end with \\r\\n");
        }
    } else if (type == LUA_TUSERDATA) {
        // vlen for requests and responses include the "\r\n" already.
        mcp_resp_t *r = luaL_testudata(L, 2, "mcp.response");
        if (r != NULL) {
            if (r->resp.value) {
                val = r->resp.value;
                vlen = r->resp.vlen_read; // paranoia, so we can't overread into memory.
            }
        } else {
            mcp_request_t *rq = luaL_testudata(L, 2, "mcp.request");
            if (rq->pr.vbuf) {
                val = rq->pr.vbuf;
                vlen = rq->pr.vlen;
            }
        }
    }

    if (len > MCP_REQUEST_MAXLEN) {
        proxy_lua_error(L, "request length too long");
        return 0;
    }

    if (memcmp(cmd+len-2, "\r\n", 2) != 0) {
        proxy_lua_error(L, "request must end with \r\n");
        return 0;
    }

    // FIXME (v2): if we inline the userdata we can avoid memcpy'ing the parser
    // structure from the stack? but causes some code duplication.
    if (process_request(&pr, cmd, len) != 0) {
        proxy_lua_error(L, "failed to parse request");
        return 0;
    }
    mcp_request_t *rq = mcp_new_request(L, &pr, cmd, len);

    if (val != NULL) {
        rq->pr.vlen = vlen;
        rq->pr.vbuf = malloc(vlen);
        if (rq->pr.vbuf == NULL) {
            // Note: without *c we can't tick the appropriate counter.
            // However, in practice raw malloc's are nearly never going to
            // fail.
            // TODO(v2): we can stack values into the request objects or use
            // the slabber memory, so this isn't necessary anyway.
            proxy_lua_error(L, "failed to allocate value memory for request object");
        }
        memcpy(rq->pr.vbuf, val, vlen);
        // Note: Not enforcing the memory limit here is deliberate:
        // - if we're over the memory limit, it'll get caught very soon after
        // this, but we won't be causing some lua to bail mid-flight, which is
        // more graceful to the end user.
        pthread_mutex_lock(&t->proxy_limit_lock);
        t->proxy_buffer_memory_used += rq->pr.vlen;
        pthread_mutex_unlock(&t->proxy_limit_lock);
    }

    // rq is now created, parsed, and on the stack.
    return 1;
}

int mcplib_request_key(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    lua_pushlstring(L, MCP_PARSER_KEY(&rq->pr), rq->pr.klen);
    return 1;
}

// NOTE: I've mixed up const/non-const strings in the request. During parsing
// we want it to be const, but after that's done the request is no longer
// const. It might be better to just remove the const higher up the chain, but
// I'd rather not. So for now these functions will be dumping the const to
// modify the string.
int mcplib_request_ltrimkey(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -2, "mcp.request");
    int totrim = luaL_checkinteger(L, -1);
    char *key = (char *) MCP_PARSER_KEY(&rq->pr);

    if (totrim > rq->pr.klen) {
        proxy_lua_error(L, "ltrimkey cannot zero out key");
        return 0;
    } else {
        memset(key, ' ', totrim);
        rq->pr.klen -= totrim;
        rq->pr.tok.tokens[rq->pr.keytoken] += totrim;
    }
    return 1;
}

int mcplib_request_rtrimkey(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -2, "mcp.request");
    int totrim = luaL_checkinteger(L, -1);
    char *key = (char *) MCP_PARSER_KEY(&rq->pr);

    if (totrim > rq->pr.klen) {
        proxy_lua_error(L, "rtrimkey cannot zero out key");
        return 0;
    } else {
        memset(key + (rq->pr.klen - totrim), ' ', totrim);
        rq->pr.klen -= totrim;
        // don't need to change the key token.
    }
    return 1;
}

int mcplib_request_get_rline(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    lua_pushlstring(L, rq->pr.request, rq->pr.reqlen-2);
    return 1;
}

int mcplib_request_get_value(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    if (rq->pr.vbuf) {
        lua_pushlstring(L, rq->pr.vbuf, rq->pr.vlen);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

// Virtual table operations on the request.
int mcplib_request_token(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    int argc = lua_gettop(L);

    if (argc == 1) {
        lua_pushnil(L);
        return 1;
    }

    int token = luaL_checkinteger(L, 2);

    if (token < 1 || token > rq->pr.tok.ntokens) {
        // maybe an error?
        lua_pushnil(L);
        return 1;
    }

    if (argc > 2) {
        // overwriting a token.
        size_t newlen = 0;
        const char *newtok = lua_tolstring(L, 3, &newlen);
        if (mcp_request_render(rq, token-1, 0, newtok, newlen) != 0) {
            proxy_lua_error(L, "token(): request malformed after edit");
            return 0;
        }
        return 0;
    } else {
        // fetching a token.
        mcp_parser_t *pr = &rq->pr;
        int vlen = 0;
        const char *start = mcmc_token_get(pr->request, &pr->tok, pr->keytoken, &vlen);

        P_DEBUG("%s: pushing token of len: %lu\n", __func__, vlen);
        lua_pushlstring(L, start, vlen);
        return 1;
    }

    return 0;
}

// Fetch only.
int mcplib_request_token_int(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    int argc = lua_gettop(L);

    if (argc == 1) {
        lua_pushnil(L);
        return 1;
    }

    int x = luaL_checkinteger(L, 2);

    if (x < 1 || x > rq->pr.tok.ntokens) {
        // maybe an error?
        lua_pushnil(L);
        return 1;
    }

    int64_t token = 0;
    if (mcmc_token_get_64(rq->pr.request, &rq->pr.tok, x-1, &token) != MCMC_OK) {
        lua_pushnil(L);
    } else {
        lua_pushinteger(L, token);
    }
    return 1;
}

int mcplib_request_ntokens(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    lua_pushinteger(L, rq->pr.tok.ntokens);
    return 1;
}

int mcplib_request_command(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    lua_pushinteger(L, rq->pr.command);
    return 1;
}

int mcplib_request_has_flag(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    size_t len = 0;
    const char *flagstr = luaL_checklstring(L, 2, &len);
    if (len != 1) {
        proxy_lua_error(L, "has_flag(): meta flag must be a single character");
        return 0;
    }

    int status = mcmc_token_has_flag(rq->pr.request, &rq->pr.tok, flagstr[0]);
    if (status == MCMC_ERR) {
        proxy_lua_error(L, "has_flag(): invalid flag, must be A-Z,a-z");
        return 0;
    } else if (status == MCMC_OK) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

// req:flag_token("F") -> (bool, nil|token)
// req:flag_token("O", "Onewopauqe") -> (bool, oldtoken)
int mcplib_request_flag_token(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    size_t len = 0;
    const char *flagstr = luaL_checklstring(L, 2, &len);
    bool replace = false;
    if (len != 1) {
        proxy_lua_error(L, "has_flag(): meta flag must be a single character");
        return 0;
    }
    if (lua_isstring(L, 3)) {
        // overwriting a flag/token with the third argument.
        replace = true;
    }

    int status = mcmc_token_has_flag(rq->pr.request, &rq->pr.tok, flagstr[0]);
    int ret = 1;
    if (status == MCMC_ERR) {
        proxy_lua_error(L, "has_flag(): invalid flag, must be A-Z,a-z");
        return 0;
    } else if (status == MCMC_OK) {
        // The flag definitely exists, but sadly we need to scan for the
        // actual flag to see if it has a token.
        lua_pushboolean(L, 1);
        int vlen = 0;
        // TODO: too much logic here since we also need to find the token
        // offset for the replace mode...
        // I think all this stuff can safely be long-term deprecated since we
        // have the mutator now so maybe I'll leave it.
        for (int x = rq->pr.keytoken+1; x < rq->pr.tok.ntokens; x++) {
            const char *s = mcmc_token_get(rq->pr.request, &rq->pr.tok, x, &vlen);
            if (s[0] == flagstr[0]) {
                if (vlen > 1) {
                    // strip the flag off the token and return.
                    lua_pushlstring(L, s+1, vlen-1);
                    ret = 2;
                }

                // Have something to replace the flag/token with.
                if (replace) {
                    size_t newlen = 0;
                    const char *newtok = lua_tolstring(L, 3, &newlen);
                    if (mcp_request_render(rq, x, 0, newtok, newlen) != 0) {
                        proxy_lua_error(L, "token(): request malformed after edit");
                        return 0;
                    }
                }
                break;
            }
        }

    } else {
        lua_pushboolean(L, 0);
    }

    return ret;
}

// returns bool, int
// bool results if flag exists or not
// if int conversion fails, int is nil
int mcplib_request_flag_token_int(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    size_t len = 0;
    const char *flagstr = luaL_checklstring(L, 2, &len);
    if (len != 1) {
        proxy_lua_error(L, "has_flag(): meta flag must be a single character");
        return 0;
    }

    int64_t val = 0;
    int status = mcmc_token_get_flag_64(rq->pr.request, &rq->pr.tok, flagstr[0], &val);
    int ret = 1;
    if (status == MCMC_NOK) {
        // explicitly token not found.
        lua_pushboolean(L, 0);
    } else {
        // token found, but conversion may have failed.
        lua_pushboolean(L, 1);
        if (status == MCMC_OK) {
            lua_pushinteger(L, val);
            ret = 2;
        }
    }
    return ret;
}

// these functions take token as string or number
// if number, internally convert it to avoid creating garbage
static inline char _mcp_request_get_arg_flag(lua_State *L, int idx) {
    size_t len = 0;
    const char *flagstr = luaL_checklstring(L, idx, &len);

    if (len != 1) {
        proxy_lua_error(L, "request: meta flag must be a single character");
        return 0;
    }
    if (flagstr[0] < 65 || flagstr[0] > 122) {
        proxy_lua_error(L, "request: invalid flag, must be A-Z,a-z");
        return 0;
    }

    return flagstr[0];
}

// *tostring must be large enough to hold a 64bit number as a string.
static inline const char * _mcp_request_check_flag_token(lua_State *L, int idx, char *tostring, size_t *tlen) {
    const char *token = NULL;
    *tlen = 0;
    if (lua_isstring(L, idx)) {
        token = lua_tolstring(L, idx, tlen);
    } else if (lua_isnumber(L, idx)) {
        int isnum = 0;
        lua_Integer n = lua_tointegerx(L, idx, &isnum);
        if (isnum) {
            char *end = itoa_64(n, tostring);
            token = tostring;
            *tlen = end - tostring;
        } else {
            proxy_lua_error(L, "request: invalid flag argument");
            return NULL;
        }
    } else if (lua_isnoneornil(L, idx)) {
        // no token, just add the flag.
    } else {
        proxy_lua_error(L, "request: invalid flag argument");
        return NULL;
    }

    return token;
}

// req:flag_add("F", token) -> (bool)
// if token is "example", appends "Fexample" to request
int mcplib_request_flag_add(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    char flag = _mcp_request_get_arg_flag(L, 2);
    char tostring[30];

    if (mcmc_token_has_flag(rq->pr.request, &rq->pr.tok, flag) == MCMC_OK) {
        // fail, flag already exists.
        lua_pushboolean(L, 0);
        return 1;
    }

    size_t tlen = 0;
    const char *token = _mcp_request_check_flag_token(L, 3, tostring, &tlen);

    if (mcp_request_append(rq, flag, token, tlen) == 0) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

// req:flag_set("F", token) -> (bool) [overwrites if exists]
// if token is "example", appends "Fexample" to request
int mcplib_request_flag_set(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    char flag = _mcp_request_get_arg_flag(L, 2);
    char tostring[30];

    int x = mcmc_token_get_flag_idx(rq->pr.request, &rq->pr.tok, flag);
    size_t tlen = 0;
    const char *token = _mcp_request_check_flag_token(L, 3, tostring, &tlen);

    if (x > 0) {
        // TODO: do nothing if:
        // flag exists in request, without token, and we're not setting a
        // token.
        if (mcp_request_render(rq, x, flag, token, tlen) != 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
    } else {
        if (mcp_request_append(rq, flag, token, tlen) != 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
    }

    lua_pushboolean(L, 1);
    return 1;
}

// allows replacing a flag with a different flag
// req:flag_replace("F", "N", token) -> (bool)
// if token is "example", appends "Nexample" to request
int mcplib_request_flag_replace(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    char flag = _mcp_request_get_arg_flag(L, 2);
    char newflag = _mcp_request_get_arg_flag(L, 3);
    char tostring[30];

    int x = mcmc_token_get_flag_idx(rq->pr.request, &rq->pr.tok, flag);
    size_t tlen = 0;
    const char *token = _mcp_request_check_flag_token(L, 4, tostring, &tlen);

    if (x > 0) {
        if (mcp_request_render(rq, x, newflag, token, tlen) != 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
    } else {
        if (mcp_request_append(rq, newflag, token, tlen) != 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
    }

    lua_pushboolean(L, 1);
    return 1;
}

// req:flag_del("F") -> (bool)
// remove a flag if exists
int mcplib_request_flag_del(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    char flag = _mcp_request_get_arg_flag(L, 2);

    int x = mcmc_token_get_flag_idx(rq->pr.request, &rq->pr.tok, flag);

    if (x > 0) {
        if (mcp_request_render(rq, x, 0, NULL, 0) != 0) {
            lua_pushboolean(L, 0);
            return 1;
        }
    } else {
        // nothing there, didn't delete anything.
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_pushboolean(L, 1);
    return 1;
}

// local match, token = req:match_res(res)
// checks if req has `k` or `O`. If so, checks response for `K` or `O`
// returns true, nil if matches
// returns false, res token if not match.
static inline int _mcplib_request_match_check(lua_State *L, const char *rq, int rql, const char *rs, int rsl) {
    return (rql == rsl && memcmp(rq, rs, rsl) == 0);
}

// TODO: re-evaluate tests.
int mcplib_request_match_res(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    mcp_resp_t *rs = luaL_checkudata(L, 2, "mcp.response");

    // FIXME: we reparse the buffer because it may have changed if the old API
    // was in use? Can we skip this step now or in the future?
    mcmc_resp_t reresp;

    // requests all have keys. check for an opaque.
    int opaque_len = 0;
    const char *opaque_token = mcmc_token_get_flag(rq->pr.request, &rq->pr.tok, 'O', &opaque_len);
    mcmc_parse_buf(rs->buf, rs->blen, &reresp);
    mcmc_tokenize_res(rs->buf, reresp.reslen, &rs->tok);

    int matched = 0;
    int rs_len = 0;

    if (mcmc_token_has_flag(rs->buf, &rs->tok, 'k') == MCMC_OK) {
        const char *rs_token = mcmc_token_get_flag(rs->buf, &rs->tok, 'k', &rs_len);
        matched = _mcplib_request_match_check(L, MCP_PARSER_KEY(&rq->pr), rq->pr.klen,
                rs_token, rs_len);
        if (!matched) {
            lua_pushboolean(L, 0);
            // TODO: format string to include the keys? or at least partial?
            lua_pushstring(L, "key in response does not match request key");
            return 2;
        }
    }
    if (opaque_token) {
        if (mcmc_token_has_flag(rs->buf, &rs->tok, 'O') == MCMC_OK) {
            const char *rs_token = mcmc_token_get_flag(rs->buf, &rs->tok, 'O', &rs_len);
            matched = _mcplib_request_match_check(L, opaque_token, opaque_len,
                    rs_token, rs_len);
            if (!matched) {
                lua_pushboolean(L, 0);
                lua_pushstring(L, "request opaque does not match response opaque");
                return 2;
            }
        } else {
            lua_pushboolean(L, 0);
            // would be nice to include the opaque.
            // TODO: format string response here.
            lua_pushstring(L, "opaque in request but not in response");
            return 2;
        }
    }

    lua_pushboolean(L, matched);
    lua_pushnil(L);
    return 2;
}

void mcp_request_cleanup(LIBEVENT_THREAD *t, mcp_request_t *rq) {
    // During nread c->item is the malloc'ed buffer. not yet put into
    // rq->buf - this gets freed because we've also set c->item_malloced if
    // the connection closes before finishing nread.
    if (rq->pr.vbuf != NULL) {
        pthread_mutex_lock(&t->proxy_limit_lock);
        t->proxy_buffer_memory_used -= rq->pr.vlen;
        pthread_mutex_unlock(&t->proxy_limit_lock);
        free(rq->pr.vbuf);
        // need to ensure we NULL this out now, since we can call the cleanup
        // routine independent of GC, and a later GC would double-free.
        rq->pr.vbuf = NULL;
    }
}

int mcplib_request_gc(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    mcp_request_cleanup(t, rq);

    return 0;
}

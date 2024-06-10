/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

#define PARSER_MAXLEN USHRT_MAX-1

// Find the starting offsets of each token; ignoring length.
// This creates a fast small (<= cacheline) index into the request,
// where we later scan or directly feed data into API's.
static int _process_tokenize(mcp_parser_t *pr, const size_t max) {
    const char *s = pr->request;
    int len = pr->endlen;

    // since multigets can be huge, we can't purely judge reqlen against this
    // limit, but we also can't index past it since the tokens are shorts.
    if (len > PARSER_MAXLEN) {
        len = PARSER_MAXLEN;
    }
    const char *end = s + len;
    int curtoken = 0;

    int state = 0;
    while (s != end) {
        switch (state) {
            case 0:
                // scanning for first non-space to find a token.
                if (*s != ' ') {
                    pr->tokens[curtoken] = s - pr->request;
                    if (++curtoken == max) {
                        s++;
                        state = 2;
                        break;
                    }
                    state = 1;
                }
                s++;
                break;
            case 1:
                // advance over a token
                if (*s != ' ') {
                    s++;
                } else {
                    state = 0;
                }
                break;
            case 2:
                // hit max tokens before end of the line.
                // keep advancing so we can place endcap token.
                if (*s == ' ') {
                    goto endloop;
                }
                s++;
                break;
        }
    }
endloop:

    // endcap token so we can quickly find the length of any token by looking
    // at the next one.
    pr->tokens[curtoken] = s - pr->request;
    pr->ntokens = curtoken;
    P_DEBUG("%s: cur_tokens: %d\n", __func__, curtoken);

    return 0;
}

static int _process_token_len(mcp_parser_t *pr, size_t token) {
    const char *s = pr->request + pr->tokens[token];
    const char *e = pr->request + pr->tokens[token+1];
    // start of next token is after any space delimiters, so back those out.
    while (*(e-1) == ' ') {
        e--;
    }
    return e - s;
}

static int _process_request_key(mcp_parser_t *pr) {
    pr->klen = _process_token_len(pr, pr->keytoken);
    // advance the parser in case of multikey.
    pr->parsed = pr->tokens[pr->keytoken] + pr->klen + 1;

    if (pr->request[pr->parsed-1] == ' ') {
        P_DEBUG("%s: request_key found extra space\n", __func__);
        pr->has_space = true;
    } else {
        pr->has_space = false;
    }
    return 0;
}

// Just for ascii multiget: search for next "key" beyond where we stopped
// tokenizing before.
// Returns the offset for the next key.
size_t _process_request_next_key(mcp_parser_t *pr) {
    const char *cur = pr->request + pr->parsed;
    int remain = pr->endlen - pr->parsed;

    // chew off any leading whitespace.
    while (remain) {
        if (*cur == ' ') {
            remain--;
            cur++;
            pr->parsed++;
        } else {
            break;
        }
    }

    const char *s = memchr(cur, ' ', remain);
    if (s != NULL) {
        pr->klen = s - cur;
        pr->parsed += s - cur;
    } else {
        pr->klen = remain;
        pr->parsed += remain;
    }

    return cur - pr->request;
}

// for fast testing of existence of meta flags.
// meta has all flags as final tokens
static int _process_request_metaflags(mcp_parser_t *pr, int token) {
    if (pr->ntokens <= token) {
        pr->t.meta.flags = 0; // no flags found.
        return 0;
    }
    const char *cur = pr->request + pr->tokens[token];
    const char *end = pr->request + pr->endlen;

    // We blindly convert flags into bits, since the range of possible
    // flags is deliberately < 64.
    int state = 0;
    while (cur != end) {
        switch (state) {
            case 0:
                if (*cur == ' ') {
                    cur++;
                } else {
                    if (*cur < 65 || *cur > 122) {
                        return -1;
                    }
                    P_DEBUG("%s: setting meta flag: %d\n", __func__, *cur - 65);
                    pr->t.meta.flags |= (uint64_t)1 << (*cur - 65);
                    state = 1;
                }
                break;
            case 1:
                if (*cur != ' ') {
                    cur++;
                } else {
                    state = 0;
                }
                break;
        }
    }

    // not too great hack for noreply detection: this can be flattened out
    // once a few other contexts are fixed and we detect the noreply from the
    // coroutine start instead.
    if (pr->t.meta.flags & ((uint64_t)1 << 48)) {
        pr->noreply = true;
    }

    return 0;
}

// All meta commands are of form: "cm key f l a g S100"
static int _process_request_meta(mcp_parser_t *pr) {
    _process_tokenize(pr, PARSER_MAX_TOKENS);
    if (pr->ntokens < 2) {
        P_DEBUG("%s: not enough tokens for meta command: %d\n", __func__, pr->ntokens);
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    // pass the first flag token.
    return _process_request_metaflags(pr, 2);
}

// ms <key> <datalen> <flags>*\r\n
static int _process_request_mset(mcp_parser_t *pr) {
    _process_tokenize(pr, PARSER_MAX_TOKENS);
    if (pr->ntokens < 3) {
        P_DEBUG("%s: not enough tokens for meta set command: %d\n", __func__, pr->ntokens);
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    const char *cur = pr->request + pr->tokens[2];

    errno = 0;
    char *n = NULL;
    int vlen = strtol(cur, &n, 10);
    if ((errno == ERANGE) || (cur == n)) {
        return -1;
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
       return -1;
    }
    vlen += 2;

    pr->vlen = vlen;

    // pass the first flag token
    return _process_request_metaflags(pr, 3);
}

// gat[s] <exptime> <key>*\r\n
static int _process_request_gat(mcp_parser_t *pr) {
    _process_tokenize(pr, 3);
    if (pr->ntokens < 3) {
        P_DEBUG("%s: not enough tokens for GAT: %d\n", __func__, pr->ntokens);
        return -1;
    }

    pr->keytoken = 2;
    _process_request_key(pr);
    return 0;
}

#define NOREPLYSTR "noreply"
#define NOREPLYLEN sizeof(NOREPLYSTR)-1
// given a tokenized parser for a normal ASCII command, checks for noreply
// mode.
static int _process_request_noreply(mcp_parser_t *pr) {
    if (pr->tokens[pr->ntokens] - pr->tokens[pr->ntokens-1] >= NOREPLYLEN
            && strncmp(NOREPLYSTR, pr->request + pr->tokens[pr->ntokens-1], NOREPLYLEN) == 0) {
        pr->noreply = true;
    }
    return 0;
}

// we need t find the bytes supplied immediately so we can read the request
// from the client properly.
// set <key> <flags> <exptime> <bytes> [noreply]\r\n
static int _process_request_storage(mcp_parser_t *pr, size_t max) {
    _process_tokenize(pr, max);
    if (pr->ntokens < 5) {
        P_DEBUG("%s: not enough tokens to storage command: %d\n", __func__, pr->ntokens);
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    errno = 0;
    char *n = NULL;
    const char *cur = pr->request + pr->tokens[4];

    int vlen = strtol(cur, &n, 10);
    if ((errno == ERANGE) || (cur == n)) {
        return -1;
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
       return -1;
    }
    vlen += 2;

    pr->vlen = vlen;

    return _process_request_noreply(pr);
}

// common request with key: <cmd> <key> <args>
static int _process_request_simple(mcp_parser_t *pr, const int min, const int max) {
    _process_tokenize(pr, max);
    if (pr->ntokens < min) {
        P_DEBUG("%s: not enough tokens for simple request: %d\n", __func__, pr->ntokens);
        return -1;
    }
    pr->keytoken = 1; // second token is usually the key... stupid GAT.

    _process_request_key(pr);
    return _process_request_noreply(pr);
}

// TODO: return code ENUM with error types.
// FIXME: the mcp_parser_t bits have ended up being more fragile than I hoped.
// careful zero'ing is required. revisit?
// I think this mostly refers to recursive work (maybe just multiget?)
// Is a parser object run throgh process_request() twice, ever?
int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen) {
    // we want to "parse in place" as much as possible, which allows us to
    // forward an unmodified request without having to rebuild it.

    const char *cm = command;
    size_t cl = 0;
    // min command length is 2, plus the "\r\n"
    if (cmdlen < 4) {
        return -1;
    }

    // Commands can end with bare '\n's. Depressingly I intended to be strict
    // with a \r\n requirement but never did this and need backcompat.
    // In this case we _know_ \n is at cmdlen because we can't enter this
    // function otherwise.
    if (cm[cmdlen-2] == '\r') {
        pr->endlen = cmdlen - 2;
    } else {
        pr->endlen = cmdlen - 1;
    }

    const char *s = memchr(command, ' ', pr->endlen);
    if (s != NULL) {
        cl = s - command;
    } else {
        cl = pr->endlen;
    }
    pr->keytoken = 0;
    pr->has_space = false;
    pr->parsed = cl;
    pr->request = command;
    pr->reqlen = cmdlen;
    int token_max = PARSER_MAX_TOKENS;

    int cmd = -1;
    int type = CMD_TYPE_GENERIC;
    int ret = 0;

    switch (cl) {
        case 0:
        case 1:
            // falls through with cmd as -1. should error.
            break;
        case 2:
            if (cm[0] == 'm') {
                type = CMD_TYPE_META;
                switch (cm[1]) {
                    case 'g':
                        cmd = CMD_MG;
                        ret = _process_request_meta(pr);
                        break;
                    case 's':
                        cmd = CMD_MS;
                        ret = _process_request_mset(pr);
                        break;
                    case 'd':
                        cmd = CMD_MD;
                        ret = _process_request_meta(pr);
                        break;
                    case 'n':
                        // TODO: do we route/handle NOP's at all?
                        // they should simply reflect to the client.
                        cmd = CMD_MN;
                        break;
                    case 'a':
                        cmd = CMD_MA;
                        ret = _process_request_meta(pr);
                        break;
                    case 'e':
                        cmd = CMD_ME;
                        // TODO: not much special processing here; binary keys
                        ret = _process_request_meta(pr);
                        break;
                }
            }
            break;
        case 3:
            if (cm[0] == 'g') {
                if (cm[1] == 'e' && cm[2] == 't') {
                    cmd = CMD_GET;
                    type = CMD_TYPE_GET;
                    token_max = 2; // don't chew through multigets.
                    ret = _process_request_simple(pr, 2, 2);
                }
                if (cm[1] == 'a' && cm[2] == 't') {
                    type = CMD_TYPE_GET;
                    cmd = CMD_GAT;
                    token_max = 2; // don't chew through multigets.
                    ret = _process_request_gat(pr);
                }
            } else if (cm[0] == 's' && cm[1] == 'e' && cm[2] == 't') {
                cmd = CMD_SET;
                ret = _process_request_storage(pr, token_max);
            } else if (cm[0] == 'a' && cm[1] == 'd' && cm[2] == 'd') {
                cmd = CMD_ADD;
                ret = _process_request_storage(pr, token_max);
            } else if (cm[0] == 'c' && cm[1] == 'a' && cm[2] == 's') {
                cmd = CMD_CAS;
                ret = _process_request_storage(pr, token_max);
            }
            break;
        case 4:
            if (strncmp(cm, "gets", 4) == 0) {
                cmd = CMD_GETS;
                type = CMD_TYPE_GET;
                token_max = 2; // don't chew through multigets.
                ret = _process_request_simple(pr, 2, 2);
            } else if (strncmp(cm, "incr", 4) == 0) {
                cmd = CMD_INCR;
                ret = _process_request_simple(pr, 3, 4);
            } else if (strncmp(cm, "decr", 4) == 0) {
                cmd = CMD_DECR;
                ret = _process_request_simple(pr, 3, 4);
            } else if (strncmp(cm, "gats", 4) == 0) {
                cmd = CMD_GATS;
                type = CMD_TYPE_GET;
                ret = _process_request_gat(pr);
            } else if (strncmp(cm, "quit", 4) == 0) {
                cmd = CMD_QUIT;
            }
            break;
        case 5:
            if (strncmp(cm, "touch", 5) == 0) {
                cmd = CMD_TOUCH;
                ret = _process_request_simple(pr, 3, 4);
            } else if (strncmp(cm, "stats", 5) == 0) {
                cmd = CMD_STATS;
                // Don't process a key; fetch via arguments.
                _process_tokenize(pr, token_max);
            } else if (strncmp(cm, "watch", 5) == 0) {
                cmd = CMD_WATCH;
                _process_tokenize(pr, token_max);
            }
            break;
        case 6:
            if (strncmp(cm, "delete", 6) == 0) {
                cmd = CMD_DELETE;
                ret = _process_request_simple(pr, 2, 4);
            } else if (strncmp(cm, "append", 6) == 0) {
                cmd = CMD_APPEND;
                ret = _process_request_storage(pr, token_max);
            }
            break;
        case 7:
            if (strncmp(cm, "replace", 7) == 0) {
                cmd = CMD_REPLACE;
                ret = _process_request_storage(pr, token_max);
            } else if (strncmp(cm, "prepend", 7) == 0) {
                cmd = CMD_PREPEND;
                ret = _process_request_storage(pr, token_max);
            } else if (strncmp(cm, "version", 7) == 0) {
                cmd = CMD_VERSION;
                _process_tokenize(pr, token_max);
            }
            break;
    }

    // TODO: log more specific error code.
    if (cmd == -1 || ret != 0) {
        return -1;
    }

    pr->command = cmd;
    pr->cmd_type = type;

    return 0;
}

// FIXME (v2): any reason to pass in command/cmdlen separately?
mcp_request_t *mcp_new_request(lua_State *L, mcp_parser_t *pr, const char *command, size_t cmdlen) {
    // reserving an upvalue for key.
    mcp_request_t *rq = lua_newuserdatauv(L, sizeof(mcp_request_t) + MCP_REQUEST_MAXLEN + KEY_MAX_LENGTH, 1);
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
    if (idx >= pr->ntokens) {
        return -1;
    }

    memcpy(p, pr->request, pr->tokens[idx]);
    p += pr->tokens[idx];

    if (flag) {
        *p = flag;
        p++;
    }
    if (tok) {
        memcpy(p, tok, len);
        p += len;
    }

    // Add a space and copy more tokens if there were more.
    if (idx+1 < pr->ntokens) {
        if (flag || len != 0) {
            // Only pre-space if not deleting the token.
            *p = ' ';
            p++;
        }
        memcpy(p, &pr->request[pr->tokens[idx+1]], pr->tokens[pr->ntokens] - pr->tokens[idx+1]);
        p += pr->tokens[pr->ntokens] - pr->tokens[idx+1];
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
    lua_pushlstring(L, MCP_PARSER_KEY(rq->pr), rq->pr.klen);
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
    char *key = (char *) MCP_PARSER_KEY(rq->pr);

    if (totrim > rq->pr.klen) {
        proxy_lua_error(L, "ltrimkey cannot zero out key");
        return 0;
    } else {
        memset(key, ' ', totrim);
        rq->pr.klen -= totrim;
        rq->pr.tokens[rq->pr.keytoken] += totrim;
    }
    return 1;
}

int mcplib_request_rtrimkey(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -2, "mcp.request");
    int totrim = luaL_checkinteger(L, -1);
    char *key = (char *) MCP_PARSER_KEY(rq->pr);

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

// Virtual table operations on the request.
int mcplib_request_token(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    int argc = lua_gettop(L);

    if (argc == 1) {
        lua_pushnil(L);
        return 1;
    }

    int token = luaL_checkinteger(L, 2);

    if (token < 1 || token > rq->pr.ntokens) {
        // maybe an error?
        lua_pushnil(L);
        return 1;
    }

    size_t vlen = 0;
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
        const char *start = rq->pr.request + rq->pr.tokens[token-1];
        vlen = _process_token_len(&rq->pr, token-1);

        P_DEBUG("%s: pushing token of len: %lu\n", __func__, vlen);
        lua_pushlstring(L, start, vlen);
        return 1;
    }

    return 0;
}

int mcplib_request_ntokens(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    lua_pushinteger(L, rq->pr.ntokens);
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
    if (flagstr[0] < 65 || flagstr[0] > 122) {
        proxy_lua_error(L, "has_flag(): invalid flag, must be A-Z,a-z");
        return 0;
    }
    uint64_t flagbit = (uint64_t)1 << (flagstr[0] - 65);
    if (rq->pr.t.meta.flags & flagbit) {
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
    if (flagstr[0] < 65 || flagstr[0] > 122) {
        proxy_lua_error(L, "has_flag(): invalid flag, must be A-Z,a-z");
        return 0;
    }
    if (lua_isstring(L, 3)) {
        // overwriting a flag/token with the third argument.
        replace = true;
    }
    uint64_t flagbit = (uint64_t)1 << (flagstr[0] - 65);

    int ret = 1;
    if (rq->pr.t.meta.flags & flagbit) {
        // The flag definitely exists, but sadly we need to scan for the
        // actual flag to see if it has a token.
        lua_pushboolean(L, 1);
        for (int x = rq->pr.keytoken+1; x < rq->pr.ntokens; x++) {
            const char *s = rq->pr.request + rq->pr.tokens[x];
            if (s[0] == flagstr[0]) {
                size_t vlen = _process_token_len(&rq->pr, x);
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

    uint64_t flagbit = (uint64_t)1 << (flag - 65);
    if (rq->pr.t.meta.flags & flagbit) {
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

    int x = mcp_request_find_flag_index(rq, flag);
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

    int x = mcp_request_find_flag_index(rq, flag);
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

    int x = mcp_request_find_flag_index(rq, flag);

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
//
int mcplib_request_match_res(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    mcp_resp_t *rs = luaL_checkudata(L, 2, "mcp.response");

    const char *opaque_token = NULL;
    size_t opaque_len = 0;

    // requests all have keys. check for an opaque.
    mcp_request_find_flag_token(rq, 'O', &opaque_token, &opaque_len);

    // scan the response line for tokens, since we don't have a reciprocal API
    // yet. When we do this code will be replaced with a function call like
    // the above.
    const char *p = rs->resp.rline;
    // TODO: Think this is an off-by-one in mcmc.
    const char *e = p + rs->resp.rlen - 1;
    if (!p) {
        // happens if the result line is blank (ie; 'HD\r\n')
        lua_pushboolean(L, 0);
        lua_pushnil(L);
        return 2;
    }

    int matched = 0;
    while (p != e) {
        if (*p == ' ') {
            p++;
        } else if (*p == 'k' || *p == 'O') {
            const char *rq_token = NULL;
            int rq_len = 0;
            if (*p == 'k') {
                rq_token = MCP_PARSER_KEY(rq->pr);
                rq_len = rq->pr.klen;
            } else if (*p == 'O') {
                rq_token = opaque_token;
                rq_len = opaque_len;
            }
            if (rq_token == NULL) {
                lua_pushboolean(L, 0);
                lua_pushnil(L);
                return 2;
            }

            p++; // skip flag and start comparing token
            const char *rs_token = p;

            // find end of token
            while (p != e && !isspace(*p)) {
                p++;
            }

            int rs_len = p - rs_token;
            if (rq_len != rs_len || memcmp(rq_token, rs_token, rs_len) != 0) {
                // FAIL, keys aren't the same length or don't match.
                lua_pushboolean(L, 0);
                lua_pushlstring(L, rs_token, rs_len);
                return 2;
            } else {
                matched = 1;
            }
        } else {
            // skip token
            while (p != e && *p != ' ') {
                p++;
            }
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

static int _mcp_request_find_flag(mcp_request_t *rq, const char flag) {
    uint64_t flagbit = (uint64_t)1 << (flag - 65);
    if (rq->pr.t.meta.flags & flagbit) {
        for (int x = rq->pr.keytoken+1; x < rq->pr.ntokens; x++) {
            const char *s = rq->pr.request + rq->pr.tokens[x];
            if (s[0] == flag) {
                return x;
            }
        }
    }
    return -1;
}

int mcp_request_find_flag_index(mcp_request_t *rq, const char flag) {
    int x = _mcp_request_find_flag(rq, flag);
    return x;
}

int mcp_request_find_flag_token(mcp_request_t *rq, const char flag, const char **token, size_t *len) {
    int x = _mcp_request_find_flag(rq, flag);
    if (x > 0) {
        size_t tlen = _process_token_len(&rq->pr, x);
        if (tlen > 1) {
            *token = rq->pr.request + rq->pr.tokens[x] +1;
        } else {
            *token = NULL;
        }
        *len = tlen-1;
    }
    return x;
}

// TODO (v2): check what lua does when it calls a function with a string argument
// stored from a table/similar (ie; the prefix check code).
// If it's not copying anything, we can add request-side functions to do most
// forms of matching and avoid copying the key to lua space.

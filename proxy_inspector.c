/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

enum mcp_ins_type {
    INS_REQ = 1,
    INS_RES,
};

enum mcp_ins_steptype {
    mcp_ins_step_none = 0,
    mcp_ins_step_sepkey,
    mcp_ins_step_keybegin,
    mcp_ins_step_keyis,
    mcp_ins_step_hasflag,
    mcp_ins_step_flagtoken,
    mcp_ins_step_flagint,
    mcp_ins_step_flagis,
    mcp_ins_step_final, // not used.
};

// START STEP STRUCTS

struct mcp_ins_sepkey {
    char sep;
    int pos;
    int mapref;
};

struct mcp_ins_string {
    unsigned int str; // arena offset for match string.
    unsigned int len;
};

struct mcp_ins_flag {
    uint64_t bit; // flag converted for bitmask test
    char f;
};

// TODO: it might make more sense to flatten the structs into the ins_step
// struct. It wouldn't take much more space if we can be careful with
// alignment.
struct mcp_ins_flagstr {
    unsigned int str;
    unsigned int len;
    uint64_t bit; // flag bit
    char f;
};

struct mcp_ins_step {
    enum mcp_ins_steptype type;
    union {
        struct mcp_ins_sepkey sepkey;
        struct mcp_ins_string string;
        struct mcp_ins_flag flag;
        struct mcp_ins_flagstr flagstr;
    } c;
};

// END STEP STRUCTS

struct mcp_inspector {
    enum mcp_ins_type type;
    int scount;
    unsigned int aused; // arena memory used
    unsigned int rcount; // number of results to expect
    char *arena; // string/data storage for steps
    struct mcp_ins_step steps[];
};

// PRIVATE INTERFACE

#define res_buf(r) (r->cresp ? r->cresp->iov[0].iov_base : r->buf)

// COMMON ARG HANDLERS

// multiple step types only take 'flag' as an argument.
static int mcp_inspector_flag_c_g(lua_State *L, int tidx) {
    if (lua_getfield(L, tidx, "flag") != LUA_TNIL) {
        size_t len = 0;
        const char *flag = lua_tolstring(L, -1, &len);
        if (len != 1) {
            proxy_lua_ferror(L, "inspector step %d: 'flag' must be a single character", tidx);
        }
        if (mcp_is_flag_invalid(flag[0])) {
            proxy_lua_ferror(L, "inspect step %d: 'flag' must be alphanumeric", tidx);
        }
    } else {
        proxy_lua_ferror(L, "inspector step %d: must provide 'flag' argument", tidx);
    }
    lua_pop(L, 1); // val or nil
    return 0;
}

static int mcp_inspector_flag_i_g(lua_State *L, int tidx, int sc, struct mcp_inspector *ins) {
    struct mcp_ins_step *s = &ins->steps[sc];
    struct mcp_ins_flag *c = &s->c.flag;

    if (lua_getfield(L, tidx, "flag") != LUA_TNIL) {
        const char *flag = lua_tostring(L, -1);
        c->f = flag[0];
        c->bit = (uint64_t)1 << (c->f - 65);
    }
    lua_pop(L, 1); // val or nil

    return 0;
}

static int mcp_inspector_string_c_g(lua_State *L, int tidx) {
    size_t len = 0;

    if (lua_getfield(L, tidx, "str") != LUA_TNIL) {
        lua_tolstring(L, -1, &len);
        if (len < 1) {
            proxy_lua_ferror(L, "inspector step %d: 'str' must have nonzero length", tidx);
        }
    } else {
        proxy_lua_ferror(L, "inspector step %d: must provide 'str' argument", tidx);
    }
    lua_pop(L, 1); // val or nil

    return len;
}

static int mcp_inspector_string_i_g(lua_State *L, int tidx, int sc, struct mcp_inspector *ins) {
    struct mcp_ins_step *s = &ins->steps[sc];
    struct mcp_ins_string *c = &s->c.string;
    size_t len = 0;

    // store our match string in the arena space that we reserved before.
    if (lua_getfield(L, tidx, "str") != LUA_TNIL) {
        const char *str = lua_tolstring(L, -1, &len);
        c->str = ins->aused;
        c->len = len;
        char *a = ins->arena + ins->aused;
        memcpy(a, str, len);
        ins->aused += len;
    }
    lua_pop(L, 1); // val or nil

    return len;
}

// END COMMMON ARG HANDLERS

static int mcp_inspector_sepkey_c(lua_State *L, int tidx) {
    if (lua_getfield(L, tidx, "sep") != LUA_TNIL) {
        size_t len = 0;
        lua_tolstring(L, -1, &len);
        if (len != 1) {
            proxy_lua_ferror(L, "inspector step %d: separator must be one character", tidx);
        }
    }
    lua_pop(L, 1); // val or nil

    if (lua_getfield(L, tidx, "pos") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TNUMBER);
    }
    lua_pop(L, 1); // val or nil

    if (lua_getfield(L, tidx, "map") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TTABLE);
    }
    lua_pop(L, 1); // val or nil

    return 0;
}

// initializer. arguments already checked, so just fill out the slot.
static int mcp_inspector_sepkey_i(lua_State *L, int tidx, int sc, struct mcp_inspector *ins) {
    struct mcp_ins_step *s = &ins->steps[sc];
    struct mcp_ins_sepkey *c = &s->c.sepkey;

    if (lua_getfield(L, tidx, "sep") != LUA_TNIL) {
        const char *sep = lua_tostring(L, -1);
        c->sep = sep[0];
    } else {
        // default separator
        c->sep = '/';
    }
    lua_pop(L, 1); // val or nil

    if (lua_getfield(L, tidx, "pos") != LUA_TNIL) {
        c->pos = lua_tointeger(L, -1);
    } else {
        c->pos = 1;
    }
    lua_pop(L, 1);

    if (lua_getfield(L, tidx, "map") != LUA_TNIL) {
        c->mapref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        c->mapref = 0;
        lua_pop(L, 1);
    }
    // ref was popped

    return 0;
}

// TODO: abstract out the token-position-finder
static int mcp_inspector_sepkey_r(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg) {
    mcp_request_t *rq = arg;
    struct mcp_ins_sepkey *c = &s->c.sepkey;

    const char *key = MCP_PARSER_KEY(rq->pr);
    const char *end = key + rq->pr.klen;
    char sep = c->sep;
    int pos = c->pos;

    // skip initial separators
    while (key != end) {
        if (*key == sep) {
            key++;
        } else {
            break;
        }
    }
    const char *token = key;
    int tlen = 0;

    while (key != end) {
        if (*key == sep) {
            // measure token length and stop if at position.
            if (--pos == 0) {
                tlen = key - token;
                break;
            } else {
                // NOTE: this could point past the end of the key, but unless
                // it's the token we want we won't look at it.
                token = key+1;
            }
        }
        key++;
    }

    // either the separator was never found, or we ended before finding
    // another one, which gives us an end token.
    if (pos == 1) {
        tlen = key - token;
    }

    // now have *token and tlen
    if (tlen != 0) {
        if (c->mapref) {
            // look up this string against the map.
            // NOTE: this still ends up creating a garbage string. However,
            // since the map is internal we can optimize this later by moving
            // the map lookup op to C.
            lua_rawgeti(L, LUA_REGISTRYINDEX, c->mapref);
            lua_pushlstring(L, token, tlen);
            lua_rawget(L, -2); // pops string.
            lua_remove(L, -2); // removes map, shifts lookup result down.
            // stack should be clean: just the result.
        } else {
            // no map, return the actual token.
            lua_pushlstring(L, token, tlen);
        }
    } else {
        lua_pushnil(L); // not found.
    }

    return 1;
}

static int mcp_inspector_keybegin_r(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg) {
    mcp_request_t *rq = arg;
    struct mcp_ins_string *c = &s->c.string;

    const char *key = MCP_PARSER_KEY(rq->pr);
    int klen = rq->pr.klen;
    const char *str = ins->arena + c->str;

    if (c->len < klen && strncmp(key, str, c->len) == 0) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int mcp_inspector_keyis_r(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg) {
    mcp_request_t *rq = arg;
    struct mcp_ins_string *c = &s->c.string;

    const char *key = MCP_PARSER_KEY(rq->pr);
    int klen = rq->pr.klen;
    const char *str = ins->arena + c->str;

    if (c->len == klen && strncmp(key, str, c->len) == 0) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int mcp_inspector_hasflag_r(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg) {
    struct mcp_ins_flag *c = &s->c.flag;
    if (ins->type == INS_REQ) {
        mcp_request_t *rq = arg;
        // requests should always be tokenized, so we can just check the bit.
        if (rq->pr.t.meta.flags & c->bit) {
            lua_pushboolean(L, 1);
        } else {
            lua_pushboolean(L, 0);
        }
    } else {
        mcp_resp_t *res = arg;
        if (res->resp.type == MCMC_RESP_META) {
            // result object may not be tokenized. this will do so if not
            // already. any future hits agains the same object will use the
            // cached tokenizer struct.
            mcmc_tokenize_res(res_buf(res), res->resp.reslen, &res->tok);
            if (mcmc_token_has_flag_bit(&res->tok, c->bit) == MCMC_OK) {
                lua_pushboolean(L, 1);
            } else {
                lua_pushboolean(L, 0);
            }
        } else {
            proxy_lua_error(L, "inspector error: response is not meta protocol");
        }
    }
    return 1;
}

// This mirrors `bool, (str|nil) = r:flag_token("T")`
static int mcp_inspector_flagtoken_r(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg) {
    struct mcp_ins_flag *c = &s->c.flag;
    if (ins->type == INS_REQ) {
        mcp_request_t *rq = arg;

        if (rq->pr.t.meta.flags & c->bit) {
            lua_pushboolean(L, 1); // flag exists
            const char *tok = NULL;
            size_t tlen = 0;
            mcp_request_find_flag_token(rq, c->f, &tok, &tlen);
            lua_pushlstring(L, tok, tlen); // flag's token
            return 2;
        }
    } else {
        mcp_resp_t *res = arg;
        if (res->resp.type == MCMC_RESP_META) {
            mcmc_tokenize_res(res_buf(res), res->resp.reslen, &res->tok);
            if (mcmc_token_has_flag_bit(&res->tok, c->bit) == MCMC_OK) {
                lua_pushboolean(L, 1); // flag exists
                int tlen = 0;
                const char *tok = mcmc_token_get_flag(res_buf(res), &res->tok, c->f, &tlen);
                lua_pushlstring(L, tok, tlen); // flag's token
                return 2;
            }
        }
    }
    lua_pushboolean(L, 0);
    lua_pushnil(L);

    return 2;
}

// TODO: flaguint variant?
// still stuck as signed in lua but would reject signed tokens
static int mcp_inspector_flagint_r(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg) {
    struct mcp_ins_flag *c = &s->c.flag;
    if (ins->type == INS_REQ) {
        mcp_request_t *rq = arg;

        if (rq->pr.t.meta.flags & c->bit) {
            lua_pushboolean(L, 1); // flag exists
            int64_t tok = 0;
            if (mcp_request_find_flag_tokenint64(rq, c->f, &tok) == 0) {
                lua_pushinteger(L, tok);
            } else {
                lua_pushnil(L);
            }
            return 2;
        }
    } else {
        mcp_resp_t *res = arg;
        if (res->resp.type == MCMC_RESP_META) {
            mcmc_tokenize_res(res_buf(res), res->resp.reslen, &res->tok);
            if (mcmc_token_has_flag_bit(&res->tok, c->bit) == MCMC_OK) {
                lua_pushboolean(L, 1); // flag exists
                int64_t tok = 0;
                if (mcmc_token_get_flag_64(res_buf(res), &res->tok, c->f, &tok) == MCMC_OK) {
                    lua_pushinteger(L, tok);
                } else {
                    lua_pushnil(L); // token couldn't be converted
                }
                return 2;
            }
        }
    }
    lua_pushboolean(L, 0);
    lua_pushnil(L);

    return 2;
}

static int mcp_inspector_flagstr_c(lua_State *L, int tidx) {
    mcp_inspector_flag_c_g(L, tidx);
    int size = mcp_inspector_string_c_g(L, tidx);
    return size;
}

static int mcp_inspector_flagstr_i(lua_State *L, int tidx, int sc, struct mcp_inspector *ins) {
    // TODO: if we never use mcp_ins_step we can remove it and just pass parts
    // of the relevant structs down into these functions.
    struct mcp_ins_step *s = &ins->steps[sc];
    struct mcp_ins_flagstr *c = &s->c.flagstr;
    size_t len = 0;

    if (lua_getfield(L, tidx, "flag") != LUA_TNIL) {
        const char *flag = lua_tostring(L, -1);
        c->f = flag[0];
        c->bit = (uint64_t)1 << (c->f - 65);
    }
    lua_pop(L, 1); // val or nil

    if (lua_getfield(L, tidx, "str") != LUA_TNIL) {
        const char *str = lua_tolstring(L, -1, &len);
        c->str = ins->aused;
        c->len = len;
        char *a = ins->arena + ins->aused;
        memcpy(a, str, len);
        ins->aused += len;
    }
    lua_pop(L, 1); // val or nil

    return len;
}

// FIXME: size_t vs int consistency for tlen would shorten the code.
static int mcp_inspector_flagis_r(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg) {
    struct mcp_ins_flagstr *c = &s->c.flagstr;
    const char *str = ins->arena + c->str;
    if (ins->type == INS_REQ) {
        mcp_request_t *rq = arg;

        if (rq->pr.t.meta.flags & c->bit) {
            lua_pushboolean(L, 1); // flag exists
            const char *tok = NULL;
            size_t tlen = 0;
            mcp_request_find_flag_token(rq, c->f, &tok, &tlen);
            if (tlen == c->len && strncmp(tok, str, c->len) == 0) {
                lua_pushboolean(L, 1);
            } else {
                lua_pushboolean(L, 0);
            }
            return 2;
        }
    } else {
        mcp_resp_t *res = arg;
        if (res->resp.type == MCMC_RESP_META) {
            mcmc_tokenize_res(res_buf(res), res->resp.reslen, &res->tok);
            if (mcmc_token_has_flag_bit(&res->tok, c->bit) == MCMC_OK) {
                lua_pushboolean(L, 1); // flag exists
                int tlen = 0;
                const char *tok = mcmc_token_get_flag(res_buf(res), &res->tok, c->f, &tlen);
                if (tlen == c->len && strncmp(tok, str, c->len) == 0) {
                    lua_pushboolean(L, 1);
                } else {
                    lua_pushboolean(L, 0);
                }
                return 2;
            }
        }
    }
    lua_pushboolean(L, 0);
    lua_pushnil(L);

    return 2;
}

// END STEPS

typedef int (*mcp_ins_c)(lua_State *L, int tidx);
typedef int (*mcp_ins_i)(lua_State *L, int tidx, int sc, struct mcp_inspector *ins);
typedef int (*mcp_ins_r)(lua_State *L, struct mcp_inspector *ins, struct mcp_ins_step *s, void *arg);

struct mcp_ins_entry {
    const char *s; // string name
    mcp_ins_c c;
    mcp_ins_i i;
    mcp_ins_r r;
    unsigned int t; // allowed object types
    int n; // number of results to expect
};

static const struct mcp_ins_entry mcp_ins_entries[] = {
    [mcp_ins_step_none] = {NULL, NULL, NULL, NULL, 0, 0},
    [mcp_ins_step_sepkey] = {"sepkey", mcp_inspector_sepkey_c, mcp_inspector_sepkey_i, mcp_inspector_sepkey_r, INS_REQ, 1},
    [mcp_ins_step_keybegin] = {"keybegin", mcp_inspector_string_c_g, mcp_inspector_string_i_g, mcp_inspector_keybegin_r, INS_REQ, 1},
    [mcp_ins_step_keyis] = {"keyis", mcp_inspector_string_c_g, mcp_inspector_string_i_g, mcp_inspector_keyis_r, INS_REQ, 1},
    [mcp_ins_step_hasflag] = {"hasflag", mcp_inspector_flag_c_g, mcp_inspector_flag_i_g, mcp_inspector_hasflag_r, INS_REQ|INS_RES, 1},
    [mcp_ins_step_flagtoken] = {"flagtoken", mcp_inspector_flag_c_g, mcp_inspector_flag_i_g, mcp_inspector_flagtoken_r, INS_REQ|INS_RES, 2},
    [mcp_ins_step_flagint] = {"flagint", mcp_inspector_flag_c_g, mcp_inspector_flag_i_g, mcp_inspector_flagint_r, INS_REQ|INS_RES, 2},
    [mcp_ins_step_flagis] = {"flagis", mcp_inspector_flagstr_c, mcp_inspector_flagstr_i, mcp_inspector_flagis_r, INS_REQ|INS_RES, 2},
};

// call with type string on top
static enum mcp_ins_steptype mcp_inspector_steptype(lua_State *L) {
    const char *type = luaL_checkstring(L, -1);
    for (int x = 0; x < mcp_ins_step_final; x++) {
        const struct mcp_ins_entry *e = &mcp_ins_entries[x];
        if (e->s && strcmp(type, e->s) == 0) {
            return x;
        }
    }
    return mcp_ins_step_none;
}

// - arguments given as list of tables:
//   { t = "type", arg = "bar", etc },
//   { etc }
//   - can take table-of-tables via: mcp.req_inspector_new(table.unpack(args))
// NOTES:
// - can we inline necessary strings/etc via extra allocated memory?
// - can we get mcp.inspector metatable into the upvalue of the _call and _gc
// funcs for fast-compare?
static int mcp_inspector_new(lua_State *L, enum mcp_ins_type type) {
    int argc = lua_gettop(L);
    size_t size = 0;
    int scount = 0;

    // loop argument tables once for validation and pre-calculations.
    for (int x = 1; x <= argc; x++) {
        luaL_checktype(L, x, LUA_TTABLE);
        if (lua_getfield(L, x, "t") != LUA_TNIL) {
            enum mcp_ins_steptype st = mcp_inspector_steptype(L);
            const struct mcp_ins_entry *e = &mcp_ins_entries[st];
            if (!(e->t & type)) {
                proxy_lua_ferror(L, "inspector step %d: step incompatible with inspector type", x);
            }
            if ((st == mcp_ins_step_none) || e->c == NULL) {
                proxy_lua_ferror(L, "inspector step %d: unknown step type", x);
            }
            size += e->c(L, x);
        }
        lua_pop(L, 1); // drop 't' or nil
        scount++;
    }

    // we now know the size and number of steps. allocate some flat memory.

    // TODO: we need memory for steps + arbitrary step data. (ie; string stems
    // and the like)
    // - now: single extra malloc, divvy out the buffer as requested
    // - later: if alignment of the flexible step array can be reliably
    // determined (C11 alignas or etc), inline memory can be used instead.
    size_t extsize = sizeof(struct mcp_ins_step) * scount;
    struct mcp_inspector *ins = lua_newuserdatauv(L, sizeof(*ins) + extsize, 1);
    memset(ins, 0, sizeof(*ins));

    ins->arena = malloc(size);
    if (ins->arena == NULL) {
        proxy_lua_error(L, "mcp.req_inspector_new: failed to allocate memory");
    }

    luaL_setmetatable(L, "mcp.inspector");
    switch (type) {
        case INS_REQ:
            luaL_getmetatable(L, "mcp.request");
            break;
        case INS_RES:
            luaL_getmetatable(L, "mcp.response");
            break;
    }
    // set metatable to the upvalue for a fast comparison during __call
    lua_setiuservalue(L, -2, 1);
    ins->type = type;

    // loop the arg tables again to fill in the steps
    // skip checks since we did that during the first loop.
    scount = 0;
    for (int x = 1; x <= argc; x++) {
        if (lua_getfield(L, x, "t") != LUA_TNIL) {
            enum mcp_ins_steptype st = mcp_inspector_steptype(L);
            ins->steps[scount].type = st;
            mcp_ins_entries[st].i(L, x, scount, ins);
            ins->rcount += mcp_ins_entries[st].n;
        }
        lua_pop(L, 1); // drop t or nil
        scount++;
    }

    if (size != ins->aused) {
        proxy_lua_error(L, "inspector failed to properly initialize, memory not filled correctly");
    }
    ins->scount = scount;

    return 1;
}

static int mcp_ins_run(lua_State *L, struct mcp_inspector *ins, void *arg) {
    int ret = 0;

    for (int x = 0; x < ins->scount; x++) {
        struct mcp_ins_step *s = &ins->steps[x];
        assert(s->type != mcp_ins_step_none);
        ret += mcp_ins_entries[s->type].r(L, ins, s, arg);
    }

    return ret;
}

// PUBLIC INTERFACE

int mcplib_req_inspector_new(lua_State *L) {
    return mcp_inspector_new(L, INS_REQ);
}

int mcplib_res_inspector_new(lua_State *L) {
    return mcp_inspector_new(L, INS_RES);
}

// walk each step and free references/memory/etc
int mcplib_inspector_gc(lua_State *L) {
    struct mcp_inspector *ins = lua_touserdata(L, 1);

    if (ins->arena) {
        free(ins->arena);
        ins->arena = NULL;
    }

    for (int x = 0; x < ins->scount; x++) {
        struct mcp_ins_step *s = &ins->steps[x];
        switch (s->type) {
            case mcp_ins_step_sepkey:
                if (s->c.sepkey.mapref) {
                    luaL_unref(L, LUA_REGISTRYINDEX, s->c.sepkey.mapref);
                    s->c.sepkey.mapref = 0;
                }
                break;
            case mcp_ins_step_keybegin:
            case mcp_ins_step_keyis:
            case mcp_ins_step_hasflag:
            case mcp_ins_step_flagtoken:
            case mcp_ins_step_flagint:
            case mcp_ins_step_flagis:
            case mcp_ins_step_none:
            case mcp_ins_step_final:
                break;
        }
    }

    return 0;
}

// - iterate steps, call function callbacks with as context arg
// TODO:
// - second arg _may_ be a table: in which case we fill the results into this
//   table rather than return them directly.
//   - do this via a different run function that pops each step result?
int mcplib_inspector_call(lua_State *L) {
    // since we're here from a __call, assume the type is correct.
    struct mcp_inspector *ins = lua_touserdata(L, 1);
    luaL_checktype(L, 2, LUA_TUSERDATA);
    if (lua_checkstack(L, ins->rcount) == 0) {
        proxy_lua_error(L, "inspector ran out of stack space for results");
    }

    // luaL_checkudata() is slow. Trying a new method here where we pull the
    // metatable from a reference then compare it against the meta table of
    // the argument object.
    lua_getmetatable(L, 2); // put arg metatable on stack
    lua_getiuservalue(L, 1, 1); // put stashed metatable on stack
    luaL_argcheck(L, lua_rawequal(L, -1, -2), 2,
            "invalid argument to inspector object");
    lua_pop(L, 2); // toss both metatables

    // we're valid now. run the steps
    void *arg = lua_touserdata(L, 2);
    return mcp_ins_run(L, ins, arg);
}

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

/*
 * !!!WARNING!!!
 * This is an experimental interface and is not to be used in production until
 * after this warning has been removed.
 * The req/res mutator system is currently an experimental draft, merged to
 * allow code experiments and further information gathering before completing
 * the interface.
 *
 */

// space or \r\n
#define MIN_BUF_SPACE 2

enum mcp_mut_type {
    MUT_REQ = 1,
    MUT_RES,
};

enum mcp_mut_steptype {
    mcp_mut_step_none = 0,
    mcp_mut_step_cmdset,
    mcp_mut_step_cmdcopy,
    mcp_mut_step_keycopy,
    mcp_mut_step_keyset,
    mcp_mut_step_rescodeset,
    mcp_mut_step_rescodecopy,
    mcp_mut_step_reserr,
    mcp_mut_step_flagset,
    mcp_mut_step_flagcopy,
    mcp_mut_step_valcopy,
    mcp_mut_step_final, // not used.
};

// START STEP STRUCTS

// struct forward declarations for entry/step function pointers
struct mcp_mut_step;
struct mcp_mutator;
struct mcp_mut_run;
struct mcp_mut_part;

typedef int (*mcp_mut_c)(lua_State *L, int tidx);
typedef int (*mcp_mut_i)(lua_State *L, int tidx, int sc, struct mcp_mutator *mut);
typedef int (*mcp_mut_n)(struct mcp_mut_run *run, struct mcp_mut_step *s, struct mcp_mut_part *p);
typedef void (*mcp_mut_r)(struct mcp_mut_run *run, struct mcp_mut_step *s, struct mcp_mut_part *p);

struct mcp_mut_entry {
    const char *s; // string name
    mcp_mut_c c; // argument checker
    mcp_mut_i i; // argument initializer
    mcp_mut_n n; // runtime length totaller
    mcp_mut_r r; // runtime assembly
    unsigned int t; // allowed object types
    int rc; // number of results to expect
};

struct mcp_mut_string {
    unsigned int str; // arena offset for match string.
    unsigned int len;
};

struct mcp_mut_flag {
    uint64_t bit; // flag converted for bitmask test
    char f;
};

#define RESERR_ERROR 1
#define RESERR_ERROR_STR "ERROR"
#define RESERR_CLIENT 2
#define RESERR_CLIENT_STR "CLIENT_ERROR"
#define RESERR_SERVER 3
#define RESERR_SERVER_STR "SERVER_ERROR"

struct mcp_mut_flagval {
    struct mcp_mut_flag flag;
    struct mcp_mut_string str;
};

struct mcp_mut_step {
    enum mcp_mut_steptype type;
    unsigned int idx; // common: input argument position
    mcp_mut_n n; // totaller function
    mcp_mut_r r; // data copy function
    union {
        struct mcp_mut_string string;
        struct mcp_mut_flag flag;
        struct mcp_mut_flagval flagval;
    } c;
};

// END STEP STRUCTS

struct mcp_mutator {
    enum mcp_mut_type type;
    int scount;
    unsigned int aused; // arena memory used
    unsigned int rcount; // number of results to expect
    char *arena; // string/data storage for steps
    struct mcp_mut_step steps[];
};

// scratch space for steps between total and execution stages.
struct mcp_mut_part {
    const char *src;
    size_t slen;
};

// stack scratch variables for mutation execution
struct mcp_mut_run {
    lua_State *L;
    struct mcp_mutator *mut;
    void *arg;
    char *numbuf; // stack space for rendering numerics
    char *d_pos; // current offset to the write string.

    const char *vbuf; // buffer or ptr if a value is being attached
    size_t vlen; // length of the actual value buffer.
};

#define mut_step_c(n) static int mcp_mutator_##n##_c(lua_State *L, int tidx)
#define mut_step_i(n) static int mcp_mutator_##n##_i(lua_State *L, int tidx, int sc, struct mcp_mutator *mut)
#define mut_step_r(n) static void mcp_mutator_##n##_r(struct mcp_mut_run *run, struct mcp_mut_step *s, struct mcp_mut_part *p)
#define mut_step_n(n) static int mcp_mutator_##n##_n(struct mcp_mut_run *run, struct mcp_mut_step *s, struct mcp_mut_part *p)

// PRIVATE INTERFACE

// COMMON ARG HANDLERS

static void _mut_check_idx(lua_State *L, int tidx) {
    if (lua_getfield(L, tidx, "idx") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TNUMBER);
        int isnum = 0;
        lua_Integer i = lua_tointegerx(L, -1, &isnum);
        if (!isnum) {
            proxy_lua_ferror(L, "mutator step %d: must provide 'idx' argument as an integer", tidx);
        }
        if (i < 1) {
            proxy_lua_ferror(L, "mutator step %d: 'idx' argument must be greater than 0", tidx);
        }
    } else {
        proxy_lua_ferror(L, "mutator step %d: must provide 'idx' argument", tidx);
    }
    lua_pop(L, 1);
}

static size_t _mut_check_strlen(lua_State *L, int tidx, const char *n) {
    size_t len = 0;

    if (lua_getfield(L, tidx, n) != LUA_TNIL) {
        lua_tolstring(L, -1, &len);
    } else {
        proxy_lua_ferror(L, "mutator step %d: must provide '%s' argument", tidx, n);
    }
    lua_pop(L, 1);

    return len;
}

static void _mut_check_flag(lua_State *L, int tidx) {
    if (lua_getfield(L, tidx, "flag") != LUA_TNIL) {
        size_t len = 0;
        const char *flag = lua_tolstring(L, -1, &len);
        if (len != 1) {
            proxy_lua_ferror(L, "mutator step %d: 'flag' must be a single character", tidx);
        }
        if (mcp_is_flag_invalid(flag[0])) {
            proxy_lua_ferror(L, "mutator step %d: 'flag' must be alphanumeric", tidx);
        }
    } else {
        proxy_lua_ferror(L, "mutator step %d: must provide 'flag' argument", tidx);
    }
    lua_pop(L, 1); // val or nil
}

static void _mut_init_flag(lua_State *L, int tidx, struct mcp_mut_flag *c) {
    if (lua_getfield(L, tidx, "flag") != LUA_TNIL) {
        const char *flag = lua_tostring(L, -1);
        c->f = flag[0];
        c->bit = (uint64_t)1 << (c->f - 65);
    }
    lua_pop(L, 1); // val or nil
}

// mutator must be at position 1. index to check at idx.
// pulls metatables and compares them to see if we have a request or response
// object. then fills the appropriate pointer and returns.
static inline void _mut_checkudata(lua_State *L, unsigned int idx, mcp_request_t **srq, mcp_resp_t **srs) {
    lua_getmetatable(L, idx);
    lua_getiuservalue(L, 1, MUT_REQ);
    if (lua_rawequal(L, -1, -2)) {
        lua_pop(L, 2);
        *srq = lua_touserdata(L, idx);
        return;
    }
    lua_getiuservalue(L, 1, MUT_RES);
    if (lua_rawequal(L, -1, -3)) {
        *srs = lua_touserdata(L, idx);
    }
    lua_pop(L, 3);
}

// END COMMMON ARG HANDLERS

// START STEPS

mut_step_c(cmdset) {
    size_t len = 0;

    if (lua_getfield(L, tidx, "cmd") != LUA_TNIL) {
        lua_tolstring(L, -1, &len);
        // TODO: know either exact max length or parse for valid commands
        // this small sanity check should help against user error for now.
        if (len > 20) {
            proxy_lua_ferror(L, "mutator step %d: 'cmd' too long", tidx);
        }
    } else {
        proxy_lua_ferror(L, "mutator step %d: must provide 'cmd' argument", tidx);
    }
    lua_pop(L, 1);

    return len;
}

mut_step_i(cmdset) {
    struct mcp_mut_step *s = &mut->steps[sc];
    struct mcp_mut_string *c = &s->c.string;
    size_t len = 0;

    if (lua_getfield(L, tidx, "cmd") != LUA_TNIL) {
        const char *cmd = lua_tolstring(L, -1, &len);
        c->str = mut->aused;
        c->len = len;
        char *a = mut->arena + mut->aused;
        memcpy(a, cmd, len);
        mut->aused += len;
    }
    lua_pop(L, 1);

    return 0;
}

mut_step_n(cmdset) {
    struct mcp_mut_string *c = &s->c.string;
    return c->len;
}

mut_step_r(cmdset) {
    struct mcp_mutator *mut = run->mut;
    struct mcp_mut_string *c = &s->c.string;

    const char *str = mut->arena + c->str;

    memcpy(run->d_pos, str, c->len);
    run->d_pos += c->len;
}

mut_step_c(cmdcopy) {
    _mut_check_idx(L, tidx);
    return 0;
}

mut_step_i(cmdcopy) {
    struct mcp_mut_step *s = &mut->steps[sc];
    if (lua_getfield(L, tidx, "idx") != LUA_TNIL) {
        s->idx = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);

    return 0;
}

mut_step_n(cmdcopy) {
    lua_State *L = run->L;
    unsigned idx = s->idx;
    mcp_request_t *srq = NULL;
    mcp_resp_t *srs = NULL;

    switch (lua_type(L, idx)) {
        case LUA_TSTRING:
            p->src = lua_tolstring(L, idx, &p->slen);
            break;
        case LUA_TUSERDATA:
            _mut_checkudata(L, idx, &srq, &srs);
            p->slen = 0;
            if (srq) {
                // command must be at the start
                const char *cmd = srq->pr.request;
                // command ends at the first token
                int clen = srq->pr.tokens[1];
                if (cmd[clen] == ' ') {
                    clen--;
                }
                p->src = cmd;
                p->slen = clen;
            } else {
                // can only use a request object
                return -1;
            }
            break;
        default:
            // ints/etc unsupported
            return -1;
    }

    return p->slen;
}

mut_step_r(cmdcopy) {
    memcpy(run->d_pos, p->src, p->slen);
    run->d_pos += p->slen;
}

// TODO: validate a cmd is already slated to be set
// NOTE: we might need to know the integer CMD because key position can move
// with the stupid GAT command.
mut_step_c(keycopy) {
    _mut_check_idx(L, tidx);
    return 0;
}

mut_step_i(keycopy) {
    struct mcp_mut_step *s = &mut->steps[sc];
    if (lua_getfield(L, tidx, "idx") != LUA_TNIL) {
        s->idx = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);
    return 0;
}

mut_step_n(keycopy) {
    lua_State *L = run->L;
    unsigned idx = s->idx;
    mcp_request_t *srq = NULL;
    mcp_resp_t *srs = NULL;

    switch (lua_type(L, idx)) {
        case LUA_TSTRING:
            p->src = lua_tolstring(L, idx, &p->slen);
            break;
        case LUA_TUSERDATA:
            _mut_checkudata(L, idx, &srq, &srs);
            if (srq) {
                p->src = MCP_PARSER_KEY(srq->pr);
                p->slen = srq->pr.klen;
            } else {
                // TODO: if a result object:
                // - if meta, and 'k' flag, copy flag token.
                return -1;
            }
            break;
        default:
            // ints/etc unsupported
            return -1;
    }

    return p->slen;
}

mut_step_r(keycopy) {
    memcpy(run->d_pos, p->src, p->slen);
    run->d_pos += p->slen;
}

mut_step_c(keyset) {
    size_t len = 0;

    if (lua_getfield(L, tidx, "val") != LUA_TNIL) {
        lua_tolstring(L, -1, &len);
        if (len < 1) {
            proxy_lua_ferror(L, "mutator step %d: 'val' must have nonzero length", tidx);
        }
    } else {
        proxy_lua_ferror(L, "mutator step %d: must provide 'val' argument", tidx);
    }
    lua_pop(L, 1); // val or nil

    return len;
}

mut_step_i(keyset) {
    struct mcp_mut_step *s = &mut->steps[sc];
    struct mcp_mut_string *c = &s->c.string;
    size_t len = 0;

    // store our match string in the arena space that we reserved before.
    if (lua_getfield(L, tidx, "val") != LUA_TNIL) {
        const char *str = lua_tolstring(L, -1, &len);
        c->str = mut->aused;
        c->len = len;
        char *a = mut->arena + mut->aused;
        memcpy(a, str, len);
        mut->aused += len;
    }
    lua_pop(L, 1); // val or nil

    return len;
}

mut_step_n(keyset) {
    struct mcp_mut_string *c = &s->c.string;
    return c->len;
}

mut_step_r(keyset) {
    struct mcp_mutator *mut = run->mut;
    struct mcp_mut_string *c = &s->c.string;

    const char *str = mut->arena + c->str;

    memcpy(run->d_pos, str, c->len);
    run->d_pos += c->len;
}

// TODO: pre-validate that it's an accepted code?
mut_step_c(rescodeset) {
    return _mut_check_strlen(L, tidx, "val");
}

mut_step_i(rescodeset) {
    struct mcp_mut_step *s = &mut->steps[sc];
    struct mcp_mut_string *c = &s->c.string;
    size_t len = 0;

    if (lua_getfield(L, tidx, "val") != LUA_TNIL) {
        const char *str = lua_tolstring(L, -1, &len);
        c->str = mut->aused;
        c->len = len;
        char *a = mut->arena + mut->aused;
        memcpy(a, str, len);
        mut->aused += len;
    }
    lua_pop(L, 1);

    return 0;
}

mut_step_n(rescodeset) {
    struct mcp_mut_string *c = &s->c.string;
    return c->len;
}

mut_step_r(rescodeset) {
    struct mcp_mutator *mut = run->mut;
    struct mcp_mut_string *c = &s->c.string;

    const char *str = mut->arena + c->str;

    memcpy(run->d_pos, str, c->len);
    run->d_pos += c->len;
}

mut_step_c(rescodecopy) {
    _mut_check_idx(L, tidx);
    return 0;
}

mut_step_i(rescodecopy) {
    struct mcp_mut_step *s = &mut->steps[sc];
    if (lua_getfield(L, tidx, "idx") != LUA_TNIL) {
        s->idx = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);

    return 0;
}

mut_step_n(rescodecopy) {
    lua_State *L = run->L;
    unsigned idx = s->idx;
    mcp_request_t *srq = NULL;
    mcp_resp_t *srs = NULL;

    switch (lua_type(L, idx)) {
        case LUA_TSTRING:
            p->src = lua_tolstring(L, idx, &p->slen);
            break;
        case LUA_TUSERDATA:
            _mut_checkudata(L, idx, &srq, &srs);
            if (srs) {
                // can't recover the exact code from the mcmc resp object, so lets make
                // sure it's tokenized and copy the first token.
                if (srs->resp.type == MCMC_RESP_META) {
                    mcmc_tokenize_res(srs->buf, srs->resp.reslen, &srs->tok);
                } else {
                    // FIXME: only supports meta responses
                    return -1;
                }
                int len = 0;
                p->src = mcmc_token_get(srs->buf, &srs->tok, 0, &len);
                p->slen = len;
                if (len < 2) {
                    return -1;
                }
            } else {
                return -1;
            }
            break;
        default:
            // ints/etc unsupported
            return -1;
    }

    return p->slen;
}

mut_step_r(rescodecopy) {
    memcpy(run->d_pos, p->src, p->slen);
    run->d_pos += p->slen;
}

// TODO: can be no other steps after an error is set.
// TODO: if idx given instead of msg copy an input string.
mut_step_c(reserr) {
    size_t total = 0;
    char *code = NULL;

    // FIXME: add code length to len
    if (lua_getfield(L, tidx, "code") != LUA_TNIL) {
        const char *val = lua_tostring(L, -1);

        if (strcmp(val, "error") == 0) {
            code = RESERR_ERROR_STR;
        } else if (strcmp(val, "server") == 0) {
            code = RESERR_SERVER_STR;
        } else if (strcmp(val, "client") == 0) {
            code = RESERR_CLIENT_STR;
        } else {
            proxy_lua_ferror(L, "mutator step %d: code must be 'error', server', or 'client'", tidx);
        }

        total += strlen(code);
    } else {
        proxy_lua_ferror(L, "mutator step %d: must provide 'code' argument", tidx);
    }
    lua_pop(L, 1);

    if (lua_getfield(L, tidx, "msg") != LUA_TNIL) {
        size_t len = 0;
        lua_tolstring(L, -1, &len);
        if (len < 1) {
            proxy_lua_ferror(L, "mutator step %d: 'msg' must be a nonzero length string", tidx);
        }
        total += len + 1; // room for space between code and msg
    }
    lua_pop(L, 1);

    return total;
}

mut_step_i(reserr) {
    struct mcp_mut_step *s = &mut->steps[sc];
    struct mcp_mut_string *c = &s->c.string;
    size_t len = 0;
    const char *code = NULL;

    char *a = mut->arena + mut->aused;
    if (lua_getfield(L, tidx, "code") != LUA_TNIL) {
        const char *val = lua_tostring(L, -1);
        if (strcmp(val, "error") == 0) {
            code = RESERR_ERROR_STR;
        } else if (strcmp(val, "server") == 0) {
            code = RESERR_SERVER_STR;
        } else if (strcmp(val, "client") == 0) {
            code = RESERR_CLIENT_STR;
        } else {
            // shouldn't be possible
            proxy_lua_ferror(L, "mutator step %d: code must be 'error', server', or 'client'", tidx);
        }

        // Start our string here.
        c->str = mut->aused;
        size_t clen = strlen(code);
        memcpy(a, code, clen);
        a += clen;
        *a = ' ';
        a++;
        clen++;
        mut->aused += clen;
        c->len += clen;
    } else {
        proxy_lua_ferror(L, "mutator step %d: must provide 'code' argument", tidx);
    }
    lua_pop(L, 1);

    if (lua_getfield(L, tidx, "msg") != LUA_TNIL) {
        // Extend the string with a msg if supplied.
        const char *str = lua_tolstring(L, -1, &len);
        c->len += len;
        memcpy(a, str, len);
        mut->aused += len;
    } else {
        // TODO: note no error msg
    }
    lua_pop(L, 1);

    return c->len;
}

mut_step_n(reserr) {
    struct mcp_mut_string *c = &s->c.string;
    return c->len;
}

mut_step_r(reserr) {
    struct mcp_mutator *mut = run->mut;
    struct mcp_mut_string *c = &s->c.string;

    const char *str = mut->arena + c->str;
    int len = c->len;

    // set error code first
    memcpy(run->d_pos, str, len);
    run->d_pos += len;
}

// TODO: track which flags we've already set and error on dupes
mut_step_c(flagset) {
    _mut_check_flag(L, tidx);
    size_t len = 0;

    int vtype = lua_getfield(L, tidx, "val");
    if (vtype == LUA_TNUMBER || vtype == LUA_TSTRING) {
        // this converts the arg into a string for us.
        lua_tolstring(L, -1, &len);
    } else if (vtype != LUA_TNIL) {
        proxy_lua_ferror(L, "mutator step %d: unsupported type for 'val'", tidx);
    }
    lua_pop(L, 1);

    return len;
}

mut_step_i(flagset) {
    struct mcp_mut_step *s = &mut->steps[sc];
    struct mcp_mut_flagval *c = &s->c.flagval;
    size_t len = 0;

    _mut_init_flag(L, tidx, &c->flag);
    if (lua_getfield(L, tidx, "val") != LUA_TNIL) {
        const char *str = lua_tolstring(L, -1, &len);
        c->str.str = mut->aused;
        c->str.len = len;
        char *a = mut->arena + mut->aused;
        memcpy(a, str, len);
        mut->aused += len;
    }
    lua_pop(L, 1);

    return len;
}

mut_step_n(flagset) {
    struct mcp_mut_flagval *c = &s->c.flagval;
    return c->str.len + 1; // room for flag
}

// FIXME: triple check that this is actually the same code for req vs res?
// seems like it is.
mut_step_r(flagset) {
    struct mcp_mutator *mut = run->mut;
    struct mcp_mut_flagval *c = &s->c.flagval;

    const char *str = mut->arena + c->str.str;
    int len = c->str.len;

    *(run->d_pos) = c->flag.f;
    run->d_pos++;
    if (len > 0) {
        memcpy(run->d_pos, str, len);
        run->d_pos += len;
    }
}

mut_step_c(flagcopy) {
    _mut_check_flag(L, tidx);
    _mut_check_idx(L, tidx);
    return 0;
}

// TODO: maybe: optional default val if copy source missing
mut_step_i(flagcopy) {
    struct mcp_mut_step *s = &mut->steps[sc];
    struct mcp_mut_flag *c = &s->c.flag;

    _mut_init_flag(L, tidx, c);

    if (lua_getfield(L, tidx, "idx") != LUA_TNIL) {
        s->idx = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);

    return 0;
}

mut_step_n(flagcopy) {
    struct mcp_mut_flag *c = &s->c.flag;

    lua_State *L = run->L;
    unsigned int idx = s->idx;
    mcp_request_t *srq = NULL;
    mcp_resp_t *srs = NULL;

    switch (lua_type(L, idx)) {
        case LUA_TSTRING:
            p->src = lua_tolstring(L, idx, &p->slen);
            break;
        case LUA_TNUMBER:
            // TODO: unimplemented
            return -1;
            break;
        case LUA_TUSERDATA:
            _mut_checkudata(L, idx, &srq, &srs);
            p->slen = 0;
            if (srq) {
                if (srq->pr.cmd_type != CMD_TYPE_META) {
                    return -1;
                }
                if (srq->pr.t.meta.flags & c->bit) {
                    const char *tok = NULL;
                    size_t tlen = 0;
                    mcp_request_find_flag_token(srq, c->f, &tok, &tlen);

                    if (tlen > 0) {
                        p->src = tok;
                        p->slen = tlen;
                    }
                }
            } else if (srs) {
                if (srs->resp.type != MCMC_RESP_META) {
                    // FIXME: error, can't copy flag from non-meta res
                    return -1;
                }
                mcmc_tokenize_res(srs->buf, srs->resp.reslen, &srs->tok);
                if (mcmc_token_has_flag_bit(&srs->tok, c->bit) == MCMC_OK) {
                    // flag exists, so copy that in.
                    // realistically this func is only used if we're also copying a
                    // token, so we look for that too.
                    // could add an option to avoid checking for a token?
                    int len = 0;
                    const char *tok = mcmc_token_get_flag(srs->buf, &srs->tok, c->f, &len);

                    if (len > 0) {
                        p->src = tok;
                        p->slen = len;
                    }
                }
            } else {
                return -1;
            }
            break;
        default:
            return -1;
    }

    return p->slen;
}

mut_step_r(flagcopy) {
    struct mcp_mut_flag *c = &s->c.flag;
    *(run->d_pos) = c->f;
    run->d_pos++;
    if (p->slen) {
        memcpy(run->d_pos, p->src, p->slen);
        run->d_pos += p->slen;
    }
}

// TODO: check that the value hasn't been set yet.
mut_step_c(valcopy) {
    _mut_check_idx(L, tidx);

    return 0;
}

mut_step_i(valcopy) {
    struct mcp_mut_step *s = &mut->steps[sc];

    if (lua_getfield(L, tidx, "idx") != LUA_TNIL) {
        s->idx = lua_tointeger(L, -1);
    }
    lua_pop(L, 1);

    return 0;
}

mut_step_n(valcopy) {
    lua_State *L = run->L;
    unsigned int idx = s->idx;
    // extract the string + length we need to copy
    mcp_request_t *srq = NULL;
    mcp_resp_t *srs = NULL;

    switch (lua_type(L, idx)) {
        case LUA_TSTRING:
            run->vbuf = lua_tolstring(L, idx, &run->vlen);
            break;
        case LUA_TNUMBER:
            // TODO: unimplemented
            break;
        case LUA_TUSERDATA:
            _mut_checkudata(L, idx, &srq, &srs);
            if (srq) {
                if (srq->pr.vbuf) {
                    run->vbuf = srq->pr.vbuf;
                    run->vlen = srq->pr.vlen;
                }
            } else if (srs) {
                // TODO: need to locally parse the result to get the actual val
                // offsets until later refactoring takes place.
            } else {
                return -1;
            }
            break;
        default:
            return -1;
    }

    // count the number of digits in vlen to reserve space.
    //
    // oddly algorithms to count digits and write digits are similar (outside
    // of hyper optimization via bit math), so just reuse the same code here.
    // if I can ever get arena allocations to work and remove the pre-calc
    // steps this is moot anyway.
    char temp[22];
    const char *e = itoa_u64(run->vlen, temp);

    return e - temp;
}

// print the vlen into the buffer
// we remove the \r\n from the protocol length
mut_step_r(valcopy) {
    run->d_pos = itoa_u64(run->vlen-2, run->d_pos);
}

// END STEPS

static const struct mcp_mut_entry mcp_mut_entries[] = {
    [mcp_mut_step_none] = {NULL, NULL, NULL, NULL, NULL, 0, 0},
    [mcp_mut_step_cmdset] = {"cmdset", mcp_mutator_cmdset_c, mcp_mutator_cmdset_i, mcp_mutator_cmdset_n, mcp_mutator_cmdset_r, MUT_REQ, 0},
    [mcp_mut_step_cmdcopy] = {"cmdcopy", mcp_mutator_cmdcopy_c, mcp_mutator_cmdcopy_i, mcp_mutator_cmdcopy_n, mcp_mutator_cmdcopy_r, MUT_REQ, 0},
    [mcp_mut_step_keycopy] = {"keycopy", mcp_mutator_keycopy_c, mcp_mutator_keycopy_i, mcp_mutator_keycopy_n, mcp_mutator_keycopy_r, MUT_REQ, 0},
    [mcp_mut_step_keyset] = {"keyset", mcp_mutator_keyset_c, mcp_mutator_keyset_i, mcp_mutator_keyset_n, mcp_mutator_keyset_r, MUT_REQ, 0},
    [mcp_mut_step_rescodeset] = {"rescodeset", mcp_mutator_rescodeset_c, mcp_mutator_rescodeset_i, mcp_mutator_rescodeset_n, mcp_mutator_rescodeset_r, MUT_RES, 0},
    [mcp_mut_step_rescodecopy] = {"rescodecopy", mcp_mutator_rescodecopy_c, mcp_mutator_rescodecopy_i, mcp_mutator_rescodecopy_n, mcp_mutator_rescodecopy_r, MUT_RES, 0},
    [mcp_mut_step_reserr] = {"reserr", mcp_mutator_reserr_c, mcp_mutator_reserr_i, mcp_mutator_reserr_n, mcp_mutator_reserr_r, MUT_RES, 0},
    [mcp_mut_step_flagset] = {"flagset", mcp_mutator_flagset_c, mcp_mutator_flagset_i, mcp_mutator_flagset_n, mcp_mutator_flagset_r, MUT_REQ|MUT_RES, 0},
    [mcp_mut_step_flagcopy] = {"flagcopy", mcp_mutator_flagcopy_c, mcp_mutator_flagcopy_i, mcp_mutator_flagcopy_n, mcp_mutator_flagcopy_r, MUT_REQ|MUT_RES, 0},
    [mcp_mut_step_valcopy] = {"valcopy", mcp_mutator_valcopy_c, mcp_mutator_valcopy_i, mcp_mutator_valcopy_n, mcp_mutator_valcopy_r, MUT_REQ|MUT_RES, 0},
    [mcp_mut_step_final] = {NULL, NULL, NULL, NULL, NULL, 0, 0},
};

// call with type string on top
static enum mcp_mut_steptype mcp_mutator_steptype(lua_State *L) {
    const char *type = luaL_checkstring(L, -1);
    for (int x = 0; x < mcp_mut_step_final; x++) {
        const struct mcp_mut_entry *e = &mcp_mut_entries[x];
        if (e->s && strcmp(type, e->s) == 0) {
            return x;
        }
    }
    return mcp_mut_step_none;
}

static int mcp_mutator_new(lua_State *L, enum mcp_mut_type type) {
    int argc = lua_gettop(L);
    size_t size = 0;
    int scount = 0;

    // loop argument tables once for validation and pre-calculations.
    for (int x = 1; x <= argc; x++) {
        luaL_checktype(L, x, LUA_TTABLE);
        if (lua_getfield(L, x, "t") != LUA_TNIL) {
            enum mcp_mut_steptype st = mcp_mutator_steptype(L);
            const struct mcp_mut_entry *e = &mcp_mut_entries[st];
            if (!(e->t & type)) {
                proxy_lua_ferror(L, "mutator step %d: step incompatible with mutator type", x);
            }
            if ((st == mcp_mut_step_none) || e->c == NULL) {
                proxy_lua_ferror(L, "mutator step %d: unknown step type", x);
            }
            size += e->c(L, x);
        }
        lua_pop(L, 1); // drop 't' or nil
        scount++;
    }

    // we now know the size and number of steps. allocate some flat memory.

    size_t extsize = sizeof(struct mcp_mut_step) * scount;
    struct mcp_mutator *mut = lua_newuserdatauv(L, sizeof(*mut) + extsize, 2);
    memset(mut, 0, sizeof(*mut) + extsize);

    mut->arena = malloc(size);
    if (mut->arena == NULL) {
        proxy_lua_error(L, "mutator_new: failed to allocate memory");
    }
    luaL_setmetatable(L, "mcp.mutator");
    mut->type = type;

    // Cache both request and result metatables for arg validation.
    // Since a req mutator can take a res argument and vice versa
    luaL_getmetatable(L, "mcp.request");
    lua_setiuservalue(L, -2, MUT_REQ);
    luaL_getmetatable(L, "mcp.response");
    lua_setiuservalue(L, -2, MUT_RES);

    // loop the arg tables again to fill in the steps
    // skip checks since we did that during the first loop.
    scount = 0;
    for (int x = 1; x <= argc; x++) {
        if (lua_getfield(L, x, "t") != LUA_TNIL) {
            enum mcp_mut_steptype st = mcp_mutator_steptype(L);
            mut->steps[scount].type = st;
            mcp_mut_entries[st].i(L, x, scount, mut);
            mut->rcount += mcp_mut_entries[st].rc;

            // copy function pointers into the step so we don't have to skip
            // around the much larger mcp_mut_entries at runtime.
            mut->steps[scount].n = mcp_mut_entries[st].n;
            mut->steps[scount].r = mcp_mut_entries[st].r;
            // actual args are "self, dst, args". start user idx's at 3
            mut->steps[scount].idx += 2;
        }
        lua_pop(L, 1); // drop t or nil
        scount++;
    }

    if (size != mut->aused) {
        proxy_lua_error(L, "mutator failed to properly initialize, memory not filled correctly");
    }
    mut->scount = scount;

    return 1;
}

static inline int _mcp_mut_run_total(struct mcp_mut_run *run, struct mcp_mut_part *parts) {
    int total = 0;
    struct mcp_mutator *mut = run->mut;
    for (int x = 0; x < mut->scount; x++) {
        struct mcp_mut_step *s = &mut->steps[x];
        assert(s->type != mcp_mut_step_none);
        int len = s->n(run, s, &parts[x]);
        if (len < 0) {
            return -1;
        } else {
            total += len;
        }
    }
    // account for spaces between "steps" and \r\n
    // note that steps that themselves can make multiple tokens _must_ account
    // for this on their own.
    total += mut->scount + MIN_BUF_SPACE;

    return total;
}

static inline int _mcp_mut_run_assemble(struct mcp_mut_run *run, struct mcp_mut_part *parts) {
    struct mcp_mutator *mut = run->mut;
    // assemble final req/res
    for (int x = 0; x < mut->scount; x++) {
        struct mcp_mut_step *s = &mut->steps[x];
        assert(s->type != mcp_mut_step_none);
        // Error handling is pushed to the totalling phase.
        // In this phase we should just be copying data and cannot fail.
        s->r(run, s, &parts[x]);

        *(run->d_pos) = ' ';
        run->d_pos++;
    }

    // TODO: any cases where we need to check if the final char is a space or
    // not?
    // add the \r\n after all steps
    *(run->d_pos-1) = '\r';
    *(run->d_pos) = '\n';
    run->d_pos++;

    return 0;
}

static int mcp_mut_run(struct mcp_mut_run *run) {
    struct mcp_mutator *mut = run->mut;
    LIBEVENT_THREAD *t = PROXY_GET_THR(run->L);
    int ret = 0;
    struct mcp_mut_part parts[mut->scount];

    // first accumulate the length tally
    // FIXME: noticed off-by-one's sometimes.
    // maybe add a debug assert to verify the written total (d_pos - etc)
    // matches total?
    // This isn't critical so long as total is > actual, which it has been
    int total = _mcp_mut_run_total(run, parts);
    if (total < 0) {
        lua_pushboolean(run->L, 0);
        return 1;
    }

    // ensure space and/or allocate memory then seed our destination pointer.
    if (mut->type == MUT_REQ) {
        mcp_request_t *rq = run->arg;
        if (rq->pr.vbuf) {
            // FIXME: maybe NULL rq->pr.request in cleanup phase and test that
            // instead? this check will only fire if req had a vbuf.
            proxy_lua_error(run->L, "mutator: request has already been rendered");
            return 0;
        }
        // future.. should be able to dynamically assign request buffer.
        if (total > MCP_REQUEST_MAXLEN) {
            proxy_lua_error(run->L, "mutator: new request is too long");
            return 0;
        }
        run->d_pos = rq->request;

        _mcp_mut_run_assemble(run, parts);

        if (process_request(&rq->pr, rq->request, run->d_pos - rq->request) != 0) {
            proxy_lua_error(run->L, "mutator: failed to parse new request");
            return 0;
        }

        if (run->vbuf) {
            rq->pr.vbuf = malloc(run->vlen);
            if (rq->pr.vbuf == NULL) {
                proxy_lua_error(run->L, "mutator: failed to allocate value buffer");
                return 0;
            }
            pthread_mutex_lock(&t->proxy_limit_lock);
            t->proxy_buffer_memory_used += rq->pr.vlen;
            pthread_mutex_unlock(&t->proxy_limit_lock);

            rq->pr.vlen = run->vlen;
            memcpy(rq->pr.vbuf, run->vbuf, run->vlen);
        }
    } else {
        mcp_resp_t *rs = run->arg;
        if (rs->buf) {
            proxy_lua_error(run->L, "mutator: result has already been rendered");
            return 0;
        }

        // value is inlined in result buffers. future intention to allow more
        // complex objects so we can refcount values.
        rs->buf = malloc(total + run->vlen);
        if (rs->buf == NULL) {
            proxy_lua_error(run->L, "mutator: failed to allocate result buffer");
            return 0;
        }
        run->d_pos = rs->buf;

        _mcp_mut_run_assemble(run, parts);

        rs->tok.ntokens = 0; // TODO: handler from mcmc?
        rs->status = mcmc_parse_buf(rs->buf, run->d_pos - rs->buf, &rs->resp);
        if (rs->resp.type == MCMC_RESP_FAIL) {
            proxy_lua_error(run->L, "mutator: failed to parse new result");
            return 0;
        }

        // results are sequential buffers, copy the value in.
        if (run->vbuf) {
            memcpy(run->d_pos, run->vbuf, run->vlen);
            run->d_pos += run->vlen;
        }

        rs->blen = run->d_pos - rs->buf;
        // NOTE: We increment but don't check the memory limits here. Any
        // incoming request or incoming response will also check the memory
        // limits, and just doing an increment here removes some potential
        // error handling. Requests that are already started should be allowed
        // to complete to minimize impact of hitting memory limits.
        pthread_mutex_lock(&t->proxy_limit_lock);
        t->proxy_buffer_memory_used += rs->blen;
        pthread_mutex_unlock(&t->proxy_limit_lock);
    }

    return ret;
}

// PUBLIC INTERFACE

int mcplib_req_mutator_new(lua_State *L) {
    return mcp_mutator_new(L, MUT_REQ);
}

int mcplib_res_mutator_new(lua_State *L) {
    return mcp_mutator_new(L, MUT_RES);
}

// walk each step and free references/memory/etc
int mcplib_mutator_gc(lua_State *L) {
    struct mcp_mutator *mut = lua_touserdata(L, 1);

    if (mut->arena) {
        free(mut->arena);
        mut->arena = NULL;
    }

    // NOTE: leaving commented until I run into something that actually has
    // something extra to GC
    /*for (int x = 0; x < mut->scount; x++) {
        struct mcp_mut_step *s = &mut->steps[x];
        switch (s->type) {
            case mcp_mut_step_none:
            case mcp_mut_step_cmdset:
            case mcp_mut_step_cmdcopy:
            case mcp_mut_step_keycopy:
            case mcp_mut_step_keyset:
            case mcp_mut_step_rescodeset:
            case mcp_mut_step_rescodecopy:
            case mcp_mut_step_reserr:
            case mcp_mut_step_flagset:
            case mcp_mut_step_flagcopy:
            case mcp_mut_step_valcopy:
            case mcp_mut_step_final:
                break;
        }
    }*/

    return 0;
}

int mcplib_mutator_call(lua_State *L) {
    // since we're here from a __call, assume the type is correct.
    struct mcp_mutator *mut = lua_touserdata(L, 1);
    luaL_checktype(L, 2, LUA_TUSERDATA);
    if (lua_checkstack(L, mut->rcount + 3) == 0) {
        proxy_lua_error(L, "mutator ran out of stack space for results");
    }

    lua_getmetatable(L, 2); // put dest obj arg metatable on stack
    lua_getiuservalue(L, 1, mut->type); // put stashed metatable on stack
    luaL_argcheck(L, lua_rawequal(L, -1, -2), 2,
            "invalid argument to mutator object");
    lua_pop(L, 2); // toss both metatables


    // we're valid now.
    void *arg = lua_touserdata(L, 2);
    // stack scratch space so we can avoid modifying the mut struct
    struct mcp_mut_run run = {L, mut, arg, NULL, NULL, 0};
    // TODO: numbuf space
    int ret = mcp_mut_run(&run);

    return ret;
}

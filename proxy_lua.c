/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

// func prototype example:
// static int fname (lua_State *L)
// normal library open:
// int luaopen_mcp(lua_State *L) { }

// resp:ok()
static int mcplib_response_ok(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->status == MCMC_OK) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int mcplib_response_hit(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->status == MCMC_OK && r->resp.code != MCMC_CODE_MISS) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

// Caller needs to discern if a vlen is 0 because of a failed response or an
// OK response that was actually zero. So we always return an integer value
// here.
static int mcplib_response_vlen(lua_State *L) {
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
static int mcplib_response_code(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    lua_pushinteger(L, r->resp.code);

    return 1;
}

// Get the unparsed response line for handling in lua.
static int mcplib_response_line(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->resp.rline != NULL) {
        lua_pushlstring(L, r->resp.rline, r->resp.rlen);
    } else {
        lua_pushnil(L);
    }

    return 1;
}

static int mcplib_response_gc(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    // On error/similar we might be holding the read buffer.
    // If the buf is handed off to mc_resp for return, this pointer is NULL
    if (r->buf != NULL) {
        free(r->buf);
    }

    return 0;
}

// NOTE: backends are global objects owned by pool objects.
// Each pool has a "proxy pool object" distributed to each worker VM.
// proxy pool objects are held at the same time as any request exists on a
// backend, in the coroutine stack during yield()
// To free a backend: All proxies for a pool are collected, then the central
// pool is collected, which releases backend references, which allows backend
// to be collected.
static int mcplib_backend_gc(lua_State *L) {
    mcp_backend_t *be = luaL_checkudata(L, -1, "mcp.backend");

    assert(STAILQ_EMPTY(&be->io_head));

    mcmc_disconnect(be->client);
    free(be->client);

    // FIXME (v2): upvalue for global ctx.
    proxy_ctx_t *ctx = settings.proxy_ctx;
    STAT_DECR(ctx, backend_total, 1);

    return 0;
}

static int mcplib_backend(lua_State *L) {
    luaL_checkstring(L, -3); // label for indexing backends.
    size_t nlen = 0;
    const char *name = luaL_checklstring(L, -2, &nlen);
    const char *port = luaL_checkstring(L, -1);
    // FIXME (v2): upvalue for global ctx.
    proxy_ctx_t *ctx = settings.proxy_ctx;

    if (nlen > MAX_NAMELEN-1) {
        proxy_lua_error(L, "backend name too long");
        return 0;
    }

    // first check our reference table to compare.
    lua_pushvalue(L, 1);
    int ret = lua_gettable(L, lua_upvalueindex(MCP_BACKEND_UPVALUE));
    if (ret != LUA_TNIL) {
        mcp_backend_t *be_orig = luaL_checkudata(L, -1, "mcp.backend");
        if (strncmp(be_orig->name, name, MAX_NAMELEN) == 0
                && strncmp(be_orig->port, port, MAX_PORTLEN) == 0) {
            // backend is the same, return it.
            return 1;
        } else {
            // backend not the same, pop from stack and make new one.
            lua_pop(L, 1);
        }
    } else {
        lua_pop(L, 1);
    }

    // This might shift to internal objects?
    mcp_backend_t *be = lua_newuserdatauv(L, sizeof(mcp_backend_t), 0);

    // FIXME (v2): remove some of the excess zero'ing below?
    memset(be, 0, sizeof(mcp_backend_t));
    strncpy(be->name, name, MAX_NAMELEN);
    strncpy(be->port, port, MAX_PORTLEN);
    be->depth = 0;
    be->rbufused = 0;
    be->failed_count = 0;
    STAILQ_INIT(&be->io_head);
    be->state = mcp_backend_read;
    be->connecting = false;
    be->can_write = false;
    be->stacked = false;
    be->bad = false;

    // this leaves a permanent buffer on the backend, which is fine
    // unless you have billions of backends.
    // we can later optimize for pulling buffers from idle backends.
    be->rbuf = malloc(READ_BUFFER_SIZE);
    if (be->rbuf == NULL) {
        proxy_lua_error(L, "out of memory allocating backend");
        return 0;
    }

    // initialize libevent.
    memset(&be->event, 0, sizeof(be->event));

    // initialize the client
    be->client = malloc(mcmc_size(MCMC_OPTION_BLANK));
    if (be->client == NULL) {
        proxy_lua_error(L, "out of memory allocating backend");
        return 0;
    }
    // TODO (v2): connect elsewhere. When there're multiple backend owners, or
    // sockets per backend, etc. We'll want to kick off connects as use time.
    // TODO (v2): no way to change the TCP_KEEPALIVE state post-construction.
    // This is a trivial fix if we ensure a backend's owning event thread is
    // set before it can be used in the proxy, as it would have access to the
    // tunables structure. _reset_bad_backend() may not have its event thread
    // set 100% of the time and I don't want to introduce a crash right now,
    // so I'm writing this overly long comment. :)
    int flags = MCMC_OPTION_NONBLOCK;
    STAT_L(ctx);
    if (ctx->tunables.tcp_keepalive) {
        flags |= MCMC_OPTION_TCP_KEEPALIVE;
    }
    STAT_UL(ctx);
    be->connect_flags = flags;
    int status = mcmc_connect(be->client, be->name, be->port, flags);
    if (status == MCMC_CONNECTED) {
        // FIXME (v2): is this possible? do we ever want to allow blocking
        // connections?
        proxy_lua_ferror(L, "unexpectedly connected to backend early: %s:%s\n", be->name, be->port);
        return 0;
    } else if (status == MCMC_CONNECTING) {
        be->connecting = true;
        be->can_write = false;
    } else {
        proxy_lua_ferror(L, "failed to connect to backend: %s:%s\n", be->name, be->port);
        return 0;
    }

    luaL_getmetatable(L, "mcp.backend");
    lua_setmetatable(L, -2); // set metatable to userdata.

    lua_pushvalue(L, 1); // put the label at the top for settable later.
    lua_pushvalue(L, -2); // copy the backend reference to the top.
    // set our new backend object into the reference table.
    lua_settable(L, lua_upvalueindex(MCP_BACKEND_UPVALUE));
    // stack is back to having backend on the top.

    STAT_INCR(ctx, backend_total, 1);

    return 1;
}

static int mcplib_pool_gc(lua_State *L) {
    mcp_pool_t *p = luaL_checkudata(L, -1, "mcp.pool");
    assert(p->refcount == 0);
    pthread_mutex_destroy(&p->lock);

    for (int x = 0; x < p->pool_size; x++) {
        if (p->pool[x].ref) {
            luaL_unref(L, LUA_REGISTRYINDEX, p->pool[x].ref);
        }
    }

    return 0;
}

// Looks for a short string in a key to separate which part gets hashed vs
// sent to the backend node.
// ie: "foo:bar|#|restofkey" - only "foo:bar" gets hashed.
static const char *mcp_key_hash_filter_stop(const char *conf, const char *key, size_t klen, size_t *newlen) {
    char temp[KEY_MAX_LENGTH+1];
    *newlen = klen;
    if (klen > KEY_MAX_LENGTH) {
        // Hedging against potential bugs.
        return key;
    }

    memcpy(temp, key, klen);
    temp[klen+1] = '\0';

    // TODO (v2): memmem would avoid the temp key and memcpy here, but it's
    // not technically portable. An easy improvement would be to detect
    // memmem() in `configure` and only use strstr/copy as a fallback.
    // Since keys are short it's unlikely this would be a major performance
    // win.
    char *found = strstr(temp, conf);

    if (found) {
        *newlen = found - temp;
    }

    // hash stop can't change where keys start.
    return key;
}

// Takes a two character "tag", ie; "{}", or "$$", searches string for the
// first then second character. Only hashes the portion within these tags.
// *conf _must_ be two characters.
static const char *mcp_key_hash_filter_tag(const char *conf, const char *key, size_t klen, size_t *newlen) {
    *newlen = klen;

    const char *t1 = memchr(key, conf[0], klen);
    if (t1) {
        size_t remain = klen - (t1 - key);
        // must be at least one character inbetween the tags to hash.
        if (remain > 1) {
            const char *t2 = memchr(t1, conf[1], remain);

            if (t2) {
                *newlen = t2 - t1 - 1;
                return t1+1;
            }
        }
    }

    return key;
}

static void _mcplib_pool_dist(lua_State *L, mcp_pool_t *p) {
    luaL_checktype(L, -1, LUA_TTABLE);
    if (lua_getfield(L, -1, "new") != LUA_TFUNCTION) {
        proxy_lua_error(L, "key distribution object missing 'new' function");
        return;
    }

    // - now create the copy pool table
    lua_createtable(L, p->pool_size, 0); // give the new pool table a sizing hint.
    for (int x = 1; x <= p->pool_size; x++) {
        mcp_backend_t *be = p->pool[x-1].be;
        lua_createtable(L, 0, 4);
        // stack = [p, h, f, optN, newpool, backend]
        // the key should be fine for id? maybe don't need to duplicate
        // this?
        lua_pushinteger(L, x);
        lua_setfield(L, -2, "id");
        // we don't use the hostname for ketama hashing
        // so passing ip for hostname is fine
        lua_pushstring(L, be->name);
        lua_setfield(L, -2, "addr");
        lua_pushstring(L, be->port);
        lua_setfield(L, -2, "port");

        // set the backend table into the new pool table.
        lua_rawseti(L, -2, x);
    }

    // we can either use lua_insert() or possibly _rotate to shift
    // things into the right place, but simplest is to just copy the
    // option arg to the end of the stack.
    lua_pushvalue(L, 2);
    //   - stack should be: pool, opts, func, pooltable, opts

    // call the dist new function.
    int res = lua_pcall(L, 2, 2, 0);

    if (res != LUA_OK) {
        lua_error(L); // error should be on the stack already.
        return;
    }

    // -1 is lightuserdata ptr to the struct (which must be owned by the
    // userdata), which is later used for internal calls.
    struct proxy_hash_caller *phc;

    luaL_checktype(L, -1, LUA_TLIGHTUSERDATA);
    luaL_checktype(L, -2, LUA_TUSERDATA);
    phc = lua_touserdata(L, -1);
    memcpy(&p->phc, phc, sizeof(*phc));
    lua_pop(L, 1);
    // -2 was userdata we need to hold a reference to
    p->phc_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    // UD now popped from stack.
}

// p = mcp.pool(backends, { dist = f, hashfilter = f, seed = "a", hash = f })
static int mcplib_pool(lua_State *L) {
    int argc = lua_gettop(L);
    luaL_checktype(L, 1, LUA_TTABLE);
    int n = luaL_len(L, 1); // get length of array table

    size_t plen = sizeof(mcp_pool_t) + sizeof(mcp_pool_be_t) * n;
    mcp_pool_t *p = lua_newuserdatauv(L, plen, 0);
    // Zero the memory before use, so we can realibly use __gc to clean up
    memset(p, 0, plen);
    p->pool_size = n;
    // TODO (v2): Nicer if this is fetched from mcp.default_key_hash
    p->key_hasher = XXH3_64bits_withSeed;
    pthread_mutex_init(&p->lock, NULL);
    p->ctx = settings.proxy_ctx; // TODO (v2): store ctx in upvalue.

    luaL_setmetatable(L, "mcp.pool");

    lua_pushvalue(L, -1); // dupe self for reference.
    p->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // remember lua arrays are 1 indexed.
    for (int x = 1; x <= n; x++) {
        mcp_pool_be_t *s = &p->pool[x-1];
        lua_geti(L, 1, x); // get next server into the stack.
        // If we bail here, the pool _gc() should handle releasing any backend
        // references we made so far.
        s->be = luaL_checkudata(L, -1, "mcp.backend");
        s->ref = luaL_ref(L, LUA_REGISTRYINDEX); // references and pops object.
    }

    // Allow passing an ignored nil as a second argument. Makes the lua easier
    int type = lua_type(L, 2);
    if (argc == 1 || type == LUA_TNIL) {
        lua_getglobal(L, "mcp");
        // TODO (v2): decide on a mcp.default_dist and use that instead
        if (lua_getfield(L, -1, "dist_jump_hash") != LUA_TNIL) {
            _mcplib_pool_dist(L, p);
            lua_pop(L, 1); // pop "dist_jump_hash" value.
        } else {
            lua_pop(L, 1);
        }
        lua_pop(L, 1); // pop "mcp"
        return 1;
    }

    // Supplied with an options table. We inspect this table to decorate the
    // pool, then pass it along to the a constructor if necessary.
    luaL_checktype(L, 2, LUA_TTABLE);

    // stack: backends, options, mcp.pool
    if (lua_getfield(L, 2, "dist") != LUA_TNIL) {
        // overriding the distribution function.
        _mcplib_pool_dist(L, p);
        lua_pop(L, 1); // remove the dist table from stack.
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (lua_getfield(L, 2, "filter") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TSTRING);
        const char *f_type = lua_tostring(L, -1);
        if (strcmp(f_type, "stop") == 0) {
            p->key_filter = mcp_key_hash_filter_stop;
        } else if (strcmp(f_type, "tags") == 0) {
            p->key_filter = mcp_key_hash_filter_tag;
        } else {
            proxy_lua_ferror(L, "unknown hash filter specified: %s\n", f_type);
        }

        lua_pop(L, 1); // pops "filter" value.

        if (lua_getfield(L, 2, "filter_conf") == LUA_TSTRING) {
            size_t len = 0;
            const char *conf = lua_tolstring(L, -1, &len);
            if (len < 2 || len > KEY_HASH_FILTER_MAX) {
                proxy_lua_ferror(L, "hash filter conf must be between 2 and %d characters", KEY_HASH_FILTER_MAX);
            }

            memcpy(p->key_filter_conf, conf, len);
            p->key_filter_conf[len+1] = '\0';
        } else {
            proxy_lua_error(L, "hash filter requires 'filter_conf' string");
        }
        lua_pop(L, 1); // pops "filter_conf" value.
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (lua_getfield(L, 2, "hash") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TLIGHTUSERDATA);
        struct proxy_hash_func *phf = lua_touserdata(L, -1);
        p->key_hasher = phf->func;
        lua_pop(L, 1);
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (lua_getfield(L, 2, "seed") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TSTRING);
        size_t seedlen;
        const char *seedstr = lua_tolstring(L, -1, &seedlen);
        // Note: the custom hasher for a dist may be "weird" in some cases, so
        // we use a standard hash method for the seed here.
        // I'm open to changing this (ie; mcp.pool_seed_hasher = etc)
        p->hash_seed = XXH3_64bits(seedstr, seedlen);

        lua_pop(L, 1);
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (p->phc.selector_func == NULL) {
        proxy_lua_error(L, "cannot create pool missing 'dist' argument");
    }

    return 1;
}

static int mcplib_pool_proxy_gc(lua_State *L) {
    mcp_pool_proxy_t *pp = luaL_checkudata(L, -1, "mcp.pool_proxy");
    mcp_pool_t *p = pp->main;
    pthread_mutex_lock(&p->lock);
    p->refcount--;
    if (p->refcount == 0) {
        proxy_ctx_t *ctx = p->ctx;
        pthread_mutex_lock(&ctx->manager_lock);
        STAILQ_INSERT_TAIL(&ctx->manager_head, p, next);
        pthread_cond_signal(&ctx->manager_cond);
        pthread_mutex_unlock(&ctx->manager_lock);
    }
    pthread_mutex_unlock(&p->lock);

    return 0;
}

mcp_backend_t *mcplib_pool_proxy_call_helper(lua_State *L, mcp_pool_t *p, const char *key, size_t len) {
    if (p->key_filter) {
        key = p->key_filter(p->key_filter_conf, key, len, &len);
        P_DEBUG("%s: filtered key for hashing (%.*s)\n", __func__, (int)len, key);
    }
    uint64_t hash = p->key_hasher(key, len, p->hash_seed);
    uint32_t lookup = p->phc.selector_func(hash, p->phc.ctx);

    assert(p->phc.ctx != NULL);
    // attach the backend to the request object.
    // the lua modules should "think" in 1 based indexes, so we need to
    // subtract one here.
    if (lookup >= p->pool_size) {
        proxy_lua_error(L, "key dist hasher tried to use out of bounds index");
    }

    return p->pool[lookup].be;
}

// hashfunc(request) -> backend(request)
// needs key from request object.
static int mcplib_pool_proxy_call(lua_State *L) {
    // internal args are the hash selector (self)
    mcp_pool_proxy_t *pp = luaL_checkudata(L, -2, "mcp.pool_proxy");
    mcp_pool_t *p = pp->main;
    // then request object.
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");

    // we have a fast path to the key/length.
    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot route commands without key");
        return 0;
    }
    const char *key = MCP_PARSER_KEY(rq->pr);
    size_t len = rq->pr.klen;
    rq->be = mcplib_pool_proxy_call_helper(L, p, key, len);

    // now yield request, pool up.
    return lua_yield(L, 2);
}

static int mcplib_tcp_keepalive(lua_State *L) {
    luaL_checktype(L, -1, LUA_TBOOLEAN);
    int state = lua_toboolean(L, -1);
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    STAT_L(ctx);
    ctx->tunables.tcp_keepalive = state;
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_failure_limit(lua_State *L) {
    int limit = luaL_checkinteger(L, -1);
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    if (limit < 0) {
        proxy_lua_error(L, "backend_failure_limit must be >= 0");
        return 0;
    }

    STAT_L(ctx);
    ctx->tunables.backend_failure_limit = limit;
    STAT_UL(ctx);

    return 0;
}

// sad, I had to look this up...
#define NANOSECONDS(x) ((x) * 1E9 + 0.5)
#define MICROSECONDS(x) ((x) * 1E6 + 0.5)

static int mcplib_backend_connect_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    STAT_L(ctx);
    ctx->tunables.connect.tv_sec = secondsi;
    ctx->tunables.connect.tv_usec = MICROSECONDS(subseconds);
#ifdef HAVE_LIBURING
    ctx->tunables.connect_ur.tv_sec = secondsi;
    ctx->tunables.connect_ur.tv_nsec = NANOSECONDS(subseconds);
#endif
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_retry_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    STAT_L(ctx);
    ctx->tunables.retry.tv_sec = secondsi;
    ctx->tunables.retry.tv_usec = MICROSECONDS(subseconds);
#ifdef HAVE_LIBURING
    ctx->tunables.retry_ur.tv_sec = secondsi;
    ctx->tunables.retry_ur.tv_nsec = NANOSECONDS(subseconds);
#endif
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_read_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    STAT_L(ctx);
    ctx->tunables.read.tv_sec = secondsi;
    ctx->tunables.read.tv_usec = MICROSECONDS(subseconds);
#ifdef HAVE_LIBURING
    ctx->tunables.read_ur.tv_sec = secondsi;
    ctx->tunables.read_ur.tv_nsec = NANOSECONDS(subseconds);
#endif
    STAT_UL(ctx);

    return 0;
}

// mcp.attach(mcp.HOOK_NAME, function)
// fill hook structure: if lua function, use luaL_ref() to store the func
static int mcplib_attach(lua_State *L) {
    // Pull the original worker thread out of the shared mcplib upvalue.
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));

    int hook = luaL_checkinteger(L, 1);
    // pushvalue to dupe func and etc.
    // can leave original func on stack afterward because it'll get cleared.
    int loop_end = 0;
    int loop_start = 1;
    if (hook == CMD_ANY) {
        // if CMD_ANY we need individually set loop 1 to CMD_SIZE.
        loop_end = CMD_SIZE;
    } else if (hook == CMD_ANY_STORAGE) {
        // if CMD_ANY_STORAGE we only override get/set/etc.
        loop_end = CMD_END_STORAGE;
    } else {
        loop_start = hook;
        loop_end = hook + 1;
    }

    if (lua_isfunction(L, 2)) {
        struct proxy_hook *hooks = t->proxy_hooks;
        uint64_t tag = 0; // listener socket tag

        if (lua_isstring(L, 3)) {
            size_t len;
            const char *stag = lua_tolstring(L, 3, &len);
            if (len < 1 || len > 8) {
                proxy_lua_error(L, "mcp.attach: tag must be 1 to 8 characters");
                return 0;
            }
            memcpy(&tag, stag, len);
        }

        for (int x = loop_start; x < loop_end; x++) {
            struct proxy_hook *h = &hooks[x];
            lua_pushvalue(L, 2); // duplicate the function for the ref.

            if (tag) {
                // listener was tagged. use the extended hook structure.
                struct proxy_hook_tagged *pht = h->tagged;

                if (h->tagcount == 0) {
                    pht = calloc(1, sizeof(struct proxy_hook_tagged));
                    if (pht == NULL) {
                        proxy_lua_error(L, "mcp.attach: failure allocating tagged hooks");
                        return 0;
                    }
                    h->tagcount = 1;
                    h->tagged = pht;
                }

                bool found = false;
                for (int x = 0; x < h->tagcount; x++) {
                    if (pht->tag == tag) {
                        if (pht->lua_ref) {
                            // Found existing tagged hook.
                            luaL_unref(L, LUA_REGISTRYINDEX, pht->lua_ref);
                        }

                        pht->lua_ref = luaL_ref(L, LUA_REGISTRYINDEX);
                        assert(pht->lua_ref != 0);
                        found = true;
                        break;
                    } else if (pht->tag == 0) {
                        // no tag in this slot, so we use it.
                        pht->lua_ref = luaL_ref(L, LUA_REGISTRYINDEX);
                        pht->tag = tag;
                        assert(pht->lua_ref != 0);
                        found = true;
                        break;
                    }
                    pht++;
                }

                // need to resize the array to fit the new tag.
                if (!found) {
                    pht = realloc(h->tagged, sizeof(struct proxy_hook_tagged) * (h->tagcount+1));
                    if (!pht) {
                        proxy_lua_error(L, "mcp.attach: failure to resize tagged hooks");
                        return 0;
                    }

                    pht[h->tagcount].lua_ref = luaL_ref(L, LUA_REGISTRYINDEX);
                    pht[h->tagcount].tag = tag;

                    h->tagcount++;
                    h->tagged = pht;
                }

            } else {
                if (h->lua_ref) {
                    // remove existing reference.
                    luaL_unref(L, LUA_REGISTRYINDEX, h->lua_ref);
                }

                // pops the function from the stack and leaves us a ref. for later.
                h->lua_ref = luaL_ref(L, LUA_REGISTRYINDEX);
                assert(h->lua_ref != 0);
            }
        }
    } else {
        proxy_lua_error(L, "Must pass a function to mcp.attach");
        return 0;
    }

    return 0;
}

/*** START lua interface to logger ***/

static int mcplib_log(lua_State *L) {
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));
    const char *msg = luaL_checkstring(L, -1);
    LOGGER_LOG(t->l, LOG_PROXYUSER, LOGGER_PROXY_USER, NULL, msg);
    return 0;
}

// (request, resp, "detail")
static int mcplib_log_req(lua_State *L) {
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));
    logger *l = t->l;
    // Not using the LOGGER_LOG macro so we can avoid as much overhead as
    // possible when logging is disabled.
    if (! (l->eflags & LOG_PROXYREQS)) {
        return 0;
    }
    int rtype = 0;
    int rcode = 0;
    int rstatus = 0;
    char *rname = NULL;
    char *rport = NULL;

    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    int type = lua_type(L, 2);
    if (type == LUA_TUSERDATA) {
        mcp_resp_t *rs = luaL_checkudata(L, 2, "mcp.response");
        rtype = rs->resp.type;
        rcode = rs->resp.code;
        rstatus = rs->status;
        rname = rs->be_name;
        rport = rs->be_port;
    }
    size_t dlen = 0;
    const char *detail = luaL_optlstring(L, 3, NULL, &dlen);

    struct timeval end;
    gettimeofday(&end, NULL);
    long elapsed = (end.tv_sec - rq->start.tv_sec) * 1000000 + (end.tv_usec - rq->start.tv_usec);

    logger_log(l, LOGGER_PROXY_REQ, NULL, rq->pr.request, rq->pr.reqlen, elapsed, rtype, rcode, rstatus, detail, dlen, rname, rport);

    return 0;
}

static inline uint32_t _rotl(const uint32_t x, int k) {
    return (x << k) | (x >> (32 - k));
}

// xoroshiro128++ 32bit version.
static uint32_t _nextrand(uint32_t *s) {
    const uint32_t result = _rotl(s[0] + s[3], 7) + s[0];

    const uint32_t t = s[1] << 9;

    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];

    s[2] ^= t;

    s[3] = _rotl(s[3], 11);

    return result;
}


// (milliseconds, sample_rate, allerrors, request, resp, "detail")
static int mcplib_log_reqsample(lua_State *L) {
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));
    logger *l = t->l;
    // Not using the LOGGER_LOG macro so we can avoid as much overhead as
    // possible when logging is disabled.
    if (! (l->eflags & LOG_PROXYREQS)) {
        return 0;
    }
    int rtype = 0;
    int rcode = 0;
    int rstatus = 0;
    char *rname = NULL;
    char *rport = NULL;

    int ms = luaL_checkinteger(L, 1);
    int rate = luaL_checkinteger(L, 2);
    int allerr = lua_toboolean(L, 3);
    mcp_request_t *rq = luaL_checkudata(L, 4, "mcp.request");
    int type = lua_type(L, 5);
    if (type == LUA_TUSERDATA) {
        mcp_resp_t *rs = luaL_checkudata(L, 5, "mcp.response");
        rtype = rs->resp.type;
        rcode = rs->resp.code;
        rstatus = rs->status;
        rname = rs->be_name;
        rport = rs->be_port;
    }
    size_t dlen = 0;
    const char *detail = luaL_optlstring(L, 6, NULL, &dlen);

    struct timeval end;
    gettimeofday(&end, NULL);
    long elapsed = (end.tv_sec - rq->start.tv_sec) * 1000000 + (end.tv_usec - rq->start.tv_usec);

    bool do_log = false;
    if (allerr && rstatus != MCMC_OK) {
        do_log = true;
    } else if (ms > 0 && elapsed > ms * 1000) {
        do_log = true;
    } else if (rate > 0) {
        // slightly biased random-to-rate without adding a loop, which is
        // completely fine for this use case.
        uint32_t rnd = (uint64_t)_nextrand(t->proxy_rng) * (uint64_t)rate >> 32;
        if (rnd == 0) {
            do_log = true;
        }
    }

    if (do_log) {
        logger_log(l, LOGGER_PROXY_REQ, NULL, rq->pr.request, rq->pr.reqlen, elapsed, rtype, rcode, rstatus, detail, dlen, rname, rport);
    }

    return 0;
}

// TODO: slowsample
// _err versions?

/*** END lua interface to logger ***/

static void proxy_register_defines(lua_State *L) {
#define X(x) \
    lua_pushinteger(L, x); \
    lua_setfield(L, -2, #x);

    X(MCMC_CODE_STORED);
    X(MCMC_CODE_EXISTS);
    X(MCMC_CODE_DELETED);
    X(MCMC_CODE_TOUCHED);
    X(MCMC_CODE_VERSION);
    X(MCMC_CODE_NOT_FOUND);
    X(MCMC_CODE_NOT_STORED);
    X(MCMC_CODE_OK);
    X(MCMC_CODE_NOP);
    X(MCMC_CODE_MISS);
    X(P_OK);
    X(CMD_ANY);
    X(CMD_ANY_STORAGE);
    X(AWAIT_GOOD);
    X(AWAIT_ANY);
    X(AWAIT_OK);
    X(AWAIT_FIRST);
    CMD_FIELDS
#undef X
}

// Creates and returns the top level "mcp" module
int proxy_register_libs(LIBEVENT_THREAD *t, void *ctx) {
    lua_State *L = ctx;

    const struct luaL_Reg mcplib_backend_m[] = {
        {"set", NULL},
        {"__gc", mcplib_backend_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_request_m[] = {
        {"command", mcplib_request_command},
        {"key", mcplib_request_key},
        {"ltrimkey", mcplib_request_ltrimkey},
        {"rtrimkey", mcplib_request_rtrimkey},
        {"token", mcplib_request_token},
        {"ntokens", mcplib_request_ntokens},
        {"has_flag", mcplib_request_has_flag},
        {"flag_token", mcplib_request_flag_token},
        {"__tostring", NULL},
        {"__gc", mcplib_request_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_response_m[] = {
        {"ok", mcplib_response_ok},
        {"hit", mcplib_response_hit},
        {"vlen", mcplib_response_vlen},
        {"code", mcplib_response_code},
        {"line", mcplib_response_line},
        {"__gc", mcplib_response_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_pool_m[] = {
        {"__gc", mcplib_pool_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_pool_proxy_m[] = {
        {"__call", mcplib_pool_proxy_call},
        {"__gc", mcplib_pool_proxy_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_f [] = {
        {"pool", mcplib_pool},
        {"backend", mcplib_backend},
        {"request", mcplib_request},
        {"attach", mcplib_attach},
        {"add_stat", mcplib_add_stat},
        {"stat", mcplib_stat},
        {"await", mcplib_await},
        {"log", mcplib_log},
        {"log_req", mcplib_log_req},
        {"log_reqsample", mcplib_log_reqsample},
        {"backend_connect_timeout", mcplib_backend_connect_timeout},
        {"backend_retry_timeout", mcplib_backend_retry_timeout},
        {"backend_read_timeout", mcplib_backend_read_timeout},
        {"backend_failure_limit", mcplib_backend_failure_limit},
        {"tcp_keepalive", mcplib_tcp_keepalive},
        {NULL, NULL}
    };

    // TODO (v2): function + loop.
    luaL_newmetatable(L, "mcp.backend");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_backend_m, 0); // register methods
    lua_pop(L, 1);

    luaL_newmetatable(L, "mcp.request");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_request_m, 0); // register methods
    lua_pop(L, 1);

    luaL_newmetatable(L, "mcp.response");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_response_m, 0); // register methods
    lua_pop(L, 1);

    luaL_newmetatable(L, "mcp.pool");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_pool_m, 0); // register methods
    lua_pop(L, 1); // drop the hash selector metatable

    luaL_newmetatable(L, "mcp.pool_proxy");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_pool_proxy_m, 0); // register methods
    lua_pop(L, 1); // drop the hash selector metatable

    // create main library table.
    //luaL_newlib(L, mcplib_f);
    // TODO (v2): luaL_newlibtable() just pre-allocs the exact number of things
    // here.
    // can replace with createtable and add the num. of the constant
    // definitions.
    luaL_newlibtable(L, mcplib_f);
    proxy_register_defines(L);

    mcplib_open_hash_xxhash(L);
    lua_setfield(L, -2, "hash_xxhash");
    // hash function for selectors.
    // have to wrap the function in a struct because function pointers aren't
    // pointer pointers :)
    mcplib_open_dist_jump_hash(L);
    lua_setfield(L, -2, "dist_jump_hash");
    mcplib_open_dist_ring_hash(L);
    lua_setfield(L, -2, "dist_ring_hash");

    lua_pushlightuserdata(L, (void *)t); // upvalue for original thread
    lua_newtable(L); // upvalue for mcp.attach() table.

    // create weak table for storing backends by label.
    lua_newtable(L); // {}
    lua_newtable(L); // {}, {} for metatable
    lua_pushstring(L, "v"); // {}, {}, "v" for weak values.
    lua_setfield(L, -2, "__mode"); // {}, {__mode = "v"}
    lua_setmetatable(L, -2); // {__mt = {__mode = "v"} }

    luaL_setfuncs(L, mcplib_f, 3); // store upvalues.

    lua_setglobal(L, "mcp"); // set the lib table to mcp global.
    return 1;
}

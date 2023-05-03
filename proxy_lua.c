/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

// sad, I had to look this up...
#define NANOSECONDS(x) ((x) * 1E9 + 0.5)
#define MICROSECONDS(x) ((x) * 1E6 + 0.5)

// func prototype example:
// static int fname (lua_State *L)
// normal library open:
// int luaopen_mcp(lua_State *L) { }

static int mcplib_response_elapsed(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");
    lua_pushinteger(L, r->elapsed);
    return 1;
}

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
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    // FIXME: we handle the accounting here, but the actual response buffer is
    // freed elsewhere, after the network write.
    pthread_mutex_lock(&t->proxy_limit_lock);
    t->proxy_buffer_memory_used -= r->blen;
    pthread_mutex_unlock(&t->proxy_limit_lock);

    // On error/similar we might be holding the read buffer.
    // If the buf is handed off to mc_resp for return, this pointer is NULL
    if (r->buf != NULL) {
        free(r->buf);
    }

    // release our temporary mc_resp sub-object.
    if (r->cresp != NULL) {
        mc_resp *cresp = r->cresp;
        assert(r->thread != NULL);
        resp_free(r->thread, cresp);
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
static int mcplib_backend_wrap_gc(lua_State *L) {
    mcp_backend_wrap_t *bew = luaL_checkudata(L, -1, "mcp.backendwrap");
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    if (bew->be != NULL) {
        mcp_backend_t *be = bew->be;
        // TODO (v3): technically a race where a backend could be created,
        // queued, but not picked up before being gc'ed again. In practice
        // this is impossible but at some point we should close the loop here.
        // Since we're running in the config thread it could just busy poll
        // until the connection was picked up.
        assert(be->transferred);
        proxy_event_thread_t *e = be->event_thread;
        pthread_mutex_lock(&e->mutex);
        STAILQ_INSERT_TAIL(&e->beconn_head_in, be, beconn_next);
        pthread_mutex_unlock(&e->mutex);

        // Signal to check queue.
#ifdef USE_EVENTFD
        uint64_t u = 1;
        // TODO (v2): check result? is it ever possible to get a short write/failure
        // for an eventfd?
        if (write(e->be_event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
            assert(1 == 0);
        }
#else
        if (write(e->be_notify_send_fd, "w", 1) <= 0) {
            assert(1 == 0);
        }
#endif
    }

    STAT_DECR(ctx, backend_total, 1);

    return 0;
}

static int mcplib_backend_gc(lua_State *L) {
    return 0; // no-op.
}

// backend label object; given to pools which then find or create backend
// objects as necessary.
// allow optionally passing a table of arguments for extended options:
// { label = "etc", "host" = "127.0.0.1", port = "11211",
//   readtimeout = 0.5, connecttimeout = 1, retrytime = 3,
//   failurelimit = 3, tcpkeepalive = false }
static int mcplib_backend(lua_State *L) {
    size_t llen = 0;
    size_t nlen = 0;
    size_t plen = 0;
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    mcp_backend_label_t *be = lua_newuserdatauv(L, sizeof(mcp_backend_label_t), 0);
    memset(be, 0, sizeof(*be));
    const char *label;
    const char *name;
    const char *port;
    // copy global defaults for tunables.
    memcpy(&be->tunables, &ctx->tunables, sizeof(be->tunables));

    if (lua_istable(L, 1)) {

        // We don't pop the label/host/port strings so lua won't change them
        // until after the function call.
        if (lua_getfield(L, 1, "label") != LUA_TNIL) {
            label = luaL_checklstring(L, -1, &llen);
        } else {
            proxy_lua_error(L, "backend must have a label argument");
            return 0;
        }

        if (lua_getfield(L, 1, "host") != LUA_TNIL) {
            name = luaL_checklstring(L, -1, &nlen);
        } else {
            proxy_lua_error(L, "backend must have a host argument");
            return 0;
        }

        // TODO: allow a default port.
        if (lua_getfield(L, 1, "port") != LUA_TNIL) {
            port = luaL_checklstring(L, -1, &plen);
        } else {
            proxy_lua_error(L, "backend must have a port argument");
            return 0;
        }

        if (lua_getfield(L, 1, "tcpkeepalive") != LUA_TNIL) {
            be->tunables.tcp_keepalive = lua_toboolean(L, -1);
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "failurelimit") != LUA_TNIL) {
            int limit = luaL_checkinteger(L, -1);
            if (limit < 0) {
                proxy_lua_error(L, "failure_limit must be >= 0");
                return 0;
            }

            be->tunables.backend_failure_limit = limit;
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "connecttimeout") != LUA_TNIL) {
            lua_Number secondsf = luaL_checknumber(L, -1);
            lua_Integer secondsi = (lua_Integer) secondsf;
            lua_Number subseconds = secondsf - secondsi;

            be->tunables.connect.tv_sec = secondsi;
            be->tunables.connect.tv_usec = MICROSECONDS(subseconds);
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "retrytimeout") != LUA_TNIL) {
            lua_Number secondsf = luaL_checknumber(L, -1);
            lua_Integer secondsi = (lua_Integer) secondsf;
            lua_Number subseconds = secondsf - secondsi;

            be->tunables.retry.tv_sec = secondsi;
            be->tunables.retry.tv_usec = MICROSECONDS(subseconds);
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "readtimeout") != LUA_TNIL) {
            lua_Number secondsf = luaL_checknumber(L, -1);
            lua_Integer secondsi = (lua_Integer) secondsf;
            lua_Number subseconds = secondsf - secondsi;

            be->tunables.read.tv_sec = secondsi;
            be->tunables.read.tv_usec = MICROSECONDS(subseconds);
        }
        lua_pop(L, 1);

    } else {
        label = luaL_checklstring(L, 1, &llen);
        name = luaL_checklstring(L, 2, &nlen);
        port = luaL_checklstring(L, 3, &plen);
    }

    if (llen > MAX_LABELLEN-1) {
        proxy_lua_error(L, "backend label too long");
        return 0;
    }

    if (nlen > MAX_NAMELEN-1) {
        proxy_lua_error(L, "backend name too long");
        return 0;
    }

    if (plen > MAX_PORTLEN-1) {
        proxy_lua_error(L, "backend port too long");
        return 0;
    }

    memcpy(be->label, label, llen);
    be->label[llen] = '\0';
    memcpy(be->name, name, nlen);
    be->name[nlen] = '\0';
    memcpy(be->port, port, plen);
    be->port[plen] = '\0';
    be->llen = llen;
    if (lua_istable(L, 1)) {
        lua_pop(L, 3); // drop label, name, port.
    }
    luaL_getmetatable(L, "mcp.backend");
    lua_setmetatable(L, -2); // set metatable to userdata.

    return 1; // return be object.
}

// Called with the cache label at top of the stack.
static mcp_backend_wrap_t *_mcplib_backend_checkcache(lua_State *L, mcp_backend_label_t *bel) {
    // first check our reference table to compare.
    // Note: The upvalue won't be found unless we're running from a function with it
    // set as an upvalue.
    int ret = lua_gettable(L, lua_upvalueindex(MCP_BACKEND_UPVALUE));
    if (ret != LUA_TNIL) {
        mcp_backend_wrap_t *be_orig = luaL_checkudata(L, -1, "mcp.backendwrap");
        if (strncmp(be_orig->be->name, bel->name, MAX_NAMELEN) == 0
                && strncmp(be_orig->be->port, bel->port, MAX_PORTLEN) == 0
                && memcmp(&be_orig->be->tunables, &bel->tunables, sizeof(bel->tunables)) == 0) {
            // backend is the same, return it.
            return be_orig;
        } else {
            // backend not the same, pop from stack and make new one.
            lua_pop(L, 1);
        }
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    return NULL;
}

static mcp_backend_wrap_t *_mcplib_make_backendconn(lua_State *L, mcp_backend_label_t *bel,
        proxy_event_thread_t *e) {
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    mcp_backend_wrap_t *bew = lua_newuserdatauv(L, sizeof(mcp_backend_wrap_t), 0);
    luaL_getmetatable(L, "mcp.backendwrap");
    lua_setmetatable(L, -2); // set metatable to userdata.

    mcp_backend_t *be = calloc(1, sizeof(mcp_backend_t));
    if (be == NULL) {
        proxy_lua_error(L, "out of memory allocating backend connection");
        return NULL;
    }
    bew->be = be;

    strncpy(be->name, bel->name, MAX_NAMELEN+1);
    strncpy(be->port, bel->port, MAX_PORTLEN+1);
    memcpy(&be->tunables, &bel->tunables, sizeof(bel->tunables));
    STAILQ_INIT(&be->io_head);
    be->state = mcp_backend_read;

    // this leaves a permanent buffer on the backend, which is fine
    // unless you have billions of backends.
    // we can later optimize for pulling buffers from idle backends.
    be->rbuf = malloc(READ_BUFFER_SIZE);
    if (be->rbuf == NULL) {
        proxy_lua_error(L, "out of memory allocating backend");
        return NULL;
    }

    // initialize libevent.
    memset(&be->main_event, 0, sizeof(be->main_event));
    memset(&be->write_event, 0, sizeof(be->write_event));
    memset(&be->timeout_event, 0, sizeof(be->timeout_event));

    // initialize the client
    be->client = malloc(mcmc_size(MCMC_OPTION_BLANK));
    if (be->client == NULL) {
        proxy_lua_error(L, "out of memory allocating backend");
        return NULL;
    }
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

    be->event_thread = e;
    pthread_mutex_lock(&e->mutex);
    STAILQ_INSERT_TAIL(&e->beconn_head_in, be, beconn_next);
    pthread_mutex_unlock(&e->mutex);

    // Signal to check queue.
#ifdef USE_EVENTFD
    uint64_t u = 1;
    // TODO (v2): check result? is it ever possible to get a short write/failure
    // for an eventfd?
    if (write(e->be_event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
        assert(1 == 0);
    }
#else
    if (write(e->be_notify_send_fd, "w", 1) <= 0) {
        assert(1 == 0);
    }
#endif

    lua_pushvalue(L, -2); // push the label string back to the top.
    // Add this new backend connection to the object cache.
    lua_pushvalue(L, -2); // copy the backend reference to the top.
    // set our new backend wrapper object into the reference table.
    lua_settable(L, lua_upvalueindex(MCP_BACKEND_UPVALUE));
    // stack is back to having backend on the top.

    STAT_INCR(ctx, backend_total, 1);

    return bew;
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

// in the proxy object, we can alias a ptr to the pool to where it needs to be
// based on worker number or io_thread right?
static void _mcplib_pool_make_be_loop(lua_State *L, mcp_pool_t *p, int offset, proxy_event_thread_t *t) {
    // remember lua arrays are 1 indexed.
    for (int x = 1; x <= p->pool_size; x++) {
        mcp_pool_be_t *s = &p->pool[x-1 + (offset * p->pool_size)];
        lua_geti(L, 1, x); // get next server into the stack.
        // If we bail here, the pool _gc() should handle releasing any backend
        // references we made so far.
        mcp_backend_label_t *bel = luaL_checkudata(L, -1, "mcp.backend");

        // check label for pre-existing backend conn/wrapper
        // TODO (v2): there're native ways of "from C make lua strings"
        int toconcat = 1;
        if (p->beprefix[0] != '\0') {
            lua_pushstring(L, p->beprefix);
            toconcat++;
        }
        if (p->use_iothread) {
            lua_pushstring(L, ":io:");
            toconcat++;
        } else {
            lua_pushstring(L, ":w");
            lua_pushinteger(L, offset);
            lua_pushstring(L, ":");
            toconcat += 3;
        }
        lua_pushlstring(L, bel->label, bel->llen);
        lua_concat(L, toconcat);

        lua_pushvalue(L, -1); // copy the label string for the create method.
        mcp_backend_wrap_t *bew = _mcplib_backend_checkcache(L, bel);
        if (bew == NULL) {
            bew = _mcplib_make_backendconn(L, bel, t);
        }
        s->be = bew->be; // unwrap the backend connection for direct ref.
        bew->be->use_io_thread = p->use_iothread;

        // If found from cache or made above, the backend wrapper is on the
        // top of the stack, so we can now take its reference.
        // The wrapper abstraction allows the be memory to be owned by its
        // destination thread (IO thread/etc).

        s->ref = luaL_ref(L, LUA_REGISTRYINDEX); // references and pops object.
        lua_pop(L, 1); // pop the mcp.backend label object.
        lua_pop(L, 1); // drop extra label copy.
    }
}

// call with table of backends in 1
static void _mcplib_pool_make_be(lua_State *L, mcp_pool_t *p) {
    if (p->use_iothread) {
        proxy_ctx_t *ctx = PROXY_GET_CTX(L);
        _mcplib_pool_make_be_loop(L, p, 0, ctx->proxy_io_thread);
    } else {
        // TODO (v3) globals.
        for (int n = 0; n < settings.num_threads; n++) {
            LIBEVENT_THREAD *t = get_worker_thread(n);
            _mcplib_pool_make_be_loop(L, p, t->thread_baseid, t->proxy_event_thread);
        }
    }
}

// p = mcp.pool(backends, { dist = f, hashfilter = f, seed = "a", hash = f })
static int mcplib_pool(lua_State *L) {
    int argc = lua_gettop(L);
    luaL_checktype(L, 1, LUA_TTABLE);
    int n = luaL_len(L, 1); // get length of array table
    int workers = settings.num_threads; // TODO (v3): globals usage.

    size_t plen = sizeof(mcp_pool_t) + (sizeof(mcp_pool_be_t) * n * workers);
    mcp_pool_t *p = lua_newuserdatauv(L, plen, 0);
    // Zero the memory before use, so we can realibly use __gc to clean up
    memset(p, 0, plen);
    p->pool_size = n;
    p->use_iothread = true;
    // TODO (v2): Nicer if this is fetched from mcp.default_key_hash
    p->key_hasher = XXH3_64bits_withSeed;
    pthread_mutex_init(&p->lock, NULL);
    p->ctx = PROXY_GET_CTX(L);

    luaL_setmetatable(L, "mcp.pool");

    lua_pushvalue(L, -1); // dupe self for reference.
    p->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Allow passing an ignored nil as a second argument. Makes the lua easier
    int type = lua_type(L, 2);
    if (argc == 1 || type == LUA_TNIL) {
        _mcplib_pool_make_be(L, p);
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

    if (lua_getfield(L, 2, "iothread") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TBOOLEAN);
        int use_iothread = lua_toboolean(L, -1);
        if (use_iothread) {
            p->use_iothread = true;
        } else {
            p->use_iothread = false;
        }
        lua_pop(L, 1); // remove value.
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (lua_getfield(L, 2, "beprefix") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TSTRING);
        size_t len = 0;
        const char *bepfx = lua_tolstring(L, -1, &len);
        memcpy(p->beprefix, bepfx, len);
        p->beprefix[len+1] = '\0';
        lua_pop(L, 1); // pop beprefix string.
    } else {
        lua_pop(L, 1); // pop the nil.
    }
    _mcplib_pool_make_be(L, p);

    // stack: backends, options, mcp.pool
    if (lua_getfield(L, 2, "dist") != LUA_TNIL) {
        // overriding the distribution function.
        _mcplib_pool_dist(L, p);
        lua_pop(L, 1); // remove the dist table from stack.
    } else {
        lua_pop(L, 1); // pop the nil.

        // use the default dist if not specified with an override table.
        lua_getglobal(L, "mcp");
        // TODO (v2): decide on a mcp.default_dist and use that instead
        if (lua_getfield(L, -1, "dist_jump_hash") != LUA_TNIL) {
            _mcplib_pool_dist(L, p);
            lua_pop(L, 1); // pop "dist_jump_hash" value.
        } else {
            lua_pop(L, 1);
        }
        lua_pop(L, 1); // pop "mcp"
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

mcp_backend_t *mcplib_pool_proxy_call_helper(lua_State *L, mcp_pool_proxy_t *pp, const char *key, size_t len) {
    mcp_pool_t *p = pp->main;
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

    return pp->pool[lookup].be;
}

// hashfunc(request) -> backend(request)
// needs key from request object.
static int mcplib_pool_proxy_call(lua_State *L) {
    // internal args are the hash selector (self)
    mcp_pool_proxy_t *pp = luaL_checkudata(L, -2, "mcp.pool_proxy");
    // then request object.
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");

    // we have a fast path to the key/length.
    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot route commands without key");
        return 0;
    }
    const char *key = MCP_PARSER_KEY(rq->pr);
    size_t len = rq->pr.klen;
    rq->be = mcplib_pool_proxy_call_helper(L, pp, key, len);

    // now yield request, pool up.
    lua_pushinteger(L, MCP_YIELD_POOL);
    return lua_yield(L, 3);
}

static int mcplib_tcp_keepalive(lua_State *L) {
    luaL_checktype(L, -1, LUA_TBOOLEAN);
    int state = lua_toboolean(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    STAT_L(ctx);
    ctx->tunables.tcp_keepalive = state;
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_failure_limit(lua_State *L) {
    int limit = luaL_checkinteger(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    if (limit < 0) {
        proxy_lua_error(L, "backend_failure_limit must be >= 0");
        return 0;
    }

    STAT_L(ctx);
    ctx->tunables.backend_failure_limit = limit;
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_connect_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    STAT_L(ctx);
    ctx->tunables.connect.tv_sec = secondsi;
    ctx->tunables.connect.tv_usec = MICROSECONDS(subseconds);
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_retry_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    STAT_L(ctx);
    ctx->tunables.retry.tv_sec = secondsi;
    ctx->tunables.retry.tv_usec = MICROSECONDS(subseconds);
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_read_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    STAT_L(ctx);
    ctx->tunables.read.tv_sec = secondsi;
    ctx->tunables.read.tv_usec = MICROSECONDS(subseconds);
    STAT_UL(ctx);

    return 0;
}

static int mcplib_active_req_limit(lua_State *L) {
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    uint64_t limit = luaL_checkinteger(L, -1);

    if (limit == 0) {
        limit = UINT64_MAX;
    } else {
        // FIXME: global
        int tcount = settings.num_threads;
        // The actual limit is per-worker-thread, so divide it up.
        if (limit > tcount * 2) {
            limit /= tcount;
        }
    }

    STAT_L(ctx);
    ctx->active_req_limit = limit;
    STAT_UL(ctx);

    return 0;
}

// limit specified in kilobytes
static int mcplib_buffer_memory_limit(lua_State *L) {
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    uint64_t limit = luaL_checkinteger(L, -1);

    if (limit == 0) {
        limit = UINT64_MAX;
    } else {
        limit *= 1024;

        int tcount = settings.num_threads;
        if (limit > tcount * 2) {
            limit /= tcount;
        }

        ctx->buffer_memory_limit = limit;
    }

    return 0;
}

// mcp.attach(mcp.HOOK_NAME, function)
// fill hook structure: if lua function, use luaL_ref() to store the func
static int mcplib_attach(lua_State *L) {
    // Pull the original worker thread out of the shared mcplib upvalue.
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);

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
            if (x == CMD_MN) {
                // disallow overriding MN so client pipeline flushes work.
                // need to add flush support before allowing override
                continue;
            }
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
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    const char *msg = luaL_checkstring(L, -1);
    LOGGER_LOG(t->l, LOG_PROXYUSER, LOGGER_PROXY_USER, NULL, msg);
    return 0;
}

// (request, resp, "detail")
static int mcplib_log_req(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    logger *l = t->l;
    // Not using the LOGGER_LOG macro so we can avoid as much overhead as
    // possible when logging is disabled.
    if (! (l->eflags & LOG_PROXYREQS)) {
        return 0;
    }
    int rtype = 0;
    int rcode = 0;
    int rstatus = 0;
    long elapsed = 0;
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
        elapsed = rs->elapsed;
    }
    size_t dlen = 0;
    const char *detail = luaL_optlstring(L, 3, NULL, &dlen);

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
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    logger *l = t->l;
    // Not using the LOGGER_LOG macro so we can avoid as much overhead as
    // possible when logging is disabled.
    if (! (l->eflags & LOG_PROXYREQS)) {
        return 0;
    }
    int rtype = 0;
    int rcode = 0;
    int rstatus = 0;
    long elapsed = 0;
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
        elapsed = rs->elapsed;
    }
    size_t dlen = 0;
    const char *detail = luaL_optlstring(L, 6, NULL, &dlen);

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
    X(MCMC_CODE_END);
    X(MCMC_CODE_ERROR);
    X(MCMC_CODE_CLIENT_ERROR);
    X(MCMC_CODE_SERVER_ERROR);
    X(MCMC_ERR);
    X(P_OK);
    X(CMD_ANY);
    X(CMD_ANY_STORAGE);
    X(AWAIT_GOOD);
    X(AWAIT_ANY);
    X(AWAIT_OK);
    X(AWAIT_FIRST);
    X(AWAIT_FASTGOOD);
    X(AWAIT_BACKGROUND);
    CMD_FIELDS
#undef X
}

// Creates and returns the top level "mcp" module
int proxy_register_libs(void *ctx, LIBEVENT_THREAD *t, void *state) {
    lua_State *L = state;

    const struct luaL_Reg mcplib_backend_m[] = {
        {"__gc", mcplib_backend_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_backend_wrap_m[] = {
        {"__gc", mcplib_backend_wrap_gc},
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
        {"elapsed", mcplib_response_elapsed},
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

    const struct luaL_Reg mcplib_f_config [] = {
        {"pool", mcplib_pool},
        {"backend", mcplib_backend},
        {"add_stat", mcplib_add_stat},
        {"backend_connect_timeout", mcplib_backend_connect_timeout},
        {"backend_retry_timeout", mcplib_backend_retry_timeout},
        {"backend_read_timeout", mcplib_backend_read_timeout},
        {"backend_failure_limit", mcplib_backend_failure_limit},
        {"tcp_keepalive", mcplib_tcp_keepalive},
        {"active_req_limit", mcplib_active_req_limit},
        {"buffer_memory_limit", mcplib_buffer_memory_limit},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_f_routes [] = {
        {"internal", mcplib_internal},
        {"attach", mcplib_attach},
        {"await", mcplib_await},
        {"await_logerrors", mcplib_await_logerrors},
        {"log", mcplib_log},
        {"log_req", mcplib_log_req},
        {"log_reqsample", mcplib_log_reqsample},
        {"stat", mcplib_stat},
        {"request", mcplib_request},
        {NULL, NULL}
    };
    // VM's have void* extra space in the VM by default for fast-access to a
    // context pointer like this. In some cases upvalues are inaccessible (ie;
    // GC's) but we still need access to the proxy global context.
    void **extra = lua_getextraspace(L);

    if (t != NULL) {
        // If thread VM, extra is the libevent thread
        *extra = t;
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

        luaL_newmetatable(L, "mcp.pool_proxy");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_pool_proxy_m, 0); // register methods
        lua_pop(L, 1); // drop the hash selector metatable

        luaL_newlibtable(L, mcplib_f_routes);
    } else {
        // Change the extra space override for the configuration VM to just point
        // straight to ctx.
        *extra = ctx;

        luaL_newmetatable(L, "mcp.backend");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_backend_m, 0); // register methods
        lua_pop(L, 1);

        luaL_newmetatable(L, "mcp.backendwrap");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_backend_wrap_m, 0); // register methods
        lua_pop(L, 1);

        luaL_newmetatable(L, "mcp.pool");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_pool_m, 0); // register methods
        lua_pop(L, 1); // drop the hash selector metatable

        luaL_newlibtable(L, mcplib_f_config);
    }

    // create main library table.
    //luaL_newlib(L, mcplib_f);
    // TODO (v2): luaL_newlibtable() just pre-allocs the exact number of things
    // here.
    // can replace with createtable and add the num. of the constant
    // definitions.
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

    // create weak table for storing backends by label.
    lua_newtable(L); // {}
    lua_newtable(L); // {}, {} for metatable
    lua_pushstring(L, "v"); // {}, {}, "v" for weak values.
    lua_setfield(L, -2, "__mode"); // {}, {__mode = "v"}
    lua_setmetatable(L, -2); // {__mt = {__mode = "v"} }

    if (t != NULL) {
        luaL_setfuncs(L, mcplib_f_routes, 1); // store upvalues.
    } else {
        luaL_setfuncs(L, mcplib_f_config, 1); // store upvalues.
    }

    lua_setglobal(L, "mcp"); // set the lib table to mcp global.
    return 1;
}

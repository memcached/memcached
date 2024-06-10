/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"
#include "proxy_tls.h"
#include "storage.h" // for stats call

// func prototype example:
// static int fname (lua_State *L)
// normal library open:
// int luaopen_mcp(lua_State *L) { }

struct _mcplib_statctx_s {
    lua_State *L;
};

static void _mcplib_append_stats(const char *key, const uint16_t klen,
                  const char *val, const uint32_t vlen,
                  const void *cookie) {
    // k + v == 0 means END, but we don't use END for this lua API.
    if (klen == 0) {
        return;
    }

    // cookie -> struct
    const struct _mcplib_statctx_s *c = cookie;
    lua_State *L = c->L;
    // table should always be on the top.
    lua_pushlstring(L, key, klen);
    lua_pushlstring(L, val, vlen);
    lua_rawset(L, -3);
}

static void _mcplib_append_section_stats(const char *key, const uint16_t klen,
                  const char *val, const uint32_t vlen,
                  const void *cookie) {
    char stat[STAT_KEY_LEN];
    long section = 0;
    if (klen == 0) {
        return;
    }

    const struct _mcplib_statctx_s *c = cookie;
    lua_State *L = c->L;
    // table must be at the top when this function is called.
    int tidx = lua_absindex(L, -1);

    // NOTE: sscanf is not great, especially with numerics due to UD for out
    // of range data. It is safe to use here because we're generating the
    // strings, and we don't use this function on anything that has user
    // defined data (ie; stats proxy). Otherwise sscanf saves a lot of code so
    // we use it here.
    if (sscanf(key, "items:%ld:%s", &section, stat) == 2
            || sscanf(key, "%ld:%s", &section, stat) == 2) {
        // stats [items, slabs, conns]
        if (lua_rawgeti(L, tidx, section) == LUA_TNIL) {
            lua_pop(L, 1); // drop the nil
            // no sub-section table yet, create one.
            lua_newtable(L);
            lua_pushvalue(L, -1); // copy the table
            lua_rawseti(L, tidx, section); // remember the table
            // now top of stack is the table.
        }

        lua_pushstring(L, stat);
        lua_pushlstring(L, val, vlen);
        lua_rawset(L, -3); // put key/val into sub-table
        lua_pop(L, 1); // pop sub-table.
    } else {
        // normal stat counter.
        lua_pushlstring(L, key, klen);
        lua_pushlstring(L, val, vlen);
        lua_rawset(L, tidx);
    }
}

// reimplementation of proto_text.c:process_stat()
static int mcplib_server_stats(lua_State *L) {
    int argc = lua_gettop(L);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    lua_newtable(L); // the table to return.
    struct _mcplib_statctx_s c = {
        L,
    };

    if (argc == 0 || lua_isnil(L, 1)) {
        server_stats(&_mcplib_append_stats, &c);
        get_stats(NULL, 0, &_mcplib_append_stats, &c);
    } else {
        const char *cmd = luaL_checkstring(L, 1);
        if (strcmp(cmd, "settings") == 0) {
            process_stat_settings(&_mcplib_append_stats, &c);
        } else if (strcmp(cmd, "conns") == 0) {
            process_stats_conns(&_mcplib_append_section_stats, &c);
#ifdef EXTSTORE
        } else if (strcmp(cmd, "extstore") == 0) {
            process_extstore_stats(&_mcplib_append_stats, &c);
#endif
        } else if (strcmp(cmd, "proxy") == 0) {
            process_proxy_stats(ctx, &_mcplib_append_stats, &c);
        } else if (strcmp(cmd, "proxyfuncs") == 0) {
            process_proxy_funcstats(ctx, &_mcplib_append_stats, &c);
        } else if (strcmp(cmd, "proxybe") == 0) {
            process_proxy_bestats(ctx, &_mcplib_append_stats, &c);
        } else {
            if (get_stats(cmd, strlen(cmd), &_mcplib_append_section_stats, &c)) {
                // all good.
            } else {
                // unknown command.
                proxy_lua_error(L, "unknown subcommand passed to server_stats");
            }
        }
    }

    // return the table.
    return 1;
}

static lua_Integer _mcplib_backend_get_waittime(lua_Number secondsf) {
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    if (subseconds >= 0.5) {
        // Yes, I know this rounding is probably wrong. it's close enough.
        // Rounding functions have tricky portability and whole-integer
        // rounding is at least simpler to reason about.
        secondsi++;
    }
    if (secondsi < 1) {
        secondsi = 1;
    }
    return secondsi;
}

// take string, table as arg:
// name, { every =, rerun = false, func = f }
// repeat defaults to true
static int mcplib_register_cron(lua_State *L) {
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    const char *name = luaL_checkstring(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);

    // reserve an upvalue for storing the function.
    mcp_cron_t *ce = lua_newuserdatauv(L, sizeof(mcp_cron_t), 1);
    memset(ce, 0, sizeof(*ce));

    // default repeat.
    ce->repeat = true;
    // sync config generation.
    ce->gen = ctx->config_generation;

    if (lua_getfield(L, 2, "func") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TFUNCTION);
        lua_setiuservalue(L, 3, 1); // pop value
    } else {
        proxy_lua_error(L, "proxy cron entry missing 'func' field");
        return 0;
    }

    if (lua_getfield(L, 2, "rerun") != LUA_TNIL) {
        int rerun = lua_toboolean(L, -1);
        if (!rerun) {
            ce->repeat = false;
        }
    }
    lua_pop(L, 1); // pop val or nil

    // TODO: set a limit on 'every' so we don't have to worry about
    // underflows. a year? a month?
    if (lua_getfield(L, 2, "every") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TNUMBER);
        int every = lua_tointeger(L, -1);
        if (every < 1) {
            proxy_lua_error(L, "proxy cron entry 'every' must be > 0");
            return 0;
        }
        ce->every = every;
    } else {
        proxy_lua_error(L, "proxy cron entry missing 'every' field");
        return 0;
    }
    lua_pop(L, 1); // pop val or nil

    // schedule the next cron run
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    ce->next = now.tv_sec + ce->every;
    // we may adjust ce->next shortly, so don't update global yet.

    // valid cron entry, now place into cron table.
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->cron_ref);

    // first, check if a cron of this name already exists.
    // if so and the 'every' field matches, inherit its 'next' field
    // so we don't perpetually reschedule all crons.
    if (lua_getfield(L, -1, name) != LUA_TNIL) {
        mcp_cron_t *oldce = lua_touserdata(L, -1);
        if (ce->every == oldce->every) {
            ce->next = oldce->next;
        }
    }
    lua_pop(L, 1); // drop val/nil

    lua_pushvalue(L, 3); // duplicate cron entry
    lua_setfield(L, -2, name); // pop duplicate cron entry
    lua_pop(L, 1); // drop cron table

    // update central cron sleep.
    if (ctx->cron_next > ce->next) {
        ctx->cron_next = ce->next;
    }

    return 0;
}

// just set ctx->loading = true
// called from config thread, so config_lock must be held, so it's safe to
// modify protected ctx contents.
static int mcplib_schedule_config_reload(lua_State *L) {
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    ctx->loading = true;
    return 0;
}

static int mcplib_time_real_millis(lua_State *L) {
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    lua_Integer t = now.tv_nsec / 1000000 + now.tv_sec * 1000;
    lua_pushinteger(L, t);
    return 1;
}

static int mcplib_time_mono_millis(lua_State *L) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    lua_Integer t = now.tv_nsec / 1000000 + now.tv_sec * 1000;
    lua_pushinteger(L, t);
    return 1;
}

// end util funcs.

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

static int mcplib_response_gc(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");
    mcp_response_cleanup(t, r);

    return 0;
}

// Note that this can be called multiple times for a single object, as opposed
// to _gc. The cleanup routine is armored against repeat accesses by NULL'ing
// th efields it checks.
static int mcplib_response_close(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_resp_t *r = luaL_checkudata(L, 1, "mcp.response");
    mcp_response_cleanup(t, r);

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
        // There has to be at least one connection, and the event_thread will
        // always be the same.
        proxy_event_thread_t *e = be->be[0].event_thread;
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
    be->conncount = 1; // one connection per backend as default.

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

        if (lua_getfield(L, 1, "tls") != LUA_TNIL) {
            be->tunables.use_tls = lua_toboolean(L, -1);
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "failurelimit") != LUA_TNIL) {
            int limit = luaL_checkinteger(L, -1);
            if (limit < 0) {
                proxy_lua_error(L, "failurelimit must be >= 0");
                return 0;
            }

            be->tunables.backend_failure_limit = limit;
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "depthlimit") != LUA_TNIL) {
            int limit = luaL_checkinteger(L, -1);
            if (limit < 0) {
                proxy_lua_error(L, "depthlimit must be >= 0");
                return 0;
            }

            be->tunables.backend_depth_limit = limit;
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

        // TODO (v2): print deprecation warning.
        if (lua_getfield(L, 1, "retrytimeout") != LUA_TNIL) {
            be->tunables.retry.tv_sec =
                _mcplib_backend_get_waittime(luaL_checknumber(L, -1));
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "retrywaittime") != LUA_TNIL) {
            be->tunables.retry.tv_sec =
                _mcplib_backend_get_waittime(luaL_checknumber(L, -1));
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

        if (lua_getfield(L, 1, "down") != LUA_TNIL) {
            int down = lua_toboolean(L, -1);
            be->tunables.down = down;
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "flaptime") != LUA_TNIL) {
            lua_Number secondsf = luaL_checknumber(L, -1);
            lua_Integer secondsi = (lua_Integer) secondsf;
            lua_Number subseconds = secondsf - secondsi;

            be->tunables.flap.tv_sec = secondsi;
            be->tunables.flap.tv_usec = MICROSECONDS(subseconds);
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "flapbackofframp") != LUA_TNIL) {
            float ramp = luaL_checknumber(L, -1);
            if (ramp <= 1.1) {
                ramp = 1.1;
            }
            be->tunables.flap_backoff_ramp = ramp;
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "flapbackoffmax") != LUA_TNIL) {
            luaL_checknumber(L, -1);
            uint32_t max = lua_tointeger(L, -1);
            be->tunables.flap_backoff_max = max;
        }
        lua_pop(L, 1);

        if (lua_getfield(L, 1, "connections") != LUA_TNIL) {
            int c = luaL_checkinteger(L, -1);
            if (c <= 0) {
                proxy_lua_error(L, "backend connections argument must be >= 0");
                return 0;
            } else if (c > 8) {
                proxy_lua_error(L, "backend connections argument must be <= 8");
                return 0;
            }

            be->conncount = c;
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
                && be_orig->be->conncount == bel->conncount
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

    mcp_backend_t *be = calloc(1, sizeof(mcp_backend_t) + sizeof(struct mcp_backendconn_s) * bel->conncount);
    if (be == NULL) {
        proxy_lua_error(L, "out of memory allocating backend connection");
        return NULL;
    }
    bew->be = be;

    strncpy(be->name, bel->name, MAX_NAMELEN+1);
    strncpy(be->port, bel->port, MAX_PORTLEN+1);
    strncpy(be->label, bel->label, MAX_LABELLEN+1);
    memcpy(&be->tunables, &bel->tunables, sizeof(bel->tunables));
    be->conncount = bel->conncount;
    STAILQ_INIT(&be->io_head);

    for (int x = 0; x < bel->conncount; x++) {
        struct mcp_backendconn_s *bec = &be->be[x];
        bec->be_parent = be;
        memcpy(&bec->tunables, &bel->tunables, sizeof(bel->tunables));
        STAILQ_INIT(&bec->io_head);
        bec->state = mcp_backend_read;

        // this leaves a permanent buffer on the backend, which is fine
        // unless you have billions of backends.
        // we can later optimize for pulling buffers from idle backends.
        bec->rbuf = malloc(READ_BUFFER_SIZE);
        if (bec->rbuf == NULL) {
            proxy_lua_error(L, "out of memory allocating backend");
            return NULL;
        }

        // initialize the client
        bec->client = malloc(mcmc_size(MCMC_OPTION_BLANK));
        if (bec->client == NULL) {
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
        bec->connect_flags = flags;

        // FIXME: remove ifdef via an initialized checker? or
        // mcp_tls_backend_init response code?
#ifdef PROXY_TLS
        if (be->tunables.use_tls && !ctx->tls_ctx) {
            proxy_lua_error(L, "TLS requested but not initialized: call mcp.init_tls()");
            return NULL;
        }
#endif
        mcp_tls_backend_init(ctx, bec);

        bec->event_thread = e;
    }
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

    mcp_gobj_finalize(&p->g);

    luaL_unref(L, LUA_REGISTRYINDEX, p->phc_ref);

    for (int x = 0; x < p->pool_be_total; x++) {
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
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    int argc = lua_gettop(L);
    luaL_checktype(L, 1, LUA_TTABLE);
    int n = luaL_len(L, 1); // get length of array table
    int workers = settings.num_threads; // TODO (v3): globals usage.

    size_t plen = sizeof(mcp_pool_t) + (sizeof(mcp_pool_be_t) * n * workers);
    mcp_pool_t *p = lua_newuserdatauv(L, plen, 0);
    // Zero the memory before use, so we can realibly use __gc to clean up
    memset(p, 0, plen);
    p->pool_size = n;
    p->pool_be_total = n * workers;
    p->use_iothread = ctx->tunables.use_iothread;
    // TODO (v2): Nicer if this is fetched from mcp.default_key_hash
    p->key_hasher = XXH3_64bits_withSeed;
    pthread_mutex_init(&p->g.lock, NULL);
    p->ctx = PROXY_GET_CTX(L);

    luaL_setmetatable(L, "mcp.pool");

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
    pthread_mutex_lock(&p->g.lock);
    p->g.refcount--;
    if (p->g.refcount == 0) {
        proxy_ctx_t *ctx = p->ctx;
        pthread_mutex_lock(&ctx->manager_lock);
        STAILQ_INSERT_TAIL(&ctx->manager_head, &p->g, next);
        pthread_cond_signal(&ctx->manager_cond);
        pthread_mutex_unlock(&ctx->manager_lock);
    }
    pthread_mutex_unlock(&p->g.lock);

    return 0;
}

mcp_backend_t *mcplib_pool_proxy_call_helper(mcp_pool_proxy_t *pp, const char *key, size_t len) {
    mcp_pool_t *p = pp->main;
    if (p->key_filter) {
        key = p->key_filter(p->key_filter_conf, key, len, &len);
        P_DEBUG("%s: filtered key for hashing (%.*s)\n", __func__, (int)len, key);
    }
    uint64_t hash = p->key_hasher(key, len, p->hash_seed);
    uint32_t lookup = p->phc.selector_func(hash, p->phc.ctx);

    assert(p->phc.ctx != NULL);
    if (lookup >= p->pool_size) {
        return NULL;
    }

    return pp->pool[lookup].be;
}

// pool(request) -> yields the pool/request for further processing
static int mcplib_pool_proxy_call(lua_State *L) {
    mcp_pool_proxy_t *pp = luaL_checkudata(L, -2, "mcp.pool_proxy");
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");

    // we have a fast path to the key/length.
    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot route commands without key");
        return 0;
    }
    const char *key = MCP_PARSER_KEY(rq->pr);
    size_t len = rq->pr.klen;
    mcp_backend_t *be = mcplib_pool_proxy_call_helper(pp, key, len);
    if (be == NULL) {
        proxy_lua_error(L, "key dist hasher tried to use out of bounds index");
        return 0;
    }
    lua_pushlightuserdata(L, be);

    // now yield request, pool, backend, mode up.
    lua_pushinteger(L, MCP_YIELD_POOL);
    return lua_yield(L, 4);
}

static int mcplib_backend_use_iothread(lua_State *L) {
    luaL_checktype(L, -1, LUA_TBOOLEAN);
    int state = lua_toboolean(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    STAT_L(ctx);
    ctx->tunables.use_iothread = state;
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_use_tls(lua_State *L) {
    luaL_checktype(L, -1, LUA_TBOOLEAN);
    int state = lua_toboolean(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
#ifndef PROXY_TLS
    if (state == 1) {
        proxy_lua_error(L, "cannot set mcp.backend_use_tls: TLS support not compiled");
    }
#endif
    STAT_L(ctx);
    ctx->tunables.use_tls = state;
    STAT_UL(ctx);

    return 0;
}

// TODO: error checking.
static int mcplib_init_tls(lua_State *L) {
#ifndef PROXY_TLS
    proxy_lua_error(L, "cannot run mcp.init_tls: TLS support not compiled");
#else
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    mcp_tls_init(ctx);
#endif

    return 0;
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

static int mcplib_backend_depth_limit(lua_State *L) {
    int limit = luaL_checkinteger(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    if (limit < 0) {
        proxy_lua_error(L, "backend_depth_limit must be >= 0");
        return 0;
    }

    STAT_L(ctx);
    ctx->tunables.backend_depth_limit = limit;
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

static int mcplib_backend_retry_waittime(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    lua_Integer secondsi = _mcplib_backend_get_waittime(secondsf);

    STAT_L(ctx);
    ctx->tunables.retry.tv_sec = secondsi;
    ctx->tunables.retry.tv_usec = 0;
    STAT_UL(ctx);

    return 0;
}

// TODO (v2): deprecation notice print when using this function.
static int mcplib_backend_retry_timeout(lua_State *L) {
    return mcplib_backend_retry_waittime(L);
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

static int mcplib_backend_flap_time(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    STAT_L(ctx);
    ctx->tunables.flap.tv_sec = secondsi;
    ctx->tunables.flap.tv_usec = MICROSECONDS(subseconds);
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_flap_backoff_ramp(lua_State *L) {
    float factor = luaL_checknumber(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    if (factor <= 1.1) {
        factor = 1.1;
    }

    STAT_L(ctx);
    ctx->tunables.flap_backoff_ramp = factor;
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_flap_backoff_max(lua_State *L) {
    luaL_checknumber(L, -1);
    uint32_t max = lua_tointeger(L, -1);
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);

    STAT_L(ctx);
    ctx->tunables.flap_backoff_max = max;
    STAT_UL(ctx);

    return 0;
}

static int mcplib_stat_limit(lua_State *L) {
    proxy_ctx_t *ctx = PROXY_GET_CTX(L);
    int limit = luaL_checkinteger(L, -1);

    if (limit == 0) {
        limit = MAX_USTATS_DEFAULT;
    }
    if (limit > MAX_USTATS_DEFAULT) {
        fprintf(stderr, "PROXY WARNING: setting ustats limit above default may cause performance problems\n");
    }

    // lock isn't necessary as this is only used from the config thread.
    // keeping the lock call for code consistency.
    STAT_L(ctx);
    ctx->tunables.max_ustats = limit;
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
    }
    ctx->buffer_memory_limit = limit;

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

    mcp_funcgen_t *fgen = NULL;
    if (lua_isfunction(L, 2)) {
        // create a funcgen with null generator that calls this function
        lua_pushvalue(L, 2); // function must be at top of stack.
        mcplib_funcgenbare_new(L); // convert it into a function generator.
        fgen = luaL_checkudata(L, -1, "mcp.funcgen"); // set our pointer ref.
        lua_replace(L, 2); // move the function generator over the input
                           // function. necessary for alignment with the rest
                           // of the code.
        lua_pop(L, 1); // drop the extra generator function reference.
    } else if ((fgen = luaL_testudata(L, 2, "mcp.funcgen")) != NULL) {
        // good
    } else {
        proxy_lua_error(L, "mcp.attach: must pass a function");
        return 0;
    }

    if (fgen->closed) {
        proxy_lua_error(L, "mcp.attach: cannot use a previously replaced function");
        return 0;
    }

    {
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
            lua_pushvalue(L, 2); // duplicate the ref.
            struct proxy_hook_ref *href = &h->ref;

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
                    if (pht->tag == tag || pht->tag == 0) {
                        found = true;
                        break;
                    }
                    pht++;
                }

                // need to resize the array to fit the new tag.
                if (!found) {
                    struct proxy_hook_tagged *temp = realloc(h->tagged, sizeof(struct proxy_hook_tagged) * (h->tagcount+1));
                    if (!temp) {
                        proxy_lua_error(L, "mcp.attach: failure to resize tagged hooks");
                        return 0;
                    }
                    pht = &temp[h->tagcount];
                    memset(pht, 0, sizeof(*pht));
                    h->tagcount++;
                    h->tagged = temp;
                }

                href = &pht->ref;
                pht->tag = tag;
            }

            // now assign our hook reference.
            if (href->lua_ref) {
                // Found existing tagged hook.
                luaL_unref(L, LUA_REGISTRYINDEX, href->lua_ref);
                mcp_funcgen_dereference(L, href->ctx);
            }

            lua_pushvalue(L, -1); // duplicate the funcgen
            mcp_funcgen_reference(L);
            href->lua_ref = luaL_ref(L, LUA_REGISTRYINDEX);
            href->ctx = fgen;
            assert(href->lua_ref != 0);
        }
    }

    return 0;
}

/*** START lua interface to logger ***/

// user logger specific to the config thread
static int mcplib_ct_log(lua_State *L) {
    const char *msg = luaL_checkstring(L, -1);
    // The only difference is we pull the logger from thread local storage.
    LOGGER_LOG(NULL, LOG_PROXYUSER, LOGGER_PROXY_USER, NULL, msg);
    return 0;
}

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
    int cfd = luaL_optinteger(L, 4, 0);

    logger_log(l, LOGGER_PROXY_REQ, NULL, rq->pr.request, rq->pr.reqlen, elapsed, rtype, rcode, rstatus, cfd, detail, dlen, rname, rport);

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
    int cfd = luaL_optinteger(L, 7, 0);

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
        logger_log(l, LOGGER_PROXY_REQ, NULL, rq->pr.request, rq->pr.reqlen, elapsed, rtype, rcode, rstatus, cfd, detail, dlen, rname, rport);
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
#define Y(x, l) \
    lua_pushinteger(L, x); \
    lua_setfield(L, -2, l);

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
    Y(QWAIT_ANY, "WAIT_ANY");
    Y(QWAIT_OK, "WAIT_OK");
    Y(QWAIT_GOOD, "WAIT_GOOD");
    Y(QWAIT_FASTGOOD, "WAIT_FASTGOOD");
    Y(RQUEUE_R_GOOD, "RES_GOOD");
    Y(RQUEUE_R_OK, "RES_OK");
    Y(RQUEUE_R_ANY, "RES_ANY");
    CMD_FIELDS
#undef X
#undef Y

    lua_pushboolean(L, 1);
    lua_setfield(L, -2, "WAIT_RESUME");
}

// TODO: low priority malloc error handling.
static void proxy_register_startarg(lua_State *L) {
    int idx = lua_absindex(L, -1); // remember 'mcp' table.
    if (settings.proxy_startarg == NULL) {
        // no argument given.
        lua_pushboolean(L, 0);
        lua_setfield(L, idx, "start_arg");
        return;
    }

    char *sarg = strdup(settings.proxy_startarg);
    if (strchr(sarg, ':') == NULL) {
        // just upload the string
        lua_pushstring(L, sarg);
    } else {
        // split into a table and set that instead.
        lua_newtable(L);
        int nidx = lua_absindex(L, -1);
        char *b = NULL;
        for (char *p = strtok_r(sarg, ":", &b);
                p != NULL;
                p = strtok_r(NULL, ":", &b)) {
            char *e = NULL;
            char *name = strtok_r(p, "_", &e);
            lua_pushstring(L, name); // table -> key
            char *value = strtok_r(NULL, "_", &e);
            if (value == NULL) {
                lua_pushboolean(L, 1); // table -> key -> True
            } else {
                lua_pushstring(L, value); // table -> key -> value
            }
            lua_settable(L, nidx);
        }
    }
    free(sarg);
    lua_setfield(L, idx, "start_arg");
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
        {"flag_add", mcplib_request_flag_add},
        {"flag_set", mcplib_request_flag_set},
        {"flag_replace", mcplib_request_flag_replace},
        {"flag_del", mcplib_request_flag_del},
        {"match_res", mcplib_request_match_res},
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
        {"__close", mcplib_response_close},
        {"close", mcplib_response_close},
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

    const struct luaL_Reg mcplib_ratelim_tbf_m[] = {
        {"__call", mcplib_ratelim_tbf_call},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_ratelim_global_tbf_m[] = {
        {"__gc", mcplib_ratelim_global_tbf_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_ratelim_proxy_tbf_m[] = {
        {"__call", mcplib_ratelim_proxy_tbf_call},
        {"__gc", mcplib_ratelim_proxy_tbf_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_rcontext_m[] = {
        {"handle_set_cb", mcplib_rcontext_handle_set_cb},
        {"enqueue", mcplib_rcontext_enqueue},
        {"wait_cond", mcplib_rcontext_wait_cond},
        {"enqueue_and_wait", mcplib_rcontext_enqueue_and_wait},
        {"wait_handle", mcplib_rcontext_wait_handle},
        {"res_good", mcplib_rcontext_res_good},
        {"res_ok", mcplib_rcontext_res_ok},
        {"res_any", mcplib_rcontext_res_any},
        {"result", mcplib_rcontext_result},
        {"cfd", mcplib_rcontext_cfd},
        //{"sleep", mcplib_rcontext_sleep}, see comments on function
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_funcgen_m[] = {
        {"__gc", mcplib_funcgen_gc},
        {"new_handle", mcplib_funcgen_new_handle},
        {"ready", mcplib_funcgen_ready},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_f_config [] = {
        {"pool", mcplib_pool},
        {"backend", mcplib_backend},
        {"add_stat", mcplib_add_stat},
        {"ratelim_global_tbf", mcplib_ratelim_global_tbf},
        {"stat_limit", mcplib_stat_limit},
        {"backend_connect_timeout", mcplib_backend_connect_timeout},
        {"backend_retry_timeout", mcplib_backend_retry_timeout},
        {"backend_retry_waittime", mcplib_backend_retry_waittime},
        {"backend_read_timeout", mcplib_backend_read_timeout},
        {"backend_failure_limit", mcplib_backend_failure_limit},
        {"backend_depth_limit", mcplib_backend_depth_limit},
        {"backend_flap_time", mcplib_backend_flap_time},
        {"backend_flap_backoff_ramp", mcplib_backend_flap_backoff_ramp},
        {"backend_flap_backoff_max", mcplib_backend_flap_backoff_max},
        {"backend_use_iothread", mcplib_backend_use_iothread},
        {"backend_use_tls", mcplib_backend_use_tls},
        {"init_tls", mcplib_init_tls},
        {"tcp_keepalive", mcplib_tcp_keepalive},
        {"active_req_limit", mcplib_active_req_limit},
        {"buffer_memory_limit", mcplib_buffer_memory_limit},
        {"schedule_config_reload", mcplib_schedule_config_reload},
        {"register_cron", mcplib_register_cron},
        {"server_stats", mcplib_server_stats},
        {"log", mcplib_ct_log},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_f_routes [] = {
        {"internal", mcplib_internal},
        {"attach", mcplib_attach},
        {"funcgen_new", mcplib_funcgen_new},
        {"router_new", mcplib_router_new},
        {"await", mcplib_await},
        {"await_logerrors", mcplib_await_logerrors},
        {"log", mcplib_log},
        {"log_req", mcplib_log_req},
        {"log_reqsample", mcplib_log_reqsample},
        {"stat", mcplib_stat},
        {"request", mcplib_request},
        {"ratelim_tbf", mcplib_ratelim_tbf},
        {"time_real_millis", mcplib_time_real_millis},
        {"time_mono_millis", mcplib_time_mono_millis},
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

        luaL_newmetatable(L, "mcp.ratelim_tbf");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_ratelim_tbf_m, 0); // register methods
        lua_pop(L, 1);

        luaL_newmetatable(L, "mcp.ratelim_proxy_tbf");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_ratelim_proxy_tbf_m, 0); // register methods
        lua_pop(L, 1);

        luaL_newmetatable(L, "mcp.rcontext");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_rcontext_m, 0); // register methods
        lua_pop(L, 1);

        luaL_newmetatable(L, "mcp.funcgen");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_funcgen_m, 0); // register methods
        lua_pop(L, 1);

        // marks a special C-compatible route function.
        luaL_newmetatable(L, "mcp.rfunc");
        lua_pop(L, 1);

        // function generator userdata.
        luaL_newmetatable(L, "mcp.funcgen");
        lua_pop(L, 1);

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

        luaL_newmetatable(L, "mcp.ratelim_global_tbf");
        lua_pushvalue(L, -1); // duplicate metatable.
        lua_setfield(L, -2, "__index"); // mt.__index = mt
        luaL_setfuncs(L, mcplib_ratelim_global_tbf_m, 0); // register methods
        lua_pop(L, 1);

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

    // every VM gets a copy of the start arguments to work with.
    proxy_register_startarg(L);

    lua_setglobal(L, "mcp"); // set the lib table to mcp global.
    return 1;
}

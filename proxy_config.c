/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// Functions related to the configuration management threads and VM
// TODO (v2): move worker thread related code back out of here.

#include "proxy.h"

struct _dumpbuf {
    size_t size;
    size_t used;
    char *buf;
};

static int _dump_helper(lua_State *L, const void *p, size_t sz, void *ud) {
    (void)L;
    struct _dumpbuf *db = ud;
    if (db->used + sz > db->size) {
        db->size *= 2;
        char *nb = realloc(db->buf, db->size);
        if (nb == NULL) {
            return -1;
        }
        db->buf = nb;
    }
    memcpy(db->buf + db->used, (const char *)p, sz);
    db->used += sz;
    return 0;
}

static const char * _load_helper(lua_State *L, void *data, size_t *size) {
    (void)L;
    struct _dumpbuf *db = data;
    if (db->used == 0) {
        *size = 0;
        return NULL;
    }
    *size = db->used;
    db->used = 0;
    return db->buf;
}

void proxy_start_reload(void *arg) {
    proxy_ctx_t *ctx = arg;
    if (pthread_mutex_trylock(&ctx->config_lock) == 0) {
        pthread_cond_signal(&ctx->config_cond);
        pthread_mutex_unlock(&ctx->config_lock);
    }
}

// Manages a queue of inbound objects destined to be deallocated.
static void *_proxy_manager_thread(void *arg) {
    proxy_ctx_t *ctx = arg;
    pool_head_t head;

    pthread_mutex_lock(&ctx->manager_lock);
    while (1) {
        STAILQ_INIT(&head);
        while (STAILQ_EMPTY(&ctx->manager_head)) {
            pthread_cond_wait(&ctx->manager_cond, &ctx->manager_lock);
        }

        // pull dealloc queue into local queue.
        STAILQ_CONCAT(&head, &ctx->manager_head);
        pthread_mutex_unlock(&ctx->manager_lock);

        // Config lock is required for using config VM.
        pthread_mutex_lock(&ctx->config_lock);
        lua_State *L = ctx->proxy_state;
        mcp_pool_t *p;
        STAILQ_FOREACH(p, &head, next) {
            // we let the pool object _gc() handle backend references.

            luaL_unref(L, LUA_REGISTRYINDEX, p->phc_ref);
            // need to... unref self.
            // NOTE: double check if we really need to self-reference.
            // this is a backup here to ensure the external refcounts hit zero
            // before lua garbage collects the object. other things hold a
            // reference to the object though.
            luaL_unref(L, LUA_REGISTRYINDEX, p->self_ref);
        }
        pthread_mutex_unlock(&ctx->config_lock);

        // done.
        pthread_mutex_lock(&ctx->manager_lock);
    }

    return NULL;
}

// Thread handling the configuration reload sequence.
// TODO (v2): get a logger instance.
// TODO (v2): making this "safer" will require a few phases of work.
// 1) JFDI
// 2) "test VM" -> from config thread, test the worker reload portion.
// 3) "unit testing" -> from same temporary worker VM, execute set of
// integration tests that must pass.
// 4) run update on each worker, collecting new mcp.attach() hooks.
//    Once every worker has successfully executed and set new hooks, roll
//    through a _second_ time to actually swap the hook structures and unref
//    the old structures where marked dirty.
static void *_proxy_config_thread(void *arg) {
    proxy_ctx_t *ctx = arg;

    logger_create();
    pthread_mutex_lock(&ctx->config_lock);
    while (1) {
        pthread_cond_wait(&ctx->config_cond, &ctx->config_lock);
        LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_CONFIG, NULL, "start");
        STAT_INCR(ctx, config_reloads, 1);
        lua_State *L = ctx->proxy_state;
        lua_settop(L, 0); // clear off any crud that could have been left on the stack.

        // The main stages of config reload are:
        // - load and execute the config file
        // - run mcp_config_pools()
        // - for each worker:
        //   - copy and execute new lua code
        //   - copy selector table
        //   - run mcp_config_routes()

        if (proxy_load_config(ctx) != 0) {
            // Failed to load. log and wait for a retry.
            STAT_INCR(ctx, config_reload_fails, 1);
            LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_CONFIG, NULL, "failed");
            continue;
        }

        // TODO (v2): create a temporary VM to test-load the worker code into.
        // failing to load partway through the worker VM reloads can be
        // critically bad if we're not careful about references.
        // IE: the config VM _must_ hold references to selectors and backends
        // as long as they exist in any worker for any reason.

        for (int x = 0; x < settings.num_threads; x++) {
            LIBEVENT_THREAD *thr = get_worker_thread(x);

            pthread_mutex_lock(&ctx->worker_lock);
            ctx->worker_done = false;
            ctx->worker_failed = false;
            proxy_reload_notify(thr);
            while (!ctx->worker_done) {
                // in case of spurious wakeup.
                pthread_cond_wait(&ctx->worker_cond, &ctx->worker_lock);
            }
            pthread_mutex_unlock(&ctx->worker_lock);

            // Code load bailed.
            if (ctx->worker_failed) {
                STAT_INCR(ctx, config_reload_fails, 1);
                LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_CONFIG, NULL, "failed");
                continue;
            }
        }
        LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_CONFIG, NULL, "done");
    }

    return NULL;
}

int _start_proxy_config_threads(proxy_ctx_t *ctx) {
    int ret;

    pthread_mutex_lock(&ctx->config_lock);
    if ((ret = pthread_create(&ctx->config_tid, NULL,
                    _proxy_config_thread, ctx)) != 0) {
        fprintf(stderr, "Failed to start proxy configuration thread: %s\n",
                strerror(ret));
        pthread_mutex_unlock(&ctx->config_lock);
        return -1;
    }
    pthread_mutex_unlock(&ctx->config_lock);

    pthread_mutex_lock(&ctx->manager_lock);
    if ((ret = pthread_create(&ctx->manager_tid, NULL,
                    _proxy_manager_thread, ctx)) != 0) {
        fprintf(stderr, "Failed to start proxy configuration thread: %s\n",
                strerror(ret));
        pthread_mutex_unlock(&ctx->manager_lock);
        return -1;
    }
    pthread_mutex_unlock(&ctx->manager_lock);

    return 0;
}

int proxy_load_config(void *arg) {
    proxy_ctx_t *ctx = arg;
    lua_State *L = ctx->proxy_state;
    int res = luaL_loadfile(L, settings.proxy_startfile);
    if (res != LUA_OK) {
        fprintf(stderr, "ERROR: Failed to load proxy_startfile: %s\n", lua_tostring(L, -1));
        return -1;
    }
    // LUA_OK, LUA_ERRSYNTAX, LUA_ERRMEM, LUA_ERRFILE

    // Now we need to dump the compiled code into bytecode.
    // This will then get loaded into worker threads.
    struct _dumpbuf *db = malloc(sizeof(struct _dumpbuf));
    db->size = 16384;
    db->used = 0;
    db->buf = malloc(db->size);
    lua_dump(L, _dump_helper, db, 0);
    // 0 means no error.
    ctx->proxy_code = db;

    // now we complete the data load by calling the function.
    res = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (res != LUA_OK) {
        fprintf(stderr, "ERROR: Failed to load data into lua config state: %s\n", lua_tostring(L, -1));
        exit(EXIT_FAILURE);
    }

    // call the mcp_config_pools function to get the central backends.
    lua_getglobal(L, "mcp_config_pools");

    if (lua_isnil(L, -1)) {
        fprintf(stderr, "ERROR: Configuration file missing 'mcp_config_pools' function\n");
        exit(EXIT_FAILURE);
    }
    lua_pushnil(L); // no "old" config yet.
    if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
        fprintf(stderr, "ERROR: Failed to execute mcp_config_pools: %s\n", lua_tostring(L, -1));
        exit(EXIT_FAILURE);
    }

    // result is our main config.
    return 0;
}

static int _copy_pool(lua_State *from, lua_State *to) {
    // from, -3 should have he userdata.
    mcp_pool_t *p = luaL_checkudata(from, -3, "mcp.pool");
    size_t size = sizeof(mcp_pool_proxy_t);
    mcp_pool_proxy_t *pp = lua_newuserdatauv(to, size, 0);
    luaL_setmetatable(to, "mcp.pool_proxy");

    pp->main = p;
    pthread_mutex_lock(&p->lock);
    p->refcount++;
    pthread_mutex_unlock(&p->lock);
    return 0;
}

static void _copy_config_table(lua_State *from, lua_State *to);
// (from, -1) is the source value
// should end with (to, -1) being the new value.
static void _copy_config_table(lua_State *from, lua_State *to) {
    int type = lua_type(from, -1);
    bool found = false;
    luaL_checkstack(from, 4, "configuration error: table recursion too deep");
    luaL_checkstack(to, 4, "configuration error: table recursion too deep");
    switch (type) {
        case LUA_TNIL:
            lua_pushnil(to);
            break;
        case LUA_TUSERDATA:
            // see dump_stack() - check if it's something we handle.
            if (lua_getmetatable(from, -1) != 0) {
                lua_pushstring(from, "__name");
                if (lua_rawget(from, -2) != LUA_TNIL) {
                    const char *name = lua_tostring(from, -1);
                    if (strcmp(name, "mcp.pool") == 0) {
                        _copy_pool(from, to);
                        found = true;
                    }
                }
                lua_pop(from, 2);
            }
            if (!found) {
                proxy_lua_ferror(from, "unhandled userdata type in configuration table\n");
            }
            break;
        case LUA_TNUMBER:
            if (lua_isinteger(from, -1)) {
                lua_pushinteger(to, lua_tointeger(from, -1));
            } else {
                lua_pushnumber(to, lua_tonumber(from, -1));
            }
            break;
        case LUA_TSTRING:
            lua_pushlstring(to, lua_tostring(from, -1), lua_rawlen(from, -1));
            break;
        case LUA_TBOOLEAN:
            lua_pushboolean(to, lua_toboolean(from, -1));
            break;
        case LUA_TTABLE:
            // TODO (v2): copy the metatable first?
            // TODO (v2): size narr/nrec from old table and use createtable to
            // pre-allocate.
            lua_newtable(to); // throw new table on worker
            int t = lua_absindex(from, -1); // static index of table to copy.
            int nt = lua_absindex(to, -1); // static index of new table.
            lua_pushnil(from); // start iterator for main
            while (lua_next(from, t) != 0) {
                // (key, -2), (val, -1)
                int keytype = lua_type(from, -2);
                // to intentionally limit complexity and allow for future
                // optimizations we restrict what types may be used as keys
                // for sub-tables.
                switch (keytype) {
                    case LUA_TSTRING:
                        // to[l]string converts the actual key in the table
                        // into a string, so we must not do that unless it
                        // already is one.
                        lua_pushlstring(to, lua_tostring(from, -2), lua_rawlen(from, -2));
                        break;
                    case LUA_TNUMBER:
                        if (lua_isinteger(from, -1)) {
                            lua_pushinteger(to, lua_tointeger(from, -1));
                        } else {
                            lua_pushnumber(to, lua_tonumber(from, -1));
                        }
                        break;
                    default:
                        proxy_lua_error(from, "configuration table keys must be strings or numbers");
                }
                // lua_settable(to, n) - n being the table
                // takes -2 key -1 value, pops both.
                // use lua_absindex(L, -1) and so to convert easier?
                _copy_config_table(from, to); // push next value.
                lua_settable(to, nt);
                lua_pop(from, 1); // drop value, keep key.
            }
            // top of from is now the original table.
            // top of to should be the new table.
            break;
        default:
            proxy_lua_error(from, "unhandled data type in configuration table\n");
    }
}

// Run from proxy worker to coordinate code reload.
// config_lock must be held first.
void proxy_worker_reload(void *arg, LIBEVENT_THREAD *thr) {
    proxy_ctx_t *ctx = arg;
    pthread_mutex_lock(&ctx->worker_lock);
    if (proxy_thread_loadconf(thr) != 0) {
        ctx->worker_failed = true;
    }
    ctx->worker_done = true;
    pthread_cond_signal(&ctx->worker_cond);
    pthread_mutex_unlock(&ctx->worker_lock);
}

// FIXME (v2): need to test how to recover from an actual error here. error message
// needs to go somewhere useful, counters added, etc.
int proxy_thread_loadconf(LIBEVENT_THREAD *thr) {
    lua_State *L = thr->L;
    // load the precompiled config function.
    proxy_ctx_t *ctx = settings.proxy_ctx;
    struct _dumpbuf *db = ctx->proxy_code;
    struct _dumpbuf db2; // copy because the helper modifies it.
    memcpy(&db2, db, sizeof(struct _dumpbuf));

    lua_load(L, _load_helper, &db2, "config", NULL);
    // LUA_OK + all errs from loadfile except LUA_ERRFILE.
    //dump_stack(L);
    // - pcall the func (which should load it)
    int res = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (res != LUA_OK) {
        // FIXME (v2): don't exit here!
        fprintf(stderr, "Failed to load data into worker thread\n");
        return -1;
    }

    lua_getglobal(L, "mcp_config_routes");
    // create deepcopy of argument to pass into mcp_config_routes.
    // FIXME (v2): to avoid lua SIGABRT'ing on errors we need to protect the call
    // normal pattern:
    // lua_pushcfunction(L, &_copy_config_table);
    // lua_pushlightuserdata(L, &L2);
    // res = la_pcall(L, etc);
    // ... but since this is cross-VM we could get errors from not the
    // protected VM, breaking setjmp/etc.
    // for this part of the code we should override lua_atpanic(),
    // allowing us to specifically recover and bail.
    // However, again, this will require the next version of the config reload
    // code since we are re-using the VM's and a panic can leave us in a
    // broken state.
    // If the setjump/longjump combos are compatible a pcall for from and
    // atpanic for to might work best, since the config VM is/should be long
    // running and worker VM's should be rotated.
    _copy_config_table(ctx->proxy_state, L);

    // copied value is in front of route function, now call it.
    if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
        fprintf(stderr, "Failed to execute mcp_config_routes: %s\n", lua_tostring(L, -1));
        return -1;
    }

    // update user stats
    STAT_L(ctx);
    struct proxy_user_stats *us = &ctx->user_stats;
    struct proxy_user_stats *tus = NULL;
    if (us->num_stats != 0) {
        pthread_mutex_lock(&thr->stats.mutex);
        if (thr->proxy_user_stats == NULL) {
            tus = calloc(1, sizeof(struct proxy_user_stats));
            thr->proxy_user_stats = tus;
        } else {
            tus = thr->proxy_user_stats;
        }

        // originally this was a realloc routine but it felt fragile.
        // that might still be a better idea; still need to zero out the end.
        uint64_t *counters = calloc(us->num_stats, sizeof(uint64_t));

        // note that num_stats can _only_ grow in size.
        // we also only care about counters on the worker threads.
        if (tus->counters) {
            assert(tus->num_stats <= us->num_stats);
            memcpy(counters, tus->counters, tus->num_stats * sizeof(uint64_t));
            free(tus->counters);
        }

        tus->counters = counters;
        tus->num_stats = us->num_stats;
        pthread_mutex_unlock(&thr->stats.mutex);
    }
    STAT_UL(ctx);

    return 0;
}



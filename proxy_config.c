/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// Functions related to the configuration management threads and VM
// TODO (v2): move worker thread related code back out of here.

#include "proxy.h"

// not using queue.h becuase those require specific storage for HEAD.
// it's not possible to have the HEAD simply be in the proxy context because
// it would need to know the offset into this private structure.
// This might be doable but the problem is too trivial to spend time on it.
#define MCP_LUAFILE_SIZE 16384
struct _mcp_luafile {
    size_t size;
    size_t used;
    bool loaded; // flip this to false before each load use
    char *buf;
    char *fname; // filename to load
    struct _mcp_luafile *next;
};

static int _dump_helper(lua_State *L, const void *p, size_t sz, void *ud) {
    (void)L;
    struct _mcp_luafile *db = ud;
    if (db->used + sz > db->size) {
        // increase by blocks instead of doubling to avoid memory waste
        db->size += MCP_LUAFILE_SIZE;
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
    struct _mcp_luafile *db = data;
    if (db->loaded) {
        *size = 0;
        return NULL;
    }
    *size = db->used;
    db->loaded = true;
    return db->buf;
}

void proxy_start_reload(void *arg) {
    proxy_ctx_t *ctx = arg;
    if (pthread_mutex_trylock(&ctx->config_lock) == 0) {
        ctx->loading = true;
        pthread_cond_signal(&ctx->config_cond);
        pthread_mutex_unlock(&ctx->config_lock);
    }
}

int proxy_first_confload(void *arg) {
    proxy_ctx_t *ctx = arg;
    pthread_mutex_lock(&ctx->config_lock);
    ctx->loading = true;
    pthread_cond_signal(&ctx->config_cond);
    pthread_mutex_unlock(&ctx->config_lock);

    while (1) {
        bool stop = false;
        pthread_mutex_lock(&ctx->config_lock);
        if (!ctx->loading) {
            stop = true;
        }
        pthread_mutex_unlock(&ctx->config_lock);
        if (stop)
            break;
    }
    int fails = 0;
    STAT_L(ctx);
    fails = ctx->global_stats.config_reload_fails;
    STAT_UL(ctx);
    if (fails) {
        return -1;
    }

    return 0;
}

// Manages a queue of inbound objects destined to be deallocated.
static void *_proxy_manager_thread(void *arg) {
    proxy_ctx_t *ctx = arg;
    globalobj_head_t head;

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
        struct mcp_globalobj_s *g;
        STAILQ_FOREACH(g, &head, next) {
            // we let the object _gc() handle backend/etc references
            pthread_mutex_lock(&g->lock);
            assert(g->self_ref != -1);
            // See comment on mcp_gobj_ref()
            if (g->self_ref < -1) {
                g->refcount--;
                g->self_ref = -g->self_ref;
            }
            assert(g->self_ref > 0 || g->refcount == 0);
            if (g->refcount == 0) {
                luaL_unref(L, LUA_REGISTRYINDEX, g->self_ref);
                g->self_ref = -1;
            }
            pthread_mutex_unlock(&g->lock);
        }
        // force lua garbage collection so any resources close out quickly.
        lua_gc(L, LUA_GCCOLLECT);
        // twice because objects with garbage collector handlers are only
        // marked on the first collection cycle.
        lua_gc(L, LUA_GCCOLLECT);
        // must hold this lock while interacting with the config VM.
        pthread_mutex_unlock(&ctx->config_lock);

        // done.
        pthread_mutex_lock(&ctx->manager_lock);
    }

    return NULL;
}

// TODO: only run routine if something changed.
// This compacts all of the names for proxy user stats into a linear buffer,
// which can save considerable CPU when emitting a large number of stats. It
// also saves some total memory by having one linear buffer instead of many
// potentially small aligned allocations.
static void proxy_config_stats_prep(proxy_ctx_t *ctx) {
    char *oldnamebuf = ctx->user_stats_namebuf;
    struct proxy_user_stats_entry *entries = ctx->user_stats;
    size_t namelen = 0;

    STAT_L(ctx);
    // find size of new compact name buffer
    for (int x = 0; x < ctx->user_stats_num; x++) {
        if (entries[x].name) {
            namelen += strlen(entries[x].name) + 1; // null byte
        } else if (entries[x].cname) {
            char *name = oldnamebuf + entries[x].cname;
            namelen += strlen(name) + 1;
        }
    }
    // start one byte into the cname buffer so we can do faster checks on if a
    // name exists or not. so extend the buffer by one byte.
    namelen++;

    char *namebuf = calloc(1, namelen);
    // copy names into the compact buffer
    char *p = namebuf + 1;
    for (int x = 0; x < ctx->user_stats_num; x++) {
        struct proxy_user_stats_entry *e = &entries[x];
        char *newname = NULL;
        if (e->name) {
            // skip blank names.
            if (e->name[0]) {
                newname = e->name;
            }
        } else if (e->cname) {
            // else re-copy from old buffer
            newname = oldnamebuf + e->cname;
        }

        if (newname) {
            // set the buffer offset for this name
            e->cname = p - namebuf;
            // copy in the name
            size_t nlen = strlen(newname);
            memcpy(p, newname, nlen);
            p += nlen;
            *p = '\0'; // add null byte
            p++;
        } else {
            // name is blank or doesn't exist, ensure we skip it.
            e->cname = 0;
        }

        if (e->name) {
            // now get rid of the name buffer.
            free(e->name);
            e->name = NULL;
        }
    }

    ctx->user_stats_namebuf = namebuf;
    if (oldnamebuf) {
        free(oldnamebuf);
    }
    STAT_UL(ctx);
}

static void proxy_config_reload(proxy_ctx_t *ctx) {
    LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_CONFIG, NULL, "start");
    STAT_INCR(ctx, config_reloads, 1);
    // gen. used for tracking object lifecycles over time.
    // ie: ensuring old things are unloaded.
    ctx->config_generation++;
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
        return;
    }

    proxy_config_stats_prep(ctx);

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
            return;
        }
    }

    // Need to clear the reset flag for the stats system after pushing the new
    // config to each worker.
    STAT_L(ctx);
    for (int x = 0; x < ctx->user_stats_num; x++) {
        ctx->user_stats[x].reset = false;
    }
    STAT_UL(ctx);

    lua_pop(ctx->proxy_state, 1); // drop config_pools return value
    LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_CONFIG, NULL, "done");
}

// Very basic scheduler. Unsorted because we don't expect a huge list of
// functions to run.
static void proxy_run_crons(proxy_ctx_t *ctx) {
    lua_State *L = ctx->proxy_state;
    assert(lua_gettop(L) == 0);
    assert(ctx->cron_ref);
    struct timespec now;

    // Fetch the cron table. Created on startup so must exist.
    lua_rawgeti(L, LUA_REGISTRYINDEX, ctx->cron_ref);

    clock_gettime(CLOCK_REALTIME, &now);
    if (ctx->cron_next <= now.tv_sec) {
        ctx->cron_next = INT_MAX;
    } else {
        // no crons ready.
        return;
    }

    // Loop the cron entries.
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        const char *key = lua_tostring(L, -2);
        mcp_cron_t *ce = lua_touserdata(L, -1);
        int idx = lua_absindex(L, -1);

        // check generation.
        if (ctx->config_generation != ce->gen) {
            // remove entry.
            lua_pushnil(L);
            lua_setfield(L, 1, key);
        } else if (ce->next <= now.tv_sec) {
            // grab func and execute it
            lua_getiuservalue(L, idx, 1);
            // no arguments or return values
            int res = lua_pcall(L, 0, 0, 0);
            STAT_INCR(ctx, config_cron_runs, 1);
            if (res != LUA_OK) {
                LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_ERROR, NULL, lua_tostring(L, -1));
                STAT_INCR(ctx, config_cron_fails, 1);
                lua_pop(L, 1); // drop error.
            }

            if (ce->repeat) {
                ce->next = now.tv_sec + ce->every;
                // if rescheduled, check next against ctx. update if sooner
                if (ctx->cron_next > ce->next) {
                    ctx->cron_next = ce->next;
                }
            } else {
                // non-repeating cron. delete entry.
                lua_pushnil(L);
                lua_setfield(L, 1, key);
            }
        } else {
            // not scheduled to run now, but check if we're next.
            if (ctx->cron_next > ce->next) {
                ctx->cron_next = ce->next;
            }
        }

        lua_pop(L, 1); // drop value so we can loop.
    }

    lua_pop(L, 1); // drop cron table.
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
    struct timespec wait = {0};

    logger_create();
    pthread_mutex_lock(&ctx->config_lock);
    pthread_cond_signal(&ctx->config_cond);
    while (1) {
        ctx->loading = false;

        // cron only thinks in whole seconds.
        wait.tv_sec = ctx->cron_next;
        pthread_cond_timedwait(&ctx->config_cond, &ctx->config_lock, &wait);

        proxy_run_crons(ctx);

        if (ctx->loading) {
            proxy_config_reload(ctx);
        }
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
    thread_setname(ctx->config_tid, "mc-prx-config");
    // Avoid returning until the config thread has actually started.
    pthread_cond_wait(&ctx->config_cond, &ctx->config_lock);
    pthread_mutex_unlock(&ctx->config_lock);

    pthread_mutex_lock(&ctx->manager_lock);
    if ((ret = pthread_create(&ctx->manager_tid, NULL,
                    _proxy_manager_thread, ctx)) != 0) {
        fprintf(stderr, "Failed to start proxy manager thread: %s\n",
                strerror(ret));
        pthread_mutex_unlock(&ctx->manager_lock);
        return -1;
    }
    thread_setname(ctx->manager_tid, "mc-prx-manager");
    pthread_mutex_unlock(&ctx->manager_lock);

    return 0;
}

// this splits a list of lua startfiles into independent data chunk buffers
// we call this once the first time we start so we can use mallocs without
// having to armor against runtime malloc failures... as much.
static int proxy_init_startfiles(proxy_ctx_t *ctx, const char *files) {
    char *flist = strdup(settings.proxy_startfile);
    if (flist == NULL) {
        fprintf(stderr, "ERROR: failed to allocate memory for parsing proxy_startfile\n");
        return -1;
    }

    char *b;
    for (const char *p = strtok_r(flist, ":", &b);
            p != NULL;
            p = strtok_r(NULL, ":", &b)) {
        struct _mcp_luafile *db = calloc(sizeof(struct _mcp_luafile), 1);
        if (db == NULL) {
            fprintf(stderr, "ERROR: failed to allocate memory for parsing proxy_startfile\n");
            return -1;
        }
        db->size = MCP_LUAFILE_SIZE;
        db->buf = calloc(db->size, 1);
        db->fname = strdup(p);
        if (db->buf == NULL || db->fname == NULL) {
            fprintf(stderr, "ERROR: failed to allocate memory while parsing proxy_startfile\n");
            return -1;
        }

        // put new file at tail
        if (ctx->proxy_code == NULL) {
            ctx->proxy_code = db;
        } else {
            struct _mcp_luafile *list = ctx->proxy_code;
            while (list->next) {
                list = list->next;
            }
            assert(list->next == NULL);
            list->next = db;
        }
    }

    free(flist);
    return 0;
}

static int proxy_load_files(proxy_ctx_t *ctx) {
    lua_State *L = ctx->proxy_state;
    struct _mcp_luafile *db = ctx->proxy_code;
    assert(db);

    while (db) {
        int res;
        // clear the buffer for reuse.
        memset(db->buf, 0, db->size);
        db->used = 0;

        res = luaL_loadfile(L, db->fname);
        if (res != LUA_OK) {
            fprintf(stderr, "ERROR: Failed to load proxy_startfile: %s\n", lua_tostring(L, -1));
            return -1;
        }
        // LUA_OK, LUA_ERRSYNTAX, LUA_ERRMEM, LUA_ERRFILE

        // Now we need to dump the compiled code into bytecode.
        // This will then get loaded into worker threads.
        lua_dump(L, _dump_helper, db, 0);
        // 0 means no error.

        // now we complete the data load by calling the function.
        res = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (res != LUA_OK) {
            fprintf(stderr, "ERROR: Failed to load data into lua config state: %s\n", lua_tostring(L, -1));
            exit(EXIT_FAILURE);
        }

        db = db->next;
    }

    return 0;
}

int proxy_load_config(void *arg) {
    proxy_ctx_t *ctx = arg;
    lua_State *L = ctx->proxy_state;
    int res = 0;

    if (ctx->proxy_code == NULL) {
        res = proxy_init_startfiles(ctx, settings.proxy_startfile);
        if (res != 0) {
            return res;
        }
    }

    // load each of the data files in order.
    res = proxy_load_files(ctx);

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

static int _copy_pool(lua_State *from, lua_State *to, LIBEVENT_THREAD *thr) {
    // from, -3 should have the userdata.
    mcp_pool_t *p = luaL_checkudata(from, -3, "mcp.pool");
    size_t size = sizeof(mcp_pool_proxy_t);
    mcp_pool_proxy_t *pp = lua_newuserdatauv(to, size, 0);
    luaL_setmetatable(to, "mcp.pool_proxy");

    pp->main = p;
    if (p->use_iothread) {
        pp->pool = p->pool;
    } else {
        // allow 0 indexing for backends when unique to each worker thread
        pp->pool = &p->pool[thr->thread_baseid * p->pool_size];
    }
    lua_pushvalue(from, -3); // dupe pool for referencing
    mcp_gobj_ref(from, &p->g); // pops obj copy
    return 0;
}

static void _copy_config_table(lua_State *from, lua_State *to, LIBEVENT_THREAD *thr);
// (from, -1) is the source value
// should end with (to, -1) being the new value.
static void _copy_config_table(lua_State *from, lua_State *to, LIBEVENT_THREAD *thr) {
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
                        _copy_pool(from, to, thr);
                        found = true;
                    } else if (strcmp(name, "mcp.ratelim_global_tbf") == 0) {
                        mcp_ratelim_proxy_tbf(from, to);
                        found = true;
                    }
                }
                lua_pop(from, 2);
            }
            if (!found) {
                proxy_lua_error(from, "unhandled userdata type in configuration table\n");
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
                        if (lua_isinteger(from, -2)) {
                            lua_pushinteger(to, lua_tointeger(from, -2));
                        } else {
                            lua_pushnumber(to, lua_tonumber(from, -2));
                        }
                        break;
                    default:
                        proxy_lua_error(from, "configuration table keys must be strings or numbers");
                }
                // lua_settable(to, n) - n being the table
                // takes -2 key -1 value, pops both.
                // use lua_absindex(L, -1) and so to convert easier?
                _copy_config_table(from, to, thr); // push next value.
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
    if (proxy_thread_loadconf(ctx, thr) != 0) {
        ctx->worker_failed = true;
    }
    ctx->worker_done = true;
    pthread_cond_signal(&ctx->worker_cond);
    pthread_mutex_unlock(&ctx->worker_lock);
}

// FIXME (v2): need to test how to recover from an actual error here. error message
// needs to go somewhere useful, counters added, etc.
int proxy_thread_loadconf(proxy_ctx_t *ctx, LIBEVENT_THREAD *thr) {
    lua_State *L = thr->L;
    // load the precompiled config functions.

    struct _mcp_luafile *db = ctx->proxy_code;
    while (db) {
        db->loaded = false;
        int res = lua_load(L, _load_helper, db, "config", NULL);
        if (res != LUA_OK) {
            fprintf(stderr, "Failed to load data into worker thread: %s\n", lua_tostring(L, -1));
            return -1;
        }

        res = lua_pcall(L, 0, LUA_MULTRET, 0);
        if (res != LUA_OK) {
            // FIXME (v2): don't exit here!
            fprintf(stderr, "Failed to load data into worker thread: %s\n", lua_tostring(L, -1));
            return -1;
        }

        db = db->next;
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
    _copy_config_table(ctx->proxy_state, L, thr);

    // copied value is in front of route function, now call it.
    if (lua_pcall(L, 1, 0, 0) != LUA_OK) {
        fprintf(stderr, "Failed to execute mcp_config_routes: %s\n", lua_tostring(L, -1));
        return -1;
    }

    // update user stats
    STAT_L(ctx);
    struct proxy_user_stats_entry *us = ctx->user_stats;
    int stats_num = ctx->user_stats_num;
    struct proxy_user_stats *tus = NULL;
    if (stats_num != 0) {
        pthread_mutex_lock(&thr->stats.mutex);
        if (thr->proxy_user_stats == NULL) {
            tus = calloc(1, sizeof(struct proxy_user_stats));
            thr->proxy_user_stats = tus;
        } else {
            tus = thr->proxy_user_stats;
        }

        // originally this was a realloc routine but it felt fragile.
        // that might still be a better idea; still need to zero out the end.
        uint64_t *counters = calloc(stats_num, sizeof(uint64_t));

        // note that num_stats can _only_ grow in size.
        if (tus->counters) {
            // pull in old counters, if the names didn't change.
            for (int x = 0; x < tus->num_stats; x++) {
                if (us[x].reset) {
                    counters[x] = 0;
                } else {
                    counters[x] = tus->counters[x];
                }
            }
            assert(tus->num_stats <= stats_num);
            free(tus->counters);
        }
        tus->counters = counters;
        tus->num_stats = stats_num;

        pthread_mutex_unlock(&thr->stats.mutex);
    }
    // also grab the concurrent request limit
    thr->proxy_active_req_limit = ctx->active_req_limit;
    STAT_UL(ctx);

    // update limit counter(s)
    pthread_mutex_lock(&thr->proxy_limit_lock);
    thr->proxy_buffer_memory_limit = ctx->buffer_memory_limit;
    pthread_mutex_unlock(&thr->proxy_limit_lock);

    return 0;
}



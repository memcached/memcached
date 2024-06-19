/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Functions for handling the proxy layer. wraps text protocols
 *
 * NOTE: many lua functions generate pointers via "lua_newuserdatauv" or
 * similar. Normal memory checking isn't done as lua will throw a high level
 * error if malloc fails. Must keep this in mind while allocating data so any
 * manually malloc'ed information gets freed properly.
 */

#include "proxy.h"

#define PROCESS_MULTIGET true
#define PROCESS_NORMAL false
#define PROXY_GC_BACKGROUND_SECONDS 2
static void proxy_process_command(conn *c, char *command, size_t cmdlen, bool multiget);
static void *mcp_profile_alloc(void *ud, void *ptr, size_t osize, size_t nsize);

/******** EXTERNAL FUNCTIONS ******/
// functions starting with _ are breakouts for the public functions.

static inline void _proxy_advance_lastkb(lua_State *L, LIBEVENT_THREAD *t) {
    int new_kb = lua_gc(L, LUA_GCCOUNT);
    // We need to slew the increase in "gc pause" because the lua GC actually
    // needs to run twice to free a userdata: once to run the _gc's and again
    // to actually clean up the object.
    // Meaning we will continually increase in size.
    if (new_kb > t->proxy_vm_last_kb) {
        new_kb = t->proxy_vm_last_kb + (new_kb - t->proxy_vm_last_kb) * 0.50;
    }

    // remove the memory freed during this cycle so we can kick off the GC
    // early if we're very aggressively making garbage.
    // carry our negative delta forward so a huge reclaim can push for a
    // couple cycles.
    if (t->proxy_vm_negative_delta >= new_kb) {
        t->proxy_vm_negative_delta -= new_kb;
        new_kb = 1;
    } else {
        new_kb -= t->proxy_vm_negative_delta;
        t->proxy_vm_negative_delta = 0;
    }

    t->proxy_vm_last_kb = new_kb;
}

// The lua GC is paused while running requests. Run it manually inbetween
// processing network events.
void proxy_gc_poke(LIBEVENT_THREAD *t) {
    lua_State *L = t->L;
    struct proxy_int_stats *is = t->proxy_int_stats;
    int vm_kb = lua_gc(L, LUA_GCCOUNT) + t->proxy_vm_extra_kb;
    if (t->proxy_vm_last_kb == 0) {
        t->proxy_vm_last_kb = vm_kb;
    }
    WSTAT_L(t);
    is->vm_memory_kb = vm_kb;
    WSTAT_UL(t);

    // equivalent of luagc "pause" value
    int last = t->proxy_vm_last_kb;
    if (t->proxy_vm_gcrunning <= 0 && vm_kb > last * 2) {
        t->proxy_vm_gcrunning = 1;
        //fprintf(stderr, "PROXYGC: proxy_gc_poke START [cur: %d - last: %d]\n", vm_kb, last);
    }

    // We configure small GC "steps" then increase the number of times we run
    // a step based on current memory usage.
    if (t->proxy_vm_gcrunning > 0) {
        t->proxy_vm_needspoke = false;
        int loops = t->proxy_vm_gcrunning;
        int done = 0;
        /*fprintf(stderr, "PROXYGC: proxy_gc_poke [cur: %d - last: %d - loops: %d]\n",
            vm_kb,
            t->proxy_vm_last_kb,
            loops);*/
        while (loops-- && !done) {
            // reset counters once full GC cycle has completed
            done = lua_gc(L, LUA_GCSTEP, 0);
        }

        int vm_kb_after = lua_gc(L, LUA_GCCOUNT);
        int vm_kb_clean = vm_kb - t->proxy_vm_extra_kb;
        if (vm_kb_clean > vm_kb_after) {
            // track the amount of memory freed during the GC cycle.
            t->proxy_vm_negative_delta += vm_kb_clean - vm_kb_after;
        }

        if (done) {
            _proxy_advance_lastkb(L, t);
            t->proxy_vm_extra_kb = 0;
            t->proxy_vm_gcrunning = 0;
            WSTAT_L(t);
            is->vm_gc_runs++;
            WSTAT_UL(t);
            //fprintf(stderr, "PROXYGC: proxy_gc_poke COMPLETE [cur: %d next: %d]\n", lua_gc(L, LUA_GCCOUNT), t->proxy_vm_last_kb);
        }

        // increase the aggressiveness by memory bloat level.
        if (t->proxy_vm_gcrunning && (last*2) + (last * t->proxy_vm_gcrunning*0.25) < vm_kb) {
            t->proxy_vm_gcrunning++;
            //fprintf(stderr, "PROXYGC: proxy_gc_poke INCREASING AGGRESSIVENESS [cur: %d - aggro: %d]\n", t->proxy_vm_last_kb, t->proxy_vm_gcrunning);
        } else if (t->proxy_vm_gcrunning > 1) {
            // memory can drop during a run, let the GC slow down again.
            t->proxy_vm_gcrunning--;
            //fprintf(stderr, "PROXYGC: proxy_gc_poke DECREASING AGGRESSIVENESS [cur: %d - aggro: %d]\n", t->proxy_vm_last_kb, t->proxy_vm_gcrunning);
        }
    }
}

// every couple seconds we force-run one GC step.
// this is needed until after API1 is retired and pool objects are no longer
// managed by the GC.
// We use a negative value so a "timer poke" GC run doesn't cause requests to
// suddenly aggressively run the GC.
static void proxy_gc_timerpoke(evutil_socket_t fd, short event, void *arg) {
    LIBEVENT_THREAD *t = arg;
    struct timeval next = { PROXY_GC_BACKGROUND_SECONDS, 0 };
    evtimer_add(t->proxy_gc_timer, &next);
    // if GC ran within the last few seconds, don't do anything.
    if (!t->proxy_vm_needspoke) {
        t->proxy_vm_needspoke = true;
        return;
    }

    // if we weren't told to skip and there's otherwise no GC running, start a
    // GC run.
    if (t->proxy_vm_gcrunning == 0) {
        t->proxy_vm_gcrunning = -1;
    }

    // only advance GC if we're doing our own timer run.
    if (t->proxy_vm_gcrunning == -1 && lua_gc(t->L, LUA_GCSTEP, 0)) {
        _proxy_advance_lastkb(t->L, t);
        t->proxy_vm_extra_kb = 0;
        t->proxy_vm_gcrunning = 0;
    }
}

bool proxy_bufmem_checkadd(LIBEVENT_THREAD *t, int len) {
    bool oom = false;
    pthread_mutex_lock(&t->proxy_limit_lock);
    if (t->proxy_buffer_memory_used > t->proxy_buffer_memory_limit) {
        oom = true;
    } else {
        t->proxy_buffer_memory_used += len;
    }
    pthread_mutex_unlock(&t->proxy_limit_lock);
    return oom;
}

// see also: process_extstore_stats()
void proxy_stats(void *arg, ADD_STAT add_stats, void *c) {
    if (arg == NULL) {
       return;
    }
    proxy_ctx_t *ctx = arg;

    STAT_L(ctx);
    APPEND_STAT("proxy_config_reloads", "%llu", (unsigned long long)ctx->global_stats.config_reloads);
    APPEND_STAT("proxy_config_reload_fails", "%llu", (unsigned long long)ctx->global_stats.config_reload_fails);
    APPEND_STAT("proxy_config_cron_runs", "%llu", (unsigned long long)ctx->global_stats.config_cron_runs);
    APPEND_STAT("proxy_config_cron_fails", "%llu", (unsigned long long)ctx->global_stats.config_cron_fails);
    APPEND_STAT("proxy_backend_total", "%llu", (unsigned long long)ctx->global_stats.backend_total);
    APPEND_STAT("proxy_backend_marked_bad", "%llu", (unsigned long long)ctx->global_stats.backend_marked_bad);
    APPEND_STAT("proxy_backend_failed", "%llu", (unsigned long long)ctx->global_stats.backend_failed);
    APPEND_STAT("proxy_request_failed_depth", "%llu", (unsigned long long)ctx->global_stats.request_failed_depth);
    STAT_UL(ctx);
}

void process_proxy_stats(void *arg, ADD_STAT add_stats, void *c) {
    char key_str[STAT_KEY_LEN];
    struct proxy_int_stats istats = {0};
    uint64_t req_limit = 0;
    uint64_t buffer_memory_limit = 0;
    uint64_t buffer_memory_used = 0;

    if (!arg) {
        return;
    }
    proxy_ctx_t *ctx = arg;
    STAT_L(ctx);
    req_limit = ctx->active_req_limit;
    buffer_memory_limit = ctx->buffer_memory_limit;

    // prepare aggregated counters.
    struct proxy_user_stats_entry *us = ctx->user_stats;
    int stats_num = ctx->user_stats_num;
    uint64_t counters[stats_num];
    memset(counters, 0, sizeof(counters));

    // TODO (v3): more globals to remove and/or change API method.
    // aggregate worker thread counters.
    for (int x = 0; x < settings.num_threads; x++) {
        LIBEVENT_THREAD *t = get_worker_thread(x);
        struct proxy_user_stats *tus = t->proxy_user_stats;
        struct proxy_int_stats *is = t->proxy_int_stats;
        WSTAT_L(t);
        for (int i = 0; i < CMD_FINAL; i++) {
            istats.counters[i] += is->counters[i];
        }
        istats.vm_gc_runs += is->vm_gc_runs;
        istats.vm_memory_kb += is->vm_memory_kb;
        if (tus && tus->num_stats >= stats_num) {
            for (int i = 0; i < stats_num; i++) {
                counters[i] += tus->counters[i];
            }
        }
        WSTAT_UL(t);
        pthread_mutex_lock(&t->proxy_limit_lock);
        buffer_memory_used += t->proxy_buffer_memory_used;
        pthread_mutex_unlock(&t->proxy_limit_lock);
    }

    // return all of the user generated stats
    if (ctx->user_stats_namebuf) {
        char vbuf[INCR_MAX_STORAGE_LEN];
        char *e = NULL; // ptr into vbuf
        const char *pfx = "user_";
        const size_t pfxlen = strlen(pfx);
        for (int x = 0; x < stats_num; x++) {
            if (us[x].cname) {
                char *name = ctx->user_stats_namebuf + us[x].cname;
                size_t nlen = strlen(name);
                if (nlen > STAT_KEY_LEN-6) {
                    // impossible, but for paranoia.
                    nlen = STAT_KEY_LEN-6;
                }
                // avoiding an snprintf call for some performance ("user_%s")
                memcpy(key_str, pfx, pfxlen);
                memcpy(key_str+pfxlen, name, nlen);
                key_str[pfxlen+nlen] = '\0';

                // APPEND_STAT() calls another snprintf, which calls our
                // add_stats argument. Lets skip yet another snprintf with
                // some unrolling.
                e = itoa_u64(counters[x], vbuf);
                *(e+1) = '\0';
                add_stats(key_str, pfxlen+nlen, vbuf, e-vbuf, c);
            }
        }
    }

    STAT_UL(ctx);

    if (buffer_memory_limit == UINT64_MAX) {
        buffer_memory_limit = 0;
    } else {
        buffer_memory_limit *= settings.num_threads;
    }
    if (req_limit == UINT64_MAX) {
        req_limit = 0;
    } else {
        req_limit *= settings.num_threads;
    }

    // return proxy counters
    APPEND_STAT("active_req_limit", "%llu", (unsigned long long)req_limit);
    APPEND_STAT("buffer_memory_limit", "%llu", (unsigned long long)buffer_memory_limit);
    APPEND_STAT("buffer_memory_used", "%llu", (unsigned long long)buffer_memory_used);
    APPEND_STAT("vm_gc_runs", "%llu", (unsigned long long)istats.vm_gc_runs);
    APPEND_STAT("vm_memory_kb", "%llu", (unsigned long long)istats.vm_memory_kb);
    APPEND_STAT("cmd_mg", "%llu", (unsigned long long)istats.counters[CMD_MG]);
    APPEND_STAT("cmd_ms", "%llu", (unsigned long long)istats.counters[CMD_MS]);
    APPEND_STAT("cmd_md", "%llu", (unsigned long long)istats.counters[CMD_MD]);
    APPEND_STAT("cmd_mn", "%llu", (unsigned long long)istats.counters[CMD_MN]);
    APPEND_STAT("cmd_ma", "%llu", (unsigned long long)istats.counters[CMD_MA]);
    APPEND_STAT("cmd_me", "%llu", (unsigned long long)istats.counters[CMD_ME]);
    APPEND_STAT("cmd_get", "%llu", (unsigned long long)istats.counters[CMD_GET]);
    APPEND_STAT("cmd_gat", "%llu", (unsigned long long)istats.counters[CMD_GAT]);
    APPEND_STAT("cmd_set", "%llu", (unsigned long long)istats.counters[CMD_SET]);
    APPEND_STAT("cmd_add", "%llu", (unsigned long long)istats.counters[CMD_ADD]);
    APPEND_STAT("cmd_cas", "%llu", (unsigned long long)istats.counters[CMD_CAS]);
    APPEND_STAT("cmd_gets", "%llu", (unsigned long long)istats.counters[CMD_GETS]);
    APPEND_STAT("cmd_gats", "%llu", (unsigned long long)istats.counters[CMD_GATS]);
    APPEND_STAT("cmd_incr", "%llu", (unsigned long long)istats.counters[CMD_INCR]);
    APPEND_STAT("cmd_decr", "%llu", (unsigned long long)istats.counters[CMD_DECR]);
    APPEND_STAT("cmd_touch", "%llu", (unsigned long long)istats.counters[CMD_TOUCH]);
    APPEND_STAT("cmd_append", "%llu", (unsigned long long)istats.counters[CMD_APPEND]);
    APPEND_STAT("cmd_prepend", "%llu", (unsigned long long)istats.counters[CMD_PREPEND]);
    APPEND_STAT("cmd_delete", "%llu", (unsigned long long)istats.counters[CMD_DELETE]);
    APPEND_STAT("cmd_replace", "%llu", (unsigned long long)istats.counters[CMD_REPLACE]);
}

void process_proxy_funcstats(void *arg, ADD_STAT add_stats, void *c) {
    char key_str[STAT_KEY_LEN];
    if (!arg) {
        return;
    }
    proxy_ctx_t *ctx = arg;
    lua_State *L = ctx->proxy_sharedvm;
    pthread_mutex_lock(&ctx->sharedvm_lock);

    // iterate all of the named function slots
    lua_pushnil(L);
    while (lua_next(L, SHAREDVM_FGEN_IDX) != 0) {
        int n = lua_tointeger(L, -1);
        lua_pop(L, 1); // drop the value, leave the key.
        if (n != 0) {
            // reuse the key. make a copy since rawget will pop it.
            lua_pushvalue(L, -1);
            lua_rawget(L, SHAREDVM_FGENSLOT_IDX);
            int slots = lua_tointeger(L, -1);
            lua_pop(L, 1); // drop the slot count.

            // now grab the name key.
            const char *name = lua_tostring(L, -1);
            snprintf(key_str, STAT_KEY_LEN-1, "funcs_%s", name);
            APPEND_STAT(key_str, "%d", n);
            snprintf(key_str, STAT_KEY_LEN-1, "slots_%s", name);
            APPEND_STAT(key_str, "%d", slots);
        } else {
            // TODO: It is safe to delete keys here. Slightly complex so low
            // priority.
        }
    }

    pthread_mutex_unlock(&ctx->sharedvm_lock);
}

void process_proxy_bestats(void *arg, ADD_STAT add_stats, void *c) {
    char key_str[STAT_KEY_LEN];
    if (!arg) {
        return;
    }
    proxy_ctx_t *ctx = arg;
    lua_State *L = ctx->proxy_sharedvm;
    pthread_mutex_lock(&ctx->sharedvm_lock);

    // iterate all of the listed backends
    lua_pushnil(L);
    while (lua_next(L, SHAREDVM_BACKEND_IDX) != 0) {
        int n = lua_tointeger(L, -1);
        lua_pop(L, 1); // drop the value, leave the key.
        if (n != 0) {
            // now grab the name key.
            const char *name = lua_tostring(L, -1);
            snprintf(key_str, STAT_KEY_LEN-1, "bad_%s", name);
            APPEND_STAT(key_str, "%d", n);
        } else {
            // delete keys of backends that are no longer bad or no longer
            // exist to keep the table small.
            const char *name = lua_tostring(L, -1);
            lua_pushnil(L);
            lua_setfield(L, SHAREDVM_BACKEND_IDX, name);
        }
    }

    pthread_mutex_unlock(&ctx->sharedvm_lock);
}

// start the centralized lua state and config thread.
void *proxy_init(bool use_uring, bool proxy_memprofile) {
    proxy_ctx_t *ctx = calloc(1, sizeof(proxy_ctx_t));
    ctx->use_uring = use_uring;
    ctx->memprofile = proxy_memprofile;

    pthread_mutex_init(&ctx->config_lock, NULL);
    pthread_cond_init(&ctx->config_cond, NULL);
    pthread_mutex_init(&ctx->worker_lock, NULL);
    pthread_cond_init(&ctx->worker_cond, NULL);
    pthread_mutex_init(&ctx->manager_lock, NULL);
    pthread_cond_init(&ctx->manager_cond, NULL);
    pthread_mutex_init(&ctx->stats_lock, NULL);

    ctx->active_req_limit = UINT64_MAX;
    ctx->buffer_memory_limit = UINT64_MAX;

    // FIXME (v2): default defines.
    ctx->tunables.tcp_keepalive = false;
    ctx->tunables.backend_failure_limit = 3;
    ctx->tunables.connect.tv_sec = 5;
    ctx->tunables.retry.tv_sec = 3;
    ctx->tunables.read.tv_sec = 3;
    ctx->tunables.flap_backoff_ramp = 1.5;
    ctx->tunables.flap_backoff_max = 3600;
    ctx->tunables.backend_depth_limit = 0;
    ctx->tunables.max_ustats = MAX_USTATS_DEFAULT;
    ctx->tunables.use_iothread = false;
    ctx->tunables.use_tls = false;

    STAILQ_INIT(&ctx->manager_head);
    lua_State *L = NULL;
    if (ctx->memprofile) {
        struct mcp_memprofile *prof = calloc(1, sizeof(struct mcp_memprofile));
        prof->id = ctx->memprofile_thread_counter++;
        L = lua_newstate(mcp_profile_alloc, prof);
    } else {
        L = luaL_newstate();
    }
    ctx->proxy_state = L;
    luaL_openlibs(L);
    // NOTE: might need to differentiate the libs yes?
    proxy_register_libs(ctx, NULL, L);
    // Create the cron table.
    lua_newtable(L);
    ctx->cron_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    ctx->cron_next = INT_MAX;

    // set up the shared state VM. Used by short-lock events (counters/state)
    // for global visibility.
    pthread_mutex_init(&ctx->sharedvm_lock, NULL);
    ctx->proxy_sharedvm = luaL_newstate();
    luaL_openlibs(ctx->proxy_sharedvm);
    // we keep info tables in the top level stack so we don't have to
    // constantly fetch them from registry.
    lua_newtable(ctx->proxy_sharedvm); // fgen count
    lua_newtable(ctx->proxy_sharedvm); // fgen slot count
    lua_newtable(ctx->proxy_sharedvm); // backend down status

    // Create/start the IO thread, which we need before servers
    // start getting created.
    proxy_event_thread_t *t = calloc(1, sizeof(proxy_event_thread_t));
    ctx->proxy_io_thread = t;
    proxy_init_event_thread(t, ctx, NULL);

    pthread_create(&t->thread_id, NULL, proxy_event_thread, t);
    thread_setname(t->thread_id, "mc-prx-io");

    _start_proxy_config_threads(ctx);
    return ctx;
}

// Initialize the VM for an individual worker thread.
void proxy_thread_init(void *ctx, LIBEVENT_THREAD *thr) {
    assert(ctx != NULL);
    assert(thr != NULL);

    // Create the hook table.
    thr->proxy_hooks = calloc(CMD_SIZE, sizeof(struct proxy_hook));
    if (thr->proxy_hooks == NULL) {
        fprintf(stderr, "Failed to allocate proxy hooks\n");
        exit(EXIT_FAILURE);
    }
    thr->proxy_int_stats = calloc(1, sizeof(struct proxy_int_stats));
    if (thr->proxy_int_stats == NULL) {
        fprintf(stderr, "Failed to allocate proxy thread stats\n");
        exit(EXIT_FAILURE);
    }
    pthread_mutex_init(&thr->proxy_limit_lock, NULL);
    thr->proxy_ctx = ctx;

    // Initialize the lua state.
    proxy_ctx_t *pctx = ctx;
    lua_State *L = NULL;
    if (pctx->memprofile) {
        struct mcp_memprofile *prof = calloc(1, sizeof(struct mcp_memprofile));
        prof->id = pctx->memprofile_thread_counter++;
        L = lua_newstate(mcp_profile_alloc, prof);
    } else {
        L = luaL_newstate();
    }

    // With smaller requests the default incremental collector appears to
    // never complete. With this simple tuning (def-1, def, def) it seems
    // fine.
    // We can't use GCGEN until we manage pools with reference counting, as
    // they may never hit GC and thus never release their connection
    // resources.
    lua_gc(L, LUA_GCINC, 199, 100, 12);
    lua_gc(L, LUA_GCSTOP); // handle GC on our own schedule.
    thr->L = L;
    luaL_openlibs(L);
    proxy_register_libs(ctx, thr, L);
    // TODO: srand on time? do we need to bother?
    for (int x = 0; x < 3; x++) {
        thr->proxy_rng[x] = rand();
    }

    thr->proxy_gc_timer = evtimer_new(thr->base, proxy_gc_timerpoke, thr);
    // kick off the timer loop.
    proxy_gc_timerpoke(0, 0, thr);

    // Create a proxy event thread structure to piggyback on the worker.
    proxy_event_thread_t *t = calloc(1, sizeof(proxy_event_thread_t));
    thr->proxy_event_thread = t;
    proxy_init_event_thread(t, ctx, thr->base);
}

// ctx_stack is a stack of io_pending_proxy_t's.
// head of q->s_ctx is the "newest" request so we must push into the head
// of the next queue, as requests are dequeued from the head
void proxy_submit_cb(io_queue_t *q) {
    proxy_event_thread_t *e = ((proxy_ctx_t *)q->ctx)->proxy_io_thread;
    io_pending_proxy_t *p = q->stack_ctx;
    io_head_t head;
    be_head_t w_head; // worker local stack.
    STAILQ_INIT(&head);
    STAILQ_INIT(&w_head);

    // NOTE: responses get returned in the correct order no matter what, since
    // mc_resp's are linked.
    // we just need to ensure stuff is parsed off the backend in the correct
    // order.
    // So we can do with a single list here, but we need to repair the list as
    // responses are parsed. (in the req_remaining-- section)
    // TODO (v2):
    // - except we can't do that because the deferred IO stack isn't
    // compatible with queue.h.
    // So for now we build the secondary list with an STAILQ, which
    // can be transplanted/etc.
    while (p) {
        mcp_backend_t *be;
        P_DEBUG("%s: queueing req for backend: %p\n", __func__, (void *)p);
        if (p->qcount_incr) {
            // funny workaround: awaiting IOP's don't count toward
            // resuming a connection, only the completion of the await
            // condition.
            q->count++;
        }

        if (p->await_background) {
            P_DEBUG("%s: fast-returning await_background object: %p\n", __func__, (void *)p);
            // intercept await backgrounds
            // this call cannot recurse if we're on the worker thread,
            // since the worker thread has to finish executing this
            // function in order to pick up the returned IO.
            return_io_pending((io_pending_t *)p);
            p = p->next;
            continue;
        }
        be = p->backend;

        if (be->use_io_thread) {
            STAILQ_INSERT_HEAD(&head, p, io_next);
        } else {
            // emulate some of handler_dequeue()
            STAILQ_INSERT_HEAD(&be->io_head, p, io_next);
            assert(be->depth > -1);
            be->depth++;
            if (!be->stacked) {
                be->stacked = true;
                STAILQ_INSERT_TAIL(&w_head, be, be_next);
            }
        }

        p = p->next;
    }

    // clear out the submit queue so we can re-queue new IO's inline.
    q->stack_ctx = NULL;

    if (!STAILQ_EMPTY(&head)) {
        bool do_notify = false;
        P_DEBUG("%s: submitting queue to IO thread\n", __func__);
        // Transfer request stack to event thread.
        pthread_mutex_lock(&e->mutex);
        if (STAILQ_EMPTY(&e->io_head_in)) {
            do_notify = true;
        }
        STAILQ_CONCAT(&e->io_head_in, &head);
        // No point in holding the lock since we're not doing a cond signal.
        pthread_mutex_unlock(&e->mutex);

        if (do_notify) {
        // Signal to check queue.
#ifdef USE_EVENTFD
        uint64_t u = 1;
        // TODO (v2): check result? is it ever possible to get a short write/failure
        // for an eventfd?
        if (write(e->event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
            assert(1 == 0);
        }
#else
        if (write(e->notify_send_fd, "w", 1) <= 0) {
            assert(1 == 0);
        }
#endif
        }
    }

    if (!STAILQ_EMPTY(&w_head)) {
        P_DEBUG("%s: running inline worker queue\n", __func__);
        // emulating proxy_event_handler
        proxy_run_backend_queue(&w_head);
    }
    return;
}

// This function handles return processing for the "old style" API: direct
// pool calls and mcp.await()
void proxy_return_rctx_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;
    if (p->client_resp && p->client_resp->blen) {
        // FIXME: workaround for buffer memory being external to objects.
        // can't run 0 since that means something special (run the GC)
        unsigned int kb = p->client_resp->blen / 1000;
        p->thread->proxy_vm_extra_kb += kb > 0 ? kb : 1;
    }

    if (p->is_await) {
        p->rctx->async_pending--;
        mcplib_await_return(p);
        // need to directly attempt to return the context,
        // we may or may not be hitting proxy_run_rcontext from await_return.
        if (p->rctx->async_pending == 0) {
            mcp_funcgen_return_rctx(p->rctx);
        }
        return;
    }

    mcp_rcontext_t *rctx = p->rctx;
    lua_rotate(rctx->Lc, 1, 1);
    lua_settop(rctx->Lc, 1);
    // hold the resp for a minute.
    mc_resp *resp = rctx->resp;

    proxy_run_rcontext(rctx);
    mcp_funcgen_return_rctx(rctx);

    io_queue_t *q = conn_io_queue_get(p->c, p->io_queue_type);
    // Detatch the iop from the mc_resp and free it here.
    conn *c = p->c;
    if (p->io_type != IO_PENDING_TYPE_EXTSTORE) {
        // if we're doing an extstore subrequest, the iop needs to live until
        // resp's ->finish_cb is called.
        resp->io_pending = NULL;
        do_cache_free(p->thread->io_cache, p);
    }

    q->count--;
    if (q->count == 0) {
        // call re-add directly since we're already in the worker thread.
        conn_worker_readd(c);
    }
}

// This is called if resp_finish is called while an iop exists on the
// resp.
// so we need to release our iop and rctx.
// - This can't happen unless we're doing extstore fetches.
// - the request context is freed before connection processing resumes.
void proxy_finalize_rctx_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;

    if (p->io_type == IO_PENDING_TYPE_EXTSTORE) {
        if (p->hdr_it) {
            // TODO: lock once, worst case this hashes/locks twice.
            if (p->miss) {
                item_unlink(p->hdr_it);
            }
            item_remove(p->hdr_it);
        }
    }
}

int try_read_command_proxy(conn *c) {
    char *el, *cont;

    if (c->rbytes == 0)
        return 0;

    el = memchr(c->rcurr, '\n', c->rbytes);
    if (!el) {
        if (c->rbytes > 1024) {
            /*
             * We didn't have a '\n' in the first k. This _has_ to be a
             * large multiget, if not we should just nuke the connection.
             */
            char *ptr = c->rcurr;
            while (*ptr == ' ') { /* ignore leading whitespaces */
                ++ptr;
            }

            if (ptr - c->rcurr > 100 ||
                (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {

                conn_set_state(c, conn_closing);
                return 1;
            }

            // ASCII multigets are unbound, so our fixed size rbuf may not
            // work for this particular workload... For backcompat we'll use a
            // malloc/realloc/free routine just for this.
            if (!c->rbuf_malloced) {
                if (!rbuf_switch_to_malloc(c)) {
                    conn_set_state(c, conn_closing);
                    return 1;
                }
            }
        }

        return 0;
    }
    cont = el + 1;

    assert(cont <= (c->rcurr + c->rbytes));

    c->last_cmd_time = current_time;
    proxy_process_command(c, c->rcurr, cont - c->rcurr, PROCESS_NORMAL);

    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    assert(c->rcurr <= (c->rbuf + c->rsize));

    return 1;

}

// Called when a connection is closed while in nread state reading a set
// Must only be called with an active coroutine.
void proxy_cleanup_conn(conn *c) {
    assert(c->proxy_rctx);
    LIBEVENT_THREAD *thr = c->thread;
    mcp_rcontext_t *rctx = c->proxy_rctx;
    assert(rctx->pending_reqs == 1);
    rctx->pending_reqs = 0;

    mcp_funcgen_return_rctx(rctx);
    c->proxy_rctx = NULL;
    WSTAT_DECR(thr, proxy_req_active, 1);
}

// we buffered a SET of some kind.
void complete_nread_proxy(conn *c) {
    assert(c != NULL);

    LIBEVENT_THREAD *thr = c->thread;
    lua_State *L = thr->L;

    if (c->proxy_rctx == NULL) {
        complete_nread_ascii(c);
        return;
    }

    conn_set_state(c, conn_new_cmd);

    assert(c->proxy_rctx);
    mcp_rcontext_t *rctx = c->proxy_rctx;
    mcp_request_t *rq = rctx->request;

    if (strncmp((char *)c->item + rq->pr.vlen - 2, "\r\n", 2) != 0) {
        lua_settop(L, 0); // clear anything remaining on the main thread.
        // FIXME (v2): need to set noreply false if mset_res, but that's kind
        // of a weird hack to begin with. Evaluate how to best do that here.
        out_string(c, "CLIENT_ERROR bad data chunk");
        rctx->pending_reqs--;
        mcp_funcgen_return_rctx(rctx);
        return;
    }

    // We move ownership of the c->item buffer from the connection to the
    // request object here. Else we can double free if the conn closes while
    // inside nread.
    rq->pr.vbuf = c->item;
    c->item = NULL;
    c->item_malloced = false;
    c->proxy_rctx = NULL;
    pthread_mutex_lock(&thr->proxy_limit_lock);
    thr->proxy_buffer_memory_used += rq->pr.vlen;
    pthread_mutex_unlock(&thr->proxy_limit_lock);

    proxy_run_rcontext(rctx);
    mcp_funcgen_return_rctx(rctx);

    lua_settop(L, 0); // clear anything remaining on the main thread.

    return;
}

// Simple error wrapper for common failures.
// lua_error() is a jump so this function never returns
// for clarity add a 'return' after calls to this.
void proxy_lua_error(lua_State *L, const char *s) {
    lua_pushstring(L, s);
    lua_error(L);
}

// Need a custom function so we can prefix lua strings easily.
void proxy_out_errstring(mc_resp *resp, char *type, const char *str) {
    size_t len;
    size_t prefix_len = strlen(type);

    assert(resp != NULL);

    resp_reset(resp);
    // avoid noreply since we're throwing important errors.

    // Fill response object with static string.
    len = strlen(str);
    if ((len + prefix_len + 2) > WRITE_BUFFER_SIZE) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    char *w = resp->wbuf;
    memcpy(w, type, prefix_len);
    w += prefix_len;

    memcpy(w, str, len);
    w += len;

    memcpy(w, "\r\n", 2);
    resp_add_iov(resp, resp->wbuf, len + prefix_len + 2);
    return;
}

// NOTE: See notes in mcp_queue_io; the secondary problem with setting the
// noreply mode from the response object is that the proxy can return strings
// manually, so we have no way to obey what the original request wanted in
// that case.
static void _set_noreply_mode(mc_resp *resp, mcp_resp_t *r) {
    switch (r->mode) {
        case RESP_MODE_NORMAL:
            break;
        case RESP_MODE_NOREPLY:
            // ascii noreply only threw egregious errors to client
            if (r->status == MCMC_OK) {
                resp->skip = true;
            }
            break;
        case RESP_MODE_METAQUIET:
            if (r->resp.code == MCMC_CODE_END) {
                resp->skip = true;
            } else if (r->cmd != CMD_MG && r->resp.code == MCMC_CODE_OK) {
                // FIXME (v2): mcmc's parser needs to help us out a bit more
                // here.
                // This is a broken case in the protocol though; quiet mode
                // ignores HD for mutations but not get.
                resp->skip = true;
            }
            break;
        default:
            assert(1 == 0);
    }
}

static void _proxy_run_rcontext_queues(mcp_rcontext_t *rctx) {
    for (int x = 0; x < rctx->fgen->max_queues; x++) {
        mcp_run_rcontext_handle(rctx, x);
    }
}

static void _proxy_run_tresp_to_resp(mc_resp *tresp, mc_resp *resp) {
    // The internal cache handler has created a resp we want to swap in
    // here. It would be fastest to swap *resp's position in the
    // link but if the set is deep this would instead be slow, so
    // we copy over details from this temporary resp instead.

    // So far all we fill is the wbuf and some iov's? so just copy
    // that + the UDP info?
    memcpy(resp->wbuf, tresp->wbuf, tresp->iov[0].iov_len);
    resp->tosend = 0;
    for (int x = 0; x < tresp->iovcnt; x++) {
        resp->iov[x] = tresp->iov[x];
        resp->tosend += tresp->iov[x].iov_len;
    }
    // resp->iov[x].iov_base needs to be updated if it's
    // pointing within its wbuf.
    // FIXME: This is too fragile. we need to be able to
    // inherit details and swap resp objects around.
    if (tresp->iov[0].iov_base == tresp->wbuf) {
        resp->iov[0].iov_base = resp->wbuf;
    }
    resp->iovcnt = tresp->iovcnt;
    resp->chunked_total = tresp->chunked_total;
    resp->chunked_data_iov = tresp->chunked_data_iov;
    // copy UDP headers...
    resp->request_id = tresp->request_id;
    resp->udp_sequence = tresp->udp_sequence;
    resp->udp_total = tresp->udp_total;
    resp->request_addr = tresp->request_addr;
    resp->request_addr_size = tresp->request_addr_size;
    resp->item = tresp->item; // will be populated if not extstore fetch
    tresp->item = NULL; // move ownership of the item to resp from tresp
    resp->skip = tresp->skip;
}

// HACK NOTES:
// These are self-notes for dormando mostly.
// The IO queue system does not work well with the proxy, as we need to:
// - only increment q->count during the submit phase
//   - .. because a resumed coroutine can queue more data.
//   - and we will never hit q->count == 0
//   - .. and then never resume the main connection. (conn_worker_readd)
//   - which will never submit the new sub-requests
// - need to only increment q->count once per stack of requests coming from a
//   resp.
//
// There are workarounds for this all over. In the await code, we test for
// "the first await object" or "is an await background object", for
// incrementing the q->count
// For pool-backed requests we always increment in submit
// For RQU backed requests (new API) there isn't an easy place to test for
// "the first request", because:
// - The connection queue is a stack of _all_ requests pending on this
// connection, and many requests can arrive in one batch.
//   - Thus we cannot simply check if there are items in the queue
// - RQU's can be recursive, so we have to loop back to the parent to check to
//   see if we're the first queue or not.
//
// This hack workaround exists so I can fix the IO queue subsystem as a change
// independent of the RCTX change, as the IO queue touches everything and
// scares the shit out of me. It's much easier to make changes to it in
// isolation, when all existing systems are currently working and testable.
//
// Description of the hack:
// - in mcp_queue_io: roll up rctx to parent, and if we are the first IO to queue
// since the rcontext started, set p->qcounr_incr = true
// Later in submit_cb:
// - q->count++ if p->qcount_incr.
//
// Finally, in proxy_return_rqu_cb:
// - If parent completed non-yielded work, q->count-- to allow conn
// resumption.
// - At bottom of rqu_cb(), flush any IO queues for the connection in case we
// re-queued work.
int proxy_run_rcontext(mcp_rcontext_t *rctx) {
    int nresults = 0;
    lua_State *Lc = rctx->Lc;
    assert(rctx->lua_narg != 0);
    int cores = lua_resume(Lc, NULL, rctx->lua_narg, &nresults);
    rctx->lua_narg = 1; // reset to default since not-default is uncommon.
    size_t rlen = 0;
    conn *c = rctx->c;
    mc_resp *resp = rctx->resp;

    if (cores == LUA_OK) {
        // don't touch the result object if we were a sub-context.
        if (!rctx->parent) {
            WSTAT_DECR(c->thread, proxy_req_active, 1);
            int type = lua_type(Lc, 1);
            mcp_resp_t *r = NULL;
            P_DEBUG("%s: coroutine completed. return type: %d\n", __func__, type);
            if (type == LUA_TUSERDATA && (r = luaL_testudata(Lc, 1, "mcp.response")) != NULL) {
                _set_noreply_mode(resp, r);
                if (r->status != MCMC_OK && r->resp.type != MCMC_RESP_ERRMSG) {
                    proxy_out_errstring(resp, PROXY_SERVER_ERROR, "backend failure");
                } else if (r->cresp) {
                    mc_resp *tresp = r->cresp;
                    assert(c != NULL);

                    _proxy_run_tresp_to_resp(tresp, resp);
                    // we let the mcp_resp gc handler free up tresp and any
                    // associated io_pending's of its own later.
                } else if (r->buf) {
                    // response set from C.
                    resp->write_and_free = r->buf;
                    resp_add_iov(resp, r->buf, r->blen);
                    // stash the length to later remove from memory tracking
                    resp->wbytes = r->blen + r->extra;
                    resp->proxy_res = true;
                    r->buf = NULL;
                } else {
                    // Empty response: used for ascii multiget emulation.
                }

            } else if (type == LUA_TSTRING) {
                // response is a raw string from lua.
                const char *s = lua_tolstring(Lc, 1, &rlen);
                size_t l = rlen > WRITE_BUFFER_SIZE ? WRITE_BUFFER_SIZE : rlen;
                memcpy(resp->wbuf, s, l);
                resp_add_iov(resp, resp->wbuf, l);
                lua_pop(Lc, 1);
            } else {
                proxy_out_errstring(resp, PROXY_SERVER_ERROR, "bad response");
            }
        }

        rctx->pending_reqs--;
    } else if (cores == LUA_YIELD) {
        int yield_type = lua_tointeger(Lc, -1);
        P_DEBUG("%s: coroutine yielded. return type: %d\n", __func__, yield_type);
        assert(yield_type != 0);
        lua_pop(Lc, 1);

        int res = 0;
        mcp_request_t *rq = NULL;
        mcp_backend_t *be = NULL;
        mcp_resp_t *r = NULL;
        switch (yield_type) {
            case MCP_YIELD_AWAIT:
                // called with await context on the stack.
                rctx->first_queue = false; // HACK: ensure awaits are counted.
                mcplib_await_run_rctx(rctx);
                break;
            case MCP_YIELD_POOL:
                // TODO (v2): c only used for cache alloc?
                // pool_call checks the argument already.
                be = lua_touserdata(Lc, -1);
                rq = lua_touserdata(Lc, -2);
                // not using a pre-made res object from this yield type.
                r = mcp_prep_resobj(Lc, rq, be, c->thread);
                rctx->first_queue = false; // HACK: ensure poolreqs are counted.
                mcp_queue_rctx_io(rctx, rq, be, r);
                break;
            case MCP_YIELD_INTERNAL:
                // stack should be: rq, res
                if (rctx->parent) {
                    LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_ERROR, NULL, "cannot run mcp.internal from a sub request");
                    rctx->pending_reqs--;
                    return LUA_ERRRUN;
                } else {
                    res = mcplib_internal_run(rctx);
                    if (res == 0) {
                        // stack should still be: rq, res
                        // TODO: turn this function into a for loop that re-runs on
                        // certain status codes, to avoid recursive depth here.
                        // or maybe... a goto? :P
                        proxy_run_rcontext(rctx);
                    } else if (res > 0) {
                        // internal run queued for extstore.
                    } else {
                        assert(res < 0);
                        proxy_out_errstring(resp, PROXY_SERVER_ERROR, "bad request");
                    }
                }
                break;
            case MCP_YIELD_WAITCOND:
            case MCP_YIELD_WAITHANDLE:
                // Even if we're in WAITHANDLE, we want to dispatch any queued
                // requests, so we still need to iterate the full set of qslots.
                _proxy_run_rcontext_queues(rctx);
                break;
            case MCP_YIELD_SLEEP:
                // Pause coroutine and do nothing. Alarm will resume.
                break;
            default:
                abort();
        }

    } else {
        // Log the error where it happens, then the parent will handle a
        // result object normally.
        P_DEBUG("%s: Failed to run coroutine: %s\n", __func__, lua_tostring(Lc, -1));
        LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_ERROR, NULL, lua_tostring(Lc, -1));
        if (!rctx->parent) {
            WSTAT_DECR(c->thread, proxy_req_active, 1);
            proxy_out_errstring(resp, PROXY_SERVER_ERROR, "lua failure");
        }
        rctx->pending_reqs--;
    }

    return cores;
}

// basically any data before the first key.
// max is like 15ish plus spaces. we can be more strict about how many spaces
// to expect because any client spamming space is being deliberately stupid
// anyway.
#define MAX_CMD_PREFIX 20

static void proxy_process_command(conn *c, char *command, size_t cmdlen, bool multiget) {
    assert(c != NULL);
    LIBEVENT_THREAD *thr = c->thread;
    struct proxy_hook *hooks = thr->proxy_hooks;
    lua_State *L = thr->L;
    proxy_ctx_t *ctx = thr->proxy_ctx;
    mcp_parser_t pr = {0};

    // Avoid doing resp_start() here, instead do it a bit later or as-needed.
    // This allows us to hop over to the internal text protocol parser, which
    // also calls resp_start().
    // Tighter integration later should obviate the need for this, it is not a
    // permanent solution.
    int ret = process_request(&pr, command, cmdlen);
    if (ret != 0) {
        WSTAT_INCR(c->thread, proxy_conn_errors, 1);
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }
        proxy_out_errstring(c->resp, PROXY_CLIENT_ERROR, "parsing request");
        if (ret == -2) {
            // Kill connection on more critical parse failure.
            conn_set_state(c, conn_closing);
        }
        return;
    }

    struct proxy_hook *hook = &hooks[pr.command];
    struct proxy_hook_ref hook_ref = hook->ref;
    // if client came from a tagged listener, scan for a more specific hook.
    // TODO: (v2) avoiding a hash table lookup here, but maybe some other
    // datastructure would suffice. for 4-8 tags this is perfectly fast.
    if (c->tag && hook->tagged) {
        struct proxy_hook_tagged *pht = hook->tagged;
        while (pht->ref.lua_ref) {
            if (c->tag == pht->tag) {
                hook_ref = pht->ref;
                break;
            }
            pht++;
        }
    }

    if (!hook_ref.lua_ref) {
        // need to pass our command string into the internal handler.
        // to minimize the code change, this means allowing it to tokenize the
        // full command. The proxy's indirect parser should be built out to
        // become common code for both proxy and ascii handlers.
        // For now this means we have to null-terminate the command string,
        // then call into text protocol handler.
        // FIXME (v2): use a ptr or something; don't like this code.
        if (cmdlen > 1 && command[cmdlen-2] == '\r') {
            command[cmdlen-2] = '\0';
        } else {
            command[cmdlen-1] = '\0';
        }
        // lets nread_proxy know we're in ascii mode.
        c->proxy_rctx = NULL;
        process_command_ascii(c, command);
        return;
    }

    // If ascii multiget, we turn this into a self-calling loop :(
    // create new request with next key, call this func again, then advance
    // original string.
    // might be better to split this function; the below bits turn into a
    // function call, then we don't re-process the above bits in the same way?
    // The way this is detected/passed on is very fragile.
    if (!multiget && pr.cmd_type == CMD_TYPE_GET && pr.has_space) {
        uint32_t keyoff = pr.tokens[pr.keytoken];
        while (pr.klen != 0) {
            char temp[KEY_MAX_LENGTH + MAX_CMD_PREFIX + 30];
            char *cur = temp;
            // Core daemon can abort the entire command if one key is bad, but
            // we cannot from the proxy. Instead we have to inject errors into
            // the stream. This should, thankfully, be rare at least.
            if (pr.tokens[pr.keytoken] > MAX_CMD_PREFIX) {
                if (!resp_start(c)) {
                    conn_set_state(c, conn_closing);
                    return;
                }
                proxy_out_errstring(c->resp, PROXY_CLIENT_ERROR, "malformed request");
            } else if (pr.klen > KEY_MAX_LENGTH) {
                if (!resp_start(c)) {
                    conn_set_state(c, conn_closing);
                    return;
                }
                proxy_out_errstring(c->resp, PROXY_CLIENT_ERROR, "key too long");
            } else {
                // copy original request up until the original key token.
                memcpy(cur, pr.request, pr.tokens[pr.keytoken]);
                cur += pr.tokens[pr.keytoken];

                // now copy in our "current" key.
                memcpy(cur, &pr.request[keyoff], pr.klen);
                cur += pr.klen;

                memcpy(cur, "\r\n", 2);
                cur += 2;

                *cur = '\0';
                P_DEBUG("%s: new multiget sub request: %s [%u/%u]\n", __func__, temp, keyoff, pr.klen);
                proxy_process_command(c, temp, cur - temp, PROCESS_MULTIGET);
            }

            // now advance to the next key.
            keyoff = _process_request_next_key(&pr);
        }

        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }

        // The above recursions should have created c->resp's in dispatch
        // order.
        // So now we add another one at the end to create the capping END
        // string.
        memcpy(c->resp->wbuf, ENDSTR, ENDLEN);
        resp_add_iov(c->resp, c->resp->wbuf, ENDLEN);

        return;
    }

    // We test the command length all the way down here because multigets can
    // be very long, and they're chopped up by now.
    if (cmdlen >= MCP_REQUEST_MAXLEN) {
        WSTAT_INCR(c->thread, proxy_conn_errors, 1);
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }
        proxy_out_errstring(c->resp, PROXY_CLIENT_ERROR, "request too long");
        conn_set_state(c, conn_closing);
        return;
    }

    if (!resp_start(c)) {
        conn_set_state(c, conn_closing);
        return;
    }

    // Count requests handled by proxy vs local.
    // Also batch the counts down this far so we can lock once for the active
    // counter instead of twice.
    struct proxy_int_stats *istats = c->thread->proxy_int_stats;
    uint64_t active_reqs = 0;
    WSTAT_L(c->thread);
    istats->counters[pr.command]++;
    c->thread->stats.proxy_conn_requests++;
    c->thread->stats.proxy_req_active++;
    active_reqs = c->thread->stats.proxy_req_active;
    WSTAT_UL(c->thread);

    if (active_reqs > ctx->active_req_limit) {
        proxy_out_errstring(c->resp, PROXY_SERVER_ERROR, "active request limit reached");
        WSTAT_DECR(c->thread, proxy_req_active, 1);
        if (pr.vlen != 0) {
            c->sbytes = pr.vlen;
            conn_set_state(c, conn_swallow);
        }
        return;
    }

    // hook is owned by a function generator.
    mcp_rcontext_t *rctx = mcp_funcgen_start(L, hook_ref.ctx, &pr);
    if (rctx == NULL) {
        proxy_out_errstring(c->resp, PROXY_SERVER_ERROR, "lua start failure");
        WSTAT_DECR(c->thread, proxy_req_active, 1);
        if (pr.vlen != 0) {
            c->sbytes = pr.vlen;
            conn_set_state(c, conn_swallow);
        }
        return;
    }

    mcp_set_request(&pr, rctx->request, command, cmdlen);
    rctx->request->ascii_multiget = multiget;
    rctx->c = c;
    rctx->conn_fd = c->sfd;
    rctx->pending_reqs++; // seed counter with the "main" request
    // remember the top level mc_resp, because further requests on the
    // same connection will replace c->resp.
    rctx->resp = c->resp;

    // for the very first call we need to place:
    // - rctx->function_ref + rctx->request_ref
    // I _think_ here is the right place to do that?
    lua_rawgeti(rctx->Lc, LUA_REGISTRYINDEX, rctx->function_ref);
    lua_rawgeti(rctx->Lc, LUA_REGISTRYINDEX, rctx->request_ref);

    if (pr.vlen != 0) {
        c->item = NULL;
        // Need to add the used memory later due to needing an extra callback
        // handler on error during nread.
        bool oom = proxy_bufmem_checkadd(c->thread, 0);

        // relying on temporary malloc's not having fragmentation
        if (!oom) {
            c->item = malloc(pr.vlen);
        }
        if (c->item == NULL) {
            // return the RCTX
            rctx->pending_reqs--;
            mcp_funcgen_return_rctx(rctx);
            // normal cleanup
            lua_settop(L, 0);
            proxy_out_errstring(c->resp, PROXY_SERVER_ERROR, "out of memory");
            WSTAT_DECR(c->thread, proxy_req_active, 1);
            c->sbytes = pr.vlen;
            conn_set_state(c, conn_swallow);
            return;
        }
        c->item_malloced = true;
        c->ritem = c->item;
        c->rlbytes = pr.vlen;

        // remember the request context for later.
        c->proxy_rctx = rctx;

        conn_set_state(c, conn_nread);
        return;
    }

    proxy_run_rcontext(rctx);
    mcp_funcgen_return_rctx(rctx);

    lua_settop(L, 0); // clear any junk from the main thread.
}

mcp_resp_t *mcp_prep_bare_resobj(lua_State *L, LIBEVENT_THREAD *t) {
    mcp_resp_t *r = lua_newuserdatauv(L, sizeof(mcp_resp_t), 0);
    // FIXME (v2): is this memset still necessary? I was using it for
    // debugging.
    memset(r, 0, sizeof(mcp_resp_t));
    r->thread = t;
    assert(r->thread != NULL);
    gettimeofday(&r->start, NULL);

    luaL_getmetatable(L, "mcp.response");
    lua_setmetatable(L, -2);

    return r;
}

void mcp_set_resobj(mcp_resp_t *r, mcp_request_t *rq, mcp_backend_t *be, LIBEVENT_THREAD *t) {
    memset(r, 0, sizeof(mcp_resp_t));
    r->buf = NULL;
    r->blen = 0;
    r->thread = t;
    assert(r->thread != NULL);
    gettimeofday(&r->start, NULL);
    // Set noreply mode.
    // TODO (v2): the response "inherits" the request's noreply mode, which isn't
    // strictly correct; we should inherit based on the request that spawned
    // the coroutine but the structure doesn't allow that yet.
    // Should also be able to settle this exact mode from the parser so we
    // don't have to re-branch here.
    if (rq->pr.noreply) {
        if (rq->pr.cmd_type == CMD_TYPE_META) {
            r->mode = RESP_MODE_METAQUIET;
            for (int x = 2; x < rq->pr.ntokens; x++) {
                if (rq->request[rq->pr.tokens[x]] == 'q') {
                    rq->request[rq->pr.tokens[x]] = ' ';
                }
            }
        } else {
            r->mode = RESP_MODE_NOREPLY;
            rq->request[rq->pr.reqlen - 3] = 'Y';
        }
    } else {
        r->mode = RESP_MODE_NORMAL;
    }

    r->cmd = rq->pr.command;

    strncpy(r->be_name, be->name, MAX_NAMELEN+1);
    strncpy(r->be_port, be->port, MAX_PORTLEN+1);

}

mcp_resp_t *mcp_prep_resobj(lua_State *L, mcp_request_t *rq, mcp_backend_t *be, LIBEVENT_THREAD *t) {
    mcp_resp_t *r = lua_newuserdatauv(L, sizeof(mcp_resp_t), 0);
    mcp_set_resobj(r, rq, be, t);

    luaL_getmetatable(L, "mcp.response");
    lua_setmetatable(L, -2);

    return r;
}

void mcp_resp_set_elapsed(mcp_resp_t *r) {
    struct timeval end;
    // stamp the elapsed time into the response object.
    gettimeofday(&end, NULL);
    r->elapsed = (end.tv_sec - r->start.tv_sec) * 1000000 +
        (end.tv_usec - r->start.tv_usec);
}

// Used for any cases where we're queueing requests to the IO subsystem.
// NOTE: it's not currently possible to limit the memory used by the IO
// object cache. So this check is redundant, and any callers may proceed
// as though it is successful.
io_pending_proxy_t *mcp_queue_rctx_io(mcp_rcontext_t *rctx, mcp_request_t *rq, mcp_backend_t *be, mcp_resp_t *r) {
    conn *c = rctx->c;
    io_queue_t *q = conn_io_queue_get(c, IO_QUEUE_PROXY);
    io_pending_proxy_t *p = do_cache_alloc(c->thread->io_cache);
    if (p == NULL) {
        WSTAT_INCR(c->thread, proxy_conn_oom, 1);
        proxy_lua_error(rctx->Lc, "out of memory allocating from IO cache");
        // NOTE: the error call above jumps to an error handler, so this does
        // not actually return.
        return NULL;
    }

    // this is a re-cast structure, so assert that we never outsize it.
    assert(sizeof(io_pending_t) >= sizeof(io_pending_proxy_t));
    memset(p, 0, sizeof(io_pending_proxy_t));
    // set up back references.
    p->io_queue_type = IO_QUEUE_PROXY;
    p->thread = c->thread;
    p->c = c;
    p->client_resp = r;
    p->flushed = false;
    p->return_cb = proxy_return_rctx_cb;
    p->finalize_cb = proxy_finalize_rctx_cb;

    // pass along the request context for resumption.
    p->rctx = rctx;

    if (rq) {
        p->ascii_multiget = rq->ascii_multiget;
        // The direct backend object. Lc is holding the reference in the stack
        p->backend = be;

        mcp_request_attach(rq, p);
    }

    // HACK
    // find the parent rctx
    while (rctx->parent) {
        rctx = rctx->parent;
    }
    // Hack to enforce the first iop increments client IO queue counter.
    if (!rctx->first_queue) {
        rctx->first_queue = true;
        p->qcount_incr = true;
    }
    // END HACK

    // link into the batch chain.
    p->next = q->stack_ctx;
    q->stack_ctx = p;
    P_DEBUG("%s: queued\n", __func__);

    return p;
}

// DO NOT call this method frequently! globally locked!
void mcp_sharedvm_delta(proxy_ctx_t *ctx, int tidx, const char *name, int delta) {
    lua_State *L = ctx->proxy_sharedvm;
    pthread_mutex_lock(&ctx->sharedvm_lock);

    if (lua_getfield(L, tidx, name) == LUA_TNIL) {
        lua_pop(L, 1);
        lua_pushinteger(L, delta);
        lua_setfield(L, tidx, name);
    } else {
        lua_pushinteger(L, delta);
        lua_arith(L, LUA_OPADD);
        lua_setfield(L, tidx, name);
    }

    pthread_mutex_unlock(&ctx->sharedvm_lock);
}

void mcp_sharedvm_remove(proxy_ctx_t *ctx, int tidx, const char *name) {
    lua_State *L = ctx->proxy_sharedvm;
    pthread_mutex_lock(&ctx->sharedvm_lock);

    lua_pushnil(L);
    lua_setfield(L, tidx, name);

    pthread_mutex_unlock(&ctx->sharedvm_lock);
}

// Global object support code.
// Global objects are created in the configuration VM, and referenced in
// worker VMs via proxy objects that refer back to memory in the
// configuration VM.
// We manage reference counts: once all remote proxy objects are collected, we
// signal the config thread to remove a final reference and collect garbage to
// remove the global object.

static void mcp_gobj_enqueue(proxy_ctx_t *ctx, struct mcp_globalobj_s *g) {
    pthread_mutex_lock(&ctx->manager_lock);
    STAILQ_INSERT_TAIL(&ctx->manager_head, g, next);
    pthread_cond_signal(&ctx->manager_cond);
    pthread_mutex_unlock(&ctx->manager_lock);
}

// References the object, initializing the self-reference if necessary.
// Call from config thread, with global object on top of stack.
void mcp_gobj_ref(lua_State *L, struct mcp_globalobj_s *g) {
    pthread_mutex_lock(&g->lock);
    if (g->self_ref == 0) {
        // Initialization requires a small dance:
        // - store a negative of our ref, increase refcount an extra time
        // - then link and signal the manager thread as though we were GC'ing
        // the object.
        // - the manager thread will later acknowledge the initialization of
        // this global object and negate the self_ref again
        // - this prevents an unused proxy object from causing the global
        // object to be reaped early while we are still copying it to worker
        // threads, as the manager thread will block waiting for the config
        // thread to finish its reload work.
        g->self_ref = -luaL_ref(L, LUA_REGISTRYINDEX);
        g->refcount++;
        proxy_ctx_t *ctx = PROXY_GET_CTX(L);
        mcp_gobj_enqueue(ctx, g);
    } else {
        lua_pop(L, 1); // drop the reference we didn't end up using.
    }
    g->refcount++;
    pthread_mutex_unlock(&g->lock);
}

void mcp_gobj_unref(proxy_ctx_t *ctx, struct mcp_globalobj_s *g) {
    pthread_mutex_lock(&g->lock);
    g->refcount--;
    if (g->refcount == 0) {
        mcp_gobj_enqueue(ctx, g);
    }
    pthread_mutex_unlock(&g->lock);
}

void mcp_gobj_finalize(struct mcp_globalobj_s *g) {
    pthread_mutex_destroy(&g->lock);
}

static void *mcp_profile_alloc(void *ud, void *ptr, size_t osize,
                                            size_t nsize) {
    struct mcp_memprofile *prof = ud;
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    enum mcp_memprofile_types t = mcp_memp_free;
    if (ptr == NULL) {
        switch (osize) {
            case LUA_TSTRING:
                t = mcp_memp_string;
                //fprintf(stderr, "alloc string: %ld\n", nsize);
                break;
            case LUA_TTABLE:
                t = mcp_memp_table;
                //fprintf(stderr, "alloc table: %ld\n", nsize);
                break;
            case LUA_TFUNCTION:
                t = mcp_memp_func;
                //fprintf(stderr, "alloc func: %ld\n", nsize);
                break;
            case LUA_TUSERDATA:
                t = mcp_memp_userdata;
                //fprintf(stderr, "alloc userdata: %ld\n", nsize);
                break;
            case LUA_TTHREAD:
                t = mcp_memp_thread;
                //fprintf(stderr, "alloc thread: %ld\n", nsize);
                break;
            default:
                t = mcp_memp_default;
                //fprintf(stderr, "alloc osize: %ld nsize: %ld\n", osize, nsize);
        }
        prof->allocs[t]++;
        prof->alloc_bytes[t] += nsize;
    } else {
        if (nsize != 0) {
            prof->allocs[mcp_memp_realloc]++;
            prof->alloc_bytes[mcp_memp_realloc] += nsize;
        } else {
            prof->allocs[mcp_memp_free]++;
            prof->alloc_bytes[mcp_memp_free] += osize;
        }
        //fprintf(stderr, "realloc: osize: %ld nsize: %ld\n", osize, nsize);
    }

    if (now.tv_sec != prof->last_status.tv_sec) {
        prof->last_status.tv_sec = now.tv_sec;
        fprintf(stderr, "MEMPROF[%d]:\tstring[%llu][%llu] table[%llu][%llu] func[%llu][%llu] udata[%llu][%llu] thr[%llu][%llu] def[%llu][%llu] realloc[%llu][%llu] free[%llu][%llu]\n",
                prof->id,
                (unsigned long long)prof->allocs[1],
                (unsigned long long)prof->alloc_bytes[1],
                (unsigned long long)prof->allocs[2],
                (unsigned long long)prof->alloc_bytes[2],
                (unsigned long long)prof->allocs[3],
                (unsigned long long)prof->alloc_bytes[3],
                (unsigned long long)prof->allocs[4],
                (unsigned long long)prof->alloc_bytes[4],
                (unsigned long long)prof->allocs[5],
                (unsigned long long)prof->alloc_bytes[5],
                (unsigned long long)prof->allocs[6],
                (unsigned long long)prof->alloc_bytes[6],
                (unsigned long long)prof->allocs[7],
                (unsigned long long)prof->alloc_bytes[7],
                (unsigned long long)prof->allocs[0],
                (unsigned long long)prof->alloc_bytes[0]);
        for (int x = 0; x < 8; x++) {
            prof->allocs[x] = 0;
            prof->alloc_bytes[x] = 0;
        }
    }

    if (nsize == 0) {
        free(ptr);
        return NULL;
    } else {
        return realloc(ptr, nsize);
    }
}

// Common lua debug command.
__attribute__((unused)) void dump_stack(lua_State *L, const char *msg) {
    int top = lua_gettop(L);
    int i = 1;
    fprintf(stderr, "--TOP OF STACK [%d] | %s\n", top, msg);
    for (; i < top + 1; i++) {
        int type = lua_type(L, i);
        // lets find the metatable of this userdata to identify it.
        if (lua_getmetatable(L, i) != 0) {
            lua_pushstring(L, "__name");
            if (lua_rawget(L, -2) != LUA_TNIL) {
                fprintf(stderr, "--|%d| [%s] (%s)\n", i, lua_typename(L, type), lua_tostring(L, -1));
                lua_pop(L, 2);
                continue;
            }
            lua_pop(L, 2);
        }
        if (type == LUA_TSTRING) {
            fprintf(stderr, "--|%d| [%s] | %s\n", i, lua_typename(L, type), lua_tostring(L, i));
        } else {
            fprintf(stderr, "--|%d| [%s]\n", i, lua_typename(L, type));
        }
    }
    fprintf(stderr, "-----------------\n");
}

// Not very pretty, but helped.
// Nice to haves:
// - summarize counts for each metatable (easy enough to do from logging)
// - use a less noisy stack dump instead of calling dump_stack()
__attribute__((unused)) void dump_registry(lua_State *L, const char *msg) {
    int ref_size = lua_rawlen(L, LUA_REGISTRYINDEX);
    fprintf(stderr, "--LUA REGISTRY TABLE [%d] | %s\n", ref_size, msg);
    // walk registry
    int ridx = lua_absindex(L, LUA_REGISTRYINDEX);
    int udata = 0;
    int number = 0;
    int string = 0;
    int function = 0;
    int table = 0;
    lua_pushnil(L);
    while (lua_next(L, ridx) != 0) {
        dump_stack(L, "===registry entry===");
        int type = lua_type(L, -1);
        if (type == LUA_TUSERDATA) {
            udata++;
        } else if (type == LUA_TNUMBER) {
            number++;
        } else if (type == LUA_TSTRING) {
            string++;
        } else if (type == LUA_TFUNCTION) {
            function++;
        } else if (type == LUA_TTABLE) {
            table++;
        }
        lua_pop(L, 1); // drop value
    }
    fprintf(stderr, "SUMMARY:\n\n");
    fprintf(stderr, "### UDATA\t[%d]\n", udata);
    fprintf(stderr, "### NUMBER\t[%d]\n", number);
    fprintf(stderr, "### STRING\t[%d]\n", string);
    fprintf(stderr, "### FUNCTION\t[%d]\n", function );
    fprintf(stderr, "### TABLE\t[%d]\n", table);
    fprintf(stderr, "-----------------\n");
}

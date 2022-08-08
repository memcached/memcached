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
static void proxy_process_command(conn *c, char *command, size_t cmdlen, bool multiget);
static void mcp_queue_io(conn *c, mc_resp *resp, int coro_ref, lua_State *Lc);
static void proxy_out_errstring(mc_resp *resp, const char *str);

/******** EXTERNAL FUNCTIONS ******/
// functions starting with _ are breakouts for the public functions.

// see also: process_extstore_stats()
// FIXME (v2): get context off of conn? global variables
void proxy_stats(ADD_STAT add_stats, conn *c) {
    if (!settings.proxy_enabled) {
       return;
    }
    proxy_ctx_t *ctx = settings.proxy_ctx;
    STAT_L(ctx);

    APPEND_STAT("proxy_config_reloads", "%llu", (unsigned long long)ctx->global_stats.config_reloads);
    APPEND_STAT("proxy_config_reload_fails", "%llu", (unsigned long long)ctx->global_stats.config_reload_fails);
    APPEND_STAT("proxy_backend_total", "%llu", (unsigned long long)ctx->global_stats.backend_total);
    APPEND_STAT("proxy_backend_marked_bad", "%llu", (unsigned long long)ctx->global_stats.backend_marked_bad);
    APPEND_STAT("proxy_backend_failed", "%llu", (unsigned long long)ctx->global_stats.backend_failed);
    STAT_UL(ctx);
}

void process_proxy_stats(ADD_STAT add_stats, conn *c) {
    char key_str[STAT_KEY_LEN];
    struct proxy_int_stats istats = {0};

    if (!settings.proxy_enabled) {
        return;
    }
    proxy_ctx_t *ctx = settings.proxy_ctx;
    STAT_L(ctx);

    // prepare aggregated counters.
    struct proxy_user_stats *us = &ctx->user_stats;
    uint64_t counters[us->num_stats];
    memset(counters, 0, sizeof(counters));

    // aggregate worker thread counters.
    for (int x = 0; x < settings.num_threads; x++) {
        LIBEVENT_THREAD *t = get_worker_thread(x);
        struct proxy_user_stats *tus = t->proxy_user_stats;
        struct proxy_int_stats *is = t->proxy_int_stats;
        WSTAT_L(t);
        for (int i = 0; i < CMD_FINAL; i++) {
            istats.counters[i] += is->counters[i];
        }
        if (tus && tus->num_stats >= us->num_stats) {
            for (int i = 0; i < us->num_stats; i++) {
                counters[i] += tus->counters[i];
            }
        }
        WSTAT_UL(t);
    }

    // return all of the user generated stats
    for (int x = 0; x < us->num_stats; x++) {
        snprintf(key_str, STAT_KEY_LEN-1, "user_%s", us->names[x]);
        APPEND_STAT(key_str, "%llu", (unsigned long long)counters[x]);
    }
    STAT_UL(ctx);

    // return proxy counters
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

// start the centralized lua state and config thread.
// TODO (v2): return ctx ptr. avoid global vars.
void proxy_init(bool use_uring) {
    proxy_ctx_t *ctx = calloc(1, sizeof(proxy_ctx_t));
    settings.proxy_ctx = ctx;
    ctx->use_uring = use_uring;

    pthread_mutex_init(&ctx->config_lock, NULL);
    pthread_cond_init(&ctx->config_cond, NULL);
    pthread_mutex_init(&ctx->worker_lock, NULL);
    pthread_cond_init(&ctx->worker_cond, NULL);
    pthread_mutex_init(&ctx->manager_lock, NULL);
    pthread_cond_init(&ctx->manager_cond, NULL);
    pthread_mutex_init(&ctx->stats_lock, NULL);

    // FIXME (v2): default defines.
    ctx->tunables.tcp_keepalive = false;
    ctx->tunables.backend_failure_limit = 3;
    ctx->tunables.connect.tv_sec = 5;
    ctx->tunables.retry.tv_sec = 3;
    ctx->tunables.read.tv_sec = 3;
#ifdef HAVE_LIBURING
    ctx->tunables.connect_ur.tv_sec = 5;
    ctx->tunables.retry_ur.tv_sec = 3;
    ctx->tunables.read_ur.tv_sec = 3;
#endif // HAVE_LIBURING

    STAILQ_INIT(&ctx->manager_head);
    lua_State *L = luaL_newstate();
    ctx->proxy_state = L;
    luaL_openlibs(L);
    // NOTE: might need to differentiate the libs yes?
    proxy_register_libs(NULL, L);

    // Create/start the backend threads, which we need before servers
    // start getting created.
    // Supporting N event threads should be possible, but it will be a
    // low number of N to avoid too many wakeup syscalls.
    // For now we hardcode to 1.
    proxy_event_thread_t *threads = calloc(1, sizeof(proxy_event_thread_t));
    ctx->proxy_threads = threads;
    for (int i = 0; i < 1; i++) {
        proxy_event_thread_t *t = &threads[i];
        t->ctx = ctx;
#ifdef USE_EVENTFD
        t->event_fd = eventfd(0, EFD_NONBLOCK);
        if (t->event_fd == -1) {
            perror("failed to create backend notify eventfd");
            exit(1);
        }
#else
        int fds[2];
        if (pipe(fds)) {
            perror("can't create proxy backend notify pipe");
            exit(1);
        }

        t->notify_receive_fd = fds[0];
        t->notify_send_fd = fds[1];
#endif
        proxy_init_evthread_events(t);

        // incoming request queue.
        STAILQ_INIT(&t->io_head_in);
        pthread_mutex_init(&t->mutex, NULL);
        pthread_cond_init(&t->cond, NULL);

        memcpy(&t->tunables, &ctx->tunables, sizeof(t->tunables));

#ifdef HAVE_LIBURING
        if (t->use_uring) {
            pthread_create(&t->thread_id, NULL, proxy_event_thread_ur, t);
        } else {
            pthread_create(&t->thread_id, NULL, proxy_event_thread, t);
        }
#else
        pthread_create(&t->thread_id, NULL, proxy_event_thread, t);
#endif // HAVE_LIBURING
    }

    _start_proxy_config_threads(ctx);
}

// Initialize the VM for an individual worker thread.
void proxy_thread_init(LIBEVENT_THREAD *thr) {
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

    // Initialize the lua state.
    lua_State *L = luaL_newstate();
    thr->L = L;
    luaL_openlibs(L);
    proxy_register_libs(thr, L);
    // TODO: srand on time? do we need to bother?
    for (int x = 0; x < 3; x++) {
        thr->proxy_rng[x] = rand();
    }

    // kick off the configuration.
    if (proxy_thread_loadconf(thr) != 0) {
        exit(EXIT_FAILURE);
    }
}

// ctx_stack is a stack of io_pending_proxy_t's.
void proxy_submit_cb(io_queue_t *q) {
    proxy_event_thread_t *e = ((proxy_ctx_t *)q->ctx)->proxy_threads;
    io_pending_proxy_t *p = q->stack_ctx;
    io_head_t head;
    STAILQ_INIT(&head);

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
        // insert into tail so head is oldest request.
        STAILQ_INSERT_TAIL(&head, p, io_next);
        if (p->is_await) {
            // need to not count await objects multiple times.
            if (p->await_first) {
                q->count++;
            }
            // funny workaround: awaiting IOP's don't count toward
            // resuming a connection, only the completion of the await
            // condition.
        } else {
            q->count++;
        }

        p = p->next;
    }

    // clear out the submit queue so we can re-queue new IO's inline.
    q->stack_ctx = NULL;

    // Transfer request stack to event thread.
    pthread_mutex_lock(&e->mutex);
    STAILQ_CONCAT(&e->io_head_in, &head);
    // No point in holding the lock since we're not doing a cond signal.
    pthread_mutex_unlock(&e->mutex);

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

    return;
}

void proxy_complete_cb(io_queue_t *q) {
    // empty/unused.
}

// called from worker thread after an individual IO has been returned back to
// the worker thread. Do post-IO run and cleanup work.
void proxy_return_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;
    if (p->is_await) {
        mcplib_await_return(p);
    } else {
        lua_State *Lc = p->coro;

        // in order to resume we need to remove the objects that were
        // originally returned
        // what's currently on the top of the stack is what we want to keep.
        lua_rotate(Lc, 1, 1);
        // We kept the original results from the yield so lua would not
        // collect them in the meantime. We can drop those now.
        lua_settop(Lc, 1);

        // p can be freed/changed from the call below, so fetch the queue now.
        io_queue_t *q = conn_io_queue_get(p->c, p->io_queue_type);
        conn *c = p->c;
        proxy_run_coroutine(Lc, p->resp, p, c);

        q->count--;
        if (q->count == 0) {
            // call re-add directly since we're already in the worker thread.
            conn_worker_readd(c);
        }
    }
}

// called from the worker thread as an mc_resp is being freed.
// must let go of the coroutine reference if there is one.
// caller frees the pending IO.
void proxy_finalize_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;

    // release our coroutine reference.
    // TODO (v2): coroutines are reusable in lua 5.4. we can stack this onto a freelist
    // after a lua_resetthread(Lc) call.
    if (p->coro_ref) {
        // Note: lua registry is the same for main thread or a coroutine.
        luaL_unref(p->coro, LUA_REGISTRYINDEX, p->coro_ref);
    }
    return;
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
    assert(c->proxy_coro_ref != 0);
    LIBEVENT_THREAD *thr = c->thread;
    lua_State *L = thr->L;
    luaL_unref(L, LUA_REGISTRYINDEX, c->proxy_coro_ref);
    c->proxy_coro_ref = 0;
    WSTAT_DECR(c, proxy_req_active, 1);
}

// we buffered a SET of some kind.
void complete_nread_proxy(conn *c) {
    assert(c != NULL);

    LIBEVENT_THREAD *thr = c->thread;
    lua_State *L = thr->L;

    if (c->proxy_coro_ref == 0) {
        complete_nread_ascii(c);
        return;
    }

    conn_set_state(c, conn_new_cmd);

    // Grab our coroutine.
    lua_rawgeti(L, LUA_REGISTRYINDEX, c->proxy_coro_ref);
    luaL_unref(L, LUA_REGISTRYINDEX, c->proxy_coro_ref);
    lua_State *Lc = lua_tothread(L, -1);
    mcp_request_t *rq = luaL_checkudata(Lc, -1, "mcp.request");

    // validate the data chunk.
    if (strncmp((char *)c->item + rq->pr.vlen - 2, "\r\n", 2) != 0) {
        lua_settop(L, 0); // clear anything remaining on the main thread.
        // FIXME (v2): need to set noreply false if mset_res, but that's kind
        // of a weird hack to begin with. Evaluate how to best do that here.
        out_string(c, "CLIENT_ERROR bad data chunk");
        return;
    }

    // We move ownership of the c->item buffer from the connection to the
    // request object here. Else we can double free if the conn closes while
    // inside nread.
    rq->pr.vbuf = c->item;
    c->item = NULL;
    c->item_malloced = false;
    c->proxy_coro_ref = 0;

    proxy_run_coroutine(Lc, c->resp, NULL, c);

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

void proxy_lua_ferror(lua_State *L, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    lua_pushfstring(L, fmt, ap);
    va_end(ap);
    lua_error(L);
}

// Need a custom function so we can prefix lua strings easily.
static void proxy_out_errstring(mc_resp *resp, const char *str) {
    size_t len;
    const static char error_prefix[] = "SERVER_ERROR ";
    const static int error_prefix_len = sizeof(error_prefix) - 1;

    assert(resp != NULL);

    resp_reset(resp);
    // avoid noreply since we're throwing important errors.

    // Fill response object with static string.
    len = strlen(str);
    if ((len + error_prefix_len + 2) > WRITE_BUFFER_SIZE) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    char *w = resp->wbuf;
    memcpy(w, error_prefix, error_prefix_len);
    w += error_prefix_len;

    memcpy(w, str, len);
    w += len;

    memcpy(w, "\r\n", 2);
    resp_add_iov(resp, resp->wbuf, len + error_prefix_len + 2);
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
            if (r->resp.code == MCMC_CODE_MISS) {
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

// this resumes every yielded coroutine (and re-resumes if necessary).
// called from the worker thread after responses have been pulled from the
// network.
// Flow:
// - the response object should already be on the coroutine stack.
// - fix up the stack.
// - run coroutine.
// - if LUA_YIELD, we need to swap out the pending IO from its mc_resp then call for a queue
// again.
// - if LUA_OK finalize the response and return
// - else set error into mc_resp.
int proxy_run_coroutine(lua_State *Lc, mc_resp *resp, io_pending_proxy_t *p, conn *c) {
    int nresults = 0;
    int cores = lua_resume(Lc, NULL, 1, &nresults);
    size_t rlen = 0;

    if (cores == LUA_OK) {
        WSTAT_DECR(c, proxy_req_active, 1);
        int type = lua_type(Lc, 1);
        if (type == LUA_TUSERDATA) {
            mcp_resp_t *r = luaL_checkudata(Lc, 1, "mcp.response");
            _set_noreply_mode(resp, r);
            if (r->buf) {
                // response set from C.
                // FIXME (v2): write_and_free() ? it's a bit wrong for here.
                resp->write_and_free = r->buf;
                resp_add_iov(resp, r->buf, r->blen);
                r->buf = NULL;
            } else if (lua_getiuservalue(Lc, 1, 1) != LUA_TNIL) {
                // uservalue slot 1 is pre-created, so we get TNIL instead of
                // TNONE when nothing was set into it.
                const char *s = lua_tolstring(Lc, -1, &rlen);
                size_t l = rlen > WRITE_BUFFER_SIZE ? WRITE_BUFFER_SIZE : rlen;
                memcpy(resp->wbuf, s, l);
                resp_add_iov(resp, resp->wbuf, l);
                lua_pop(Lc, 1);
            } else if (r->status != MCMC_OK) {
                proxy_out_errstring(resp, "backend failure");
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
            proxy_out_errstring(resp, "bad response");
        }
    } else if (cores == LUA_YIELD) {
        if (nresults == 1) {
            // TODO (v2): try harder to validate; but we have so few yield cases
            // that I'm going to shortcut this here. A single yielded result
            // means it's probably an await(), so attempt to process this.
            if (p != NULL) {
                int coro_ref = p->coro_ref;
                mc_resp *resp = p->resp;
                assert((void *)p == (void *)resp->io_pending);
                resp->io_pending = NULL;
                c = p->c;
                do_cache_free(c->thread->io_cache, p);
                mcplib_await_run(c, resp, Lc, coro_ref);
            } else {
                // coroutine object sitting on the _main_ VM right now, so we grab
                // the reference from there, which also pops it.
                int coro_ref = luaL_ref(c->thread->L, LUA_REGISTRYINDEX);
                mcplib_await_run(c, c->resp, Lc, coro_ref);
            }
        } else {
            // need to remove and free the io_pending, since c->resp owns it.
            // so we call mcp_queue_io() again and let it override the
            // mc_resp's io_pending object.

            int coro_ref = 0;
            mc_resp *resp;
            if (p != NULL) {
                coro_ref = p->coro_ref;
                resp = p->resp;
                c = p->c;
                do_cache_free(p->c->thread->io_cache, p);
                // *p is now dead.
            } else {
                // yielding from a top level call to the coroutine,
                // so we need to grab a reference to the coroutine thread.
                // TODO (v2): make this more explicit?
                // we only need to get the reference here, and error conditions
                // should instead drop it, but now it's not obvious to users that
                // we're reaching back into the main thread's stack.
                assert(c != NULL);
                coro_ref = luaL_ref(c->thread->L, LUA_REGISTRYINDEX);
                resp = c->resp;
            }
            // TODO (v2): c only used for cache alloc? push the above into the func?
            mcp_queue_io(c, resp, coro_ref, Lc);
        }
    } else {
        WSTAT_DECR(c, proxy_req_active, 1);
        P_DEBUG("%s: Failed to run coroutine: %s\n", __func__, lua_tostring(Lc, -1));
        LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_ERROR, NULL, lua_tostring(Lc, -1));
        proxy_out_errstring(resp, "lua failure");
    }

    return 0;
}

static void proxy_process_command(conn *c, char *command, size_t cmdlen, bool multiget) {
    assert(c != NULL);
    LIBEVENT_THREAD *thr = c->thread;
    struct proxy_hook *hooks = thr->proxy_hooks;
    lua_State *L = thr->L;
    mcp_parser_t pr = {0};

    // Avoid doing resp_start() here, instead do it a bit later or as-needed.
    // This allows us to hop over to the internal text protocol parser, which
    // also calls resp_start().
    // Tighter integration later should obviate the need for this, it is not a
    // permanent solution.
    int ret = process_request(&pr, command, cmdlen);
    if (ret != 0) {
        WSTAT_INCR(c, proxy_conn_errors, 1);
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }
        proxy_out_errstring(c->resp, "parsing request");
        if (ret == -2) {
            // Kill connection on more critical parse failure.
            conn_set_state(c, conn_closing);
        }
        return;
    }

    struct proxy_hook *hook = &hooks[pr.command];
    int hook_ref = hook->lua_ref;
    // if client came from a tagged listener, scan for a more specific hook.
    // TODO: (v2) avoiding a hash table lookup here, but maybe some other
    // datastructure would suffice. for 4-8 tags this is perfectly fast.
    if (c->tag && hook->tagged) {
        struct proxy_hook_tagged *pht = hook->tagged;
        while (pht->lua_ref) {
            if (c->tag == pht->tag) {
                hook_ref = pht->lua_ref;
                break;
            }
            pht++;
        }
    }

    if (!hook_ref) {
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
        c->proxy_coro_ref = 0;
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
            char temp[KEY_MAX_LENGTH + 30];
            char *cur = temp;
            // Core daemon can abort the entire command if one key is bad, but
            // we cannot from the proxy. Instead we have to inject errors into
            // the stream. This should, thankfully, be rare at least.
            if (pr.klen > KEY_MAX_LENGTH) {
                if (!resp_start(c)) {
                    conn_set_state(c, conn_closing);
                    return;
                }
                proxy_out_errstring(c->resp, "key too long");
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
        WSTAT_INCR(c, proxy_conn_errors, 1);
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }
        proxy_out_errstring(c->resp, "request too long");
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
    WSTAT_L(c->thread);
    istats->counters[pr.command]++;
    c->thread->stats.proxy_conn_requests++;
    c->thread->stats.proxy_req_active++;
    WSTAT_UL(c->thread);

    // start a coroutine.
    // TODO (v2): This can pull a thread from a cache.
    lua_newthread(L);
    lua_State *Lc = lua_tothread(L, -1);
    // leave the thread first on the stack, so we can reference it if needed.
    // pull the lua hook function onto the stack.
    lua_rawgeti(Lc, LUA_REGISTRYINDEX, hook_ref);

    mcp_request_t *rq = mcp_new_request(Lc, &pr, command, cmdlen);
    if (multiget) {
        rq->ascii_multiget = true;
    }
    // NOTE: option 1) copy c->tag into rq->tag here.
    // add req:listen_tag() to retrieve in top level route.

    // TODO (v2): lift this to a post-processor?
    if (rq->pr.vlen != 0) {
        // relying on temporary malloc's not succumbing as poorly to
        // fragmentation.
        c->item = malloc(rq->pr.vlen);
        if (c->item == NULL) {
            lua_settop(L, 0);
            proxy_out_errstring(c->resp, "out of memory");
            WSTAT_DECR(c, proxy_req_active, 1);
            return;
        }
        c->item_malloced = true;
        c->ritem = c->item;
        c->rlbytes = rq->pr.vlen;
        c->proxy_coro_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops coroutine.

        conn_set_state(c, conn_nread);
        return;
    }

    proxy_run_coroutine(Lc, c->resp, NULL, c);

    lua_settop(L, 0); // clear anything remaining on the main thread.
}

// analogue for storage_get_item(); add a deferred IO object to the current
// connection's response object. stack enough information to write to the
// server on the submit callback, and enough to resume the lua state on the
// completion callback.
static void mcp_queue_io(conn *c, mc_resp *resp, int coro_ref, lua_State *Lc) {
    io_queue_t *q = conn_io_queue_get(c, IO_QUEUE_PROXY);

    // stack: request, hash selector. latter just to hold a reference.

    mcp_request_t *rq = luaL_checkudata(Lc, -1, "mcp.request");
    mcp_backend_t *be = rq->be;

    // Then we push a response object, which we'll re-use later.
    // reserve one uservalue for a lua-supplied response.
    mcp_resp_t *r = lua_newuserdatauv(Lc, sizeof(mcp_resp_t), 1);
    // FIXME (v2): is this memset still necessary? I was using it for
    // debugging.
    memset(r, 0, sizeof(mcp_resp_t));
    r->buf = NULL;
    r->blen = 0;
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

    luaL_getmetatable(Lc, "mcp.response");
    lua_setmetatable(Lc, -2);

    io_pending_proxy_t *p = do_cache_alloc(c->thread->io_cache);
    if (p == NULL) {
        WSTAT_INCR(c, proxy_conn_oom, 1);
        proxy_lua_error(Lc, "out of memory allocating from IO cache");
        return;
    }

    // this is a re-cast structure, so assert that we never outsize it.
    assert(sizeof(io_pending_t) >= sizeof(io_pending_proxy_t));
    memset(p, 0, sizeof(io_pending_proxy_t));
    // set up back references.
    p->io_queue_type = IO_QUEUE_PROXY;
    p->thread = c->thread;
    p->c = c;
    p->resp = resp;
    p->client_resp = r;
    p->flushed = false;
    p->ascii_multiget = rq->ascii_multiget;
    resp->io_pending = (io_pending_t *)p;

    // top of the main thread should be our coroutine.
    // lets grab a reference to it and pop so it doesn't get gc'ed.
    p->coro_ref = coro_ref;

    // we'll drop the pointer to the coro on here to save some CPU
    // on re-fetching it later. The pointer shouldn't change.
    p->coro = Lc;

    // The direct backend object. Lc is holding the reference in the stack
    p->backend = be;
    // See #887 for notes.
    // TODO (v2): hopefully this can be optimized out.
    strncpy(r->be_name, be->name, MAX_NAMELEN+1);
    strncpy(r->be_port, be->port, MAX_PORTLEN+1);

    mcp_request_attach(Lc, rq, p);

    // link into the batch chain.
    p->next = q->stack_ctx;
    q->stack_ctx = p;

    return;
}

// Common lua debug command.
__attribute__((unused)) void dump_stack(lua_State *L) {
    int top = lua_gettop(L);
    int i = 1;
    fprintf(stderr, "--TOP OF STACK [%d]\n", top);
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



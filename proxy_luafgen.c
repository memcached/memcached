/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"
#ifdef TLS
#include "tls.h"
#endif

static mcp_funcgen_t *mcp_funcgen_route(lua_State *L, mcp_funcgen_t *fgen, mcp_parser_t *pr);
static int mcp_funcgen_router_cleanup(lua_State *L, mcp_funcgen_t *fgen);
static void _mcplib_funcgen_cache(mcp_funcgen_t *fgen, mcp_rcontext_t *rctx);
static void mcp_funcgen_cleanup(lua_State *L, mcp_funcgen_t *fgen);
static void mcp_resume_rctx_from_cb(mcp_rcontext_t *rctx);
static void proxy_return_rqu_cb(io_pending_t *pending);

static inline void _mcp_queue_hack(conn *c) {
    if (c) {
        // HACK
        // see notes above proxy_run_rcontext.
        // in case the above resume calls queued new work, we have to submit
        // it to the backend handling system here.
        for (io_queue_t *q = c->io_queues; q->type != IO_QUEUE_NONE; q++) {
            if (q->stack_ctx != NULL) {
                io_queue_cb_t *qcb = thread_io_queue_get(c->thread, q->type);
                qcb->submit_cb(q);
            }
        }
    }
}

// If we're GC'ed but not closed, it means it was created but never
// attached to a function, so ensure everything is closed properly.
int mcplib_funcgen_gc(lua_State *L) {
    mcp_funcgen_t *fgen = luaL_checkudata(L, -1, "mcp.funcgen");
    if (fgen->closed) {
        return 0;
    }
    assert(fgen->self_ref == 0);

    mcp_funcgen_cleanup(L, fgen);
    fgen->closed = true;
    return 0;
}

// handler for *_wait_*() variants and sleep calls
static void mcp_funcgen_wait_handler(const int fd, const short which, void *arg) {
    mcp_rcontext_t *rctx = arg;

    // if we were in waiting: reset wait mode, push wait_done + boolean true
    // if we were in sleep: reset wait mode.
    // immediately resume.
    lua_settop(rctx->Lc, 0);
    rctx->wait_count = 0;
    rctx->lua_narg = 2;
    if (rctx->wait_mode == QWAIT_HANDLE) {
        // if timed out then we shouldn't have a result. just push nil.
        lua_pushnil(rctx->Lc);
    } else if (rctx->wait_mode == QWAIT_SLEEP) {
        // no extra arg.
        rctx->lua_narg = 1;
    } else {
        // how many results were processed
        lua_pushinteger(rctx->Lc, rctx->wait_done);
    }
    // "timed out"
    lua_pushboolean(rctx->Lc, 1);

    rctx->wait_mode = QWAIT_IDLE;

    mcp_resume_rctx_from_cb(rctx);
}

// For describing functions which generate functions which can execute
// requests.
// These "generator functions" handle pre-allocating and creating a memory
// heirarchy, allowing dynamic runtimes at high speed.

// must be called with fgen on top of stack in fgen->thread->L
static void mcp_rcontext_cleanup(lua_State *L, mcp_funcgen_t *fgen, mcp_rcontext_t *rctx, int fgen_idx) {
    luaL_unref(L, LUA_REGISTRYINDEX, rctx->coroutine_ref);
    luaL_unref(L, LUA_REGISTRYINDEX, rctx->function_ref);
    if (rctx->request_ref) {
        luaL_unref(L, LUA_REGISTRYINDEX, rctx->request_ref);
    }
    assert(rctx->pending_reqs == 0);

    // cleanup of request queue entries. recurse funcgen cleanup.
    for (int x = 0; x < fgen->max_queues; x++) {
        struct mcp_rqueue_s *rqu = &rctx->qslots[x];
        if (rqu->obj_type == RQUEUE_TYPE_POOL) {
            // nothing to do.
        } else if (rqu->obj_type == RQUEUE_TYPE_FGEN) {
            // don't need to recurse, just free the subrctx.
            mcp_rcontext_t *subrctx = rqu->obj;
            lua_rawgeti(L, LUA_REGISTRYINDEX, subrctx->fgen->self_ref);
            mcp_rcontext_cleanup(L, subrctx->fgen, subrctx, lua_absindex(L, -1));
            lua_pop(L, 1); // drop subrctx fgen
        } else if (rqu->obj_type != RQUEUE_TYPE_NONE) {
            assert(1 == 0);
        }

        if (rqu->res_ref) {
            luaL_unref(L, LUA_REGISTRYINDEX, rqu->res_ref);
            rqu->res_ref = 0;
        }

        if (rqu->cb_ref) {
            luaL_unref(L, LUA_REGISTRYINDEX, rqu->cb_ref);
            rqu->cb_ref = 0;
        }
    }

    // look for rctx-local objects.
    if (rctx->uobj_count) {
        int lim = fgen->max_queues + rctx->uobj_count;
        for (int x = fgen->max_queues; x < lim; x++) {
            struct mcp_rqueue_s *rqu = &rctx->qslots[x];
            // Don't need to look at the type:
            // - slot has to be freed (thus cleaned up) before getting here
            // - any uobj is ref'ed into obj_ref
            luaL_unref(L, LUA_REGISTRYINDEX, rqu->obj_ref);
            rqu->obj_ref = 0;
        }
    }

    // nuke alarm if set.
    // should only be paranoia here, but just in case.
    if (event_pending(&rctx->timeout_event, EV_TIMEOUT, NULL)) {
        event_del(&rctx->timeout_event);
    }

    lua_getiuservalue(L, fgen_idx, 1);
    luaL_unref(L, -1, rctx->self_ref);
    rctx->self_ref = 0;
    lua_pop(L, 1); // drop freelist table

    fgen->total--;
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    // Fake an allocation when we free slots as they are long running data.
    // This tricks the GC into running and freeing them.
    t->proxy_vm_extra_kb += 2;
    mcp_sharedvm_delta(t->proxy_ctx, SHAREDVM_FGENSLOT_IDX, fgen->name, -1);
}

// TODO: switch from an array to a STAILQ so we can avoid the memory
// management and error handling.
// Realistically it's impossible for these to error so we're safe for now.
#ifdef MEMCACHED_DEBUG
// require fewer test rounds for unit tests.
#define FGEN_FREE_PRESSURE_MAX 100
#define FGEN_FREE_PRESSURE_DROP 10
#define FGEN_FREE_WAIT 0
#else
#define FGEN_FREE_PRESSURE_MAX 5000
#define FGEN_FREE_PRESSURE_DROP 200
#define FGEN_FREE_WAIT 60 // seconds.
#endif
static void _mcplib_funcgen_cache(mcp_funcgen_t *fgen, mcp_rcontext_t *rctx) {
    bool do_cache = true;
    // Easing algorithm to decide when to "early free" rctx slots:
    // - If we recently allocated a slot, reset pressure.
    // - Each time an rctx is freed and more than half of available rctx's are
    // free, increase pressure.
    // - If free rctx are less than half of total, reduce pressure.
    // - If pressure is too high, immediately free the rctx, then drop the
    // pressure slightly.
    // - If pressure is too high, and has been for more than FGEN_FREE_WAIT
    // seconds, immediately free the rctx, then drop the pressure slightly.
    //
    // This should allow bursty traffic to avoid spinning on alloc/frees,
    // while one-time bursts will slowly free slots back down to a min of 1.
    if (fgen->free > fgen->total/2 - 1) {
        if (fgen->free_pressure++ > FGEN_FREE_PRESSURE_MAX) {
            struct timespec now;
            clock_gettime(CLOCK_REALTIME, &now);
            if (fgen->free_waiter.tv_sec == 0) {
                fgen->free_waiter.tv_sec = now.tv_sec + FGEN_FREE_WAIT;
            }

            if (now.tv_sec >= fgen->free_waiter.tv_sec) {
                do_cache = false;
            }
            // check again in a little while.
            fgen->free_pressure -= FGEN_FREE_PRESSURE_DROP;
        }
    } else {
        fgen->free_pressure >>= 1;
        // must be too-free for a full wait period before releasing.
        fgen->free_waiter.tv_sec = 0;
    }

    if (do_cache) {
        if (fgen->free + 1 >= fgen->free_max) {
            int x = fgen->free_max;
            fgen->free_max *= 2;
            fgen->list = realloc(fgen->list, fgen->free_max * sizeof(mcp_rcontext_t *));
            for (; x < fgen->free_max; x++) {
                fgen->list[x] = NULL;
            }
        }
        fgen->list[fgen->free] = rctx;
        fgen->free++;
    } else {
        // do not cache the rctx
        assert(fgen->self_ref);
        lua_State *L = fgen->thread->L;
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->self_ref);
        mcp_rcontext_cleanup(L, fgen, rctx, lua_absindex(L, -1));
        lua_pop(L, 1); // drop fgen
    }

    // we're closed and every outstanding request slot has been
    // returned.
    if (fgen->closed && fgen->free == fgen->total) {
        mcp_funcgen_cleanup(fgen->thread->L, fgen);
    }
}

// call with stack: mcp.funcgen -2, function -1
static int _mcplib_funcgen_gencall(lua_State *L) {
    mcp_funcgen_t *fgen = luaL_checkudata(L, -2, "mcp.funcgen");
    int fgen_idx = lua_absindex(L, -2);
    // create the ctx object.
    int total_queues = fgen->max_queues + fgen->uobj_queues;
    size_t rctx_len = sizeof(mcp_rcontext_t) + sizeof(struct mcp_rqueue_s) * total_queues;
    mcp_rcontext_t *rc = lua_newuserdatauv(L, rctx_len, 0);
    memset(rc, 0, rctx_len);

    luaL_getmetatable(L, "mcp.rcontext");
    lua_setmetatable(L, -2);
    // allow the rctx to reference the function generator.
    rc->fgen = fgen;
    rc->lua_narg = 1;

    // initialize the queue slots based on the fgen parent
    for (int x = 0; x < fgen->max_queues; x++) {
        struct mcp_rqueue_s *frqu = &fgen->queue_list[x];
        struct mcp_rqueue_s *rqu = &rc->qslots[x];
        rqu->obj_type = frqu->obj_type;
        if (frqu->obj_type == RQUEUE_TYPE_POOL) {
            rqu->obj_ref = 0;
            rqu->obj = frqu->obj;
            mcp_resp_t *r = mcp_prep_bare_resobj(L, fgen->thread);
            rqu->res_ref = luaL_ref(L, LUA_REGISTRYINDEX);
            rqu->res_obj = r;
        } else if (frqu->obj_type == RQUEUE_TYPE_FGEN) {
            // owner funcgen already holds the subfgen reference, so here we're just
            // grabbing a subrctx to pin into the slot.
            mcp_funcgen_t *fg = frqu->obj;
            mcp_rcontext_t *subrctx = mcp_funcgen_get_rctx(L, fg->self_ref, fg);
            if (subrctx == NULL) {
                proxy_lua_error(L, "failed to generate request slot during queue_assign()");
            }

            // if this rctx ever had a request object assigned to it, we can get
            // rid of it. we're pinning the subrctx in here and don't want
            // to waste memory.
            if (subrctx->request_ref) {
                luaL_unref(L, LUA_REGISTRYINDEX, subrctx->request_ref);
                subrctx->request_ref = 0;
                subrctx->request = NULL;
            }

            // link the new rctx into this chain; we'll hold onto it until the
            // parent de-allocates.
            subrctx->parent = rc;
            subrctx->parent_handle = x;
            rqu->obj = subrctx;
        }
    }

    // copy the rcontext reference
    lua_pushvalue(L, -1);

    // issue a rotation so one rcontext is now below genfunc, and one rcontext
    // is on the top.
    // right shift: gf, rc1, rc2 -> rc2, gf, rc1
    lua_rotate(L, -3, 1);

    // current stack should be func, mcp.rcontext.
    int call_argnum = 1;
    // stack will be func, rctx, arg if there is an arg.
    if (fgen->argument_ref) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->argument_ref);
        call_argnum++;
    }

    // can throw an error upstream.
    lua_call(L, call_argnum, 1);

    // we should have a top level function as a result.
    if (!lua_isfunction(L, -1)) {
        proxy_lua_error(L, "function generator didn't return a function");
        return 0;
    }
    // can't fail past this point.

    // pop the returned function.
    rc->function_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // link the rcontext into the function generator.
    fgen->total++;

    lua_getiuservalue(L, fgen_idx, 1); // get the reference table.
    // rc, t -> t, rc
    lua_rotate(L, -2, 1);
    rc->self_ref = luaL_ref(L, -2); // pop rcontext
    lua_pop(L, 1); // pop ref table.

    _mcplib_funcgen_cache(fgen, rc);

    // associate a coroutine thread with this context.
    rc->Lc = lua_newthread(L);
    assert(rc->Lc);
    rc->coroutine_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // increment the slot counter
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_sharedvm_delta(t->proxy_ctx, SHAREDVM_FGENSLOT_IDX, fgen->name, 1);

    event_assign(&rc->timeout_event, t->base, -1, EV_TIMEOUT, mcp_funcgen_wait_handler, rc);

    // return the fgen.
    // FIXME: just return 0? need to adjust caller to not mis-ref the
    // generator function.
    return 1;
}

static void _mcp_funcgen_return_rctx(mcp_rcontext_t *rctx) {
    mcp_funcgen_t *fgen = rctx->fgen;
    assert(rctx->pending_reqs == 0);
    int res = lua_resetthread(rctx->Lc);
    if (res != LUA_OK) {
        // TODO: I was under the impression it was possible to reuse a
        // coroutine from an error state, but it seems like this only works if
        // the routine landed in LUA_YIELD or LUA_OK
        // Leaving a note here to triple check this or if my memory was wrong.
        // Instead for now we throw away the coroutine if it was involved in
        // an error. Realistically this shouldn't be normal so it might not
        // matter anyway.
        lua_State *L = fgen->thread->L;
        luaL_unref(L, LUA_REGISTRYINDEX, rctx->coroutine_ref);
        rctx->Lc = lua_newthread(L);
        assert(rctx->Lc);
        rctx->coroutine_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_settop(rctx->Lc, 0);
    }
    rctx->wait_mode = QWAIT_IDLE;
    rctx->resp = NULL;
    rctx->first_queue = false; // HACK
    if (rctx->request) {
        mcp_request_cleanup(fgen->thread, rctx->request);
    }

    // nuke alarm if set.
    if (event_pending(&rctx->timeout_event, EV_TIMEOUT, NULL)) {
        event_del(&rctx->timeout_event);
    }

    // reset each rqu.
    for (int x = 0; x < fgen->max_queues; x++) {
        struct mcp_rqueue_s *rqu = &rctx->qslots[x];
        if (rqu->res_ref) {
            if (rqu->res_obj) {
                // using a persistent object.
                mcp_response_cleanup(fgen->thread, rqu->res_obj);
            } else {
                // temporary error object
                luaL_unref(rctx->Lc, LUA_REGISTRYINDEX, rqu->res_ref);
                rqu->res_ref = 0;
            }
        }
        if (rqu->req_ref) {
            luaL_unref(rctx->Lc, LUA_REGISTRYINDEX, rqu->req_ref);
            rqu->req_ref = 0;
        }
        assert(rqu->state != RQUEUE_ACTIVE);
        rqu->state = RQUEUE_IDLE;
        rqu->flags = 0;
        rqu->rq = NULL;
        if (rqu->obj_type == RQUEUE_TYPE_FGEN) {
            _mcp_funcgen_return_rctx(rqu->obj);
        }
    }

    // look for rctx-local objects.
    if (rctx->uobj_count) {
        int lim = fgen->max_queues + rctx->uobj_count;
        for (int x = fgen->max_queues; x < lim; x++) {
            struct mcp_rqueue_s *rqu = &rctx->qslots[x];
            if (rqu->obj_type == RQUEUE_TYPE_UOBJ_REQ) {
                mcp_request_t *rq = rqu->obj;
                mcp_request_cleanup(fgen->thread, rq);
            } else if (rqu->obj_type == RQUEUE_TYPE_UOBJ_RES) {
                mcp_resp_t *rs = rqu->obj;
                mcp_response_cleanup(fgen->thread, rs);
            } else {
                // no known type. only crash the debug binary.
                assert(1 == 0);
            }
        }
    }
}

// TODO: check rctx->awaiting before returning?
// TODO: separate the "cleanup" portion from the "Return to cache" portion, so
// we can call that directly for subrctx's
void mcp_funcgen_return_rctx(mcp_rcontext_t *rctx) {
    mcp_funcgen_t *fgen = rctx->fgen;
    if (rctx->pending_reqs != 0) {
        // not ready to return to cache yet.
        return;
    }
    if (rctx->parent) {
        // Important: we need to hold the parent request reference until this
        // subrctx is fully depleted of outstanding requests itself.
        rctx->parent->pending_reqs--;
        assert(rctx->parent->pending_reqs > -1);
        if (rctx->parent->pending_reqs == 0) {
            mcp_funcgen_return_rctx(rctx->parent);
        }
        return;
    }
    WSTAT_DECR(rctx->fgen->thread, proxy_req_active, 1);
    _mcp_funcgen_return_rctx(rctx);
    _mcplib_funcgen_cache(fgen, rctx);
}

mcp_rcontext_t *mcp_funcgen_get_rctx(lua_State *L, int fgen_ref, mcp_funcgen_t *fgen) {
    mcp_rcontext_t *rctx = NULL;
    // nothing left in slot cache, generate a new function.
    if (fgen->free == 0) {
        // reset free pressure so we try to keep the rctx cached
        fgen->free_pressure = 0;
        fgen->free_waiter.tv_sec = 0;
        // TODO (perf): pre-create this c closure somewhere hidden.
        lua_pushcclosure(L, _mcplib_funcgen_gencall, 0);
        // pull in the funcgen object
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen_ref);
        // then generator function
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->generator_ref);
        // then generate a new function slot.
        int res = lua_pcall(L, 2, 1, 0);
        if (res != LUA_OK) {
            LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_ERROR, NULL, lua_tostring(L, -1));
            lua_settop(L, 0);
            return NULL;
        }
        lua_pop(L, 1); // drop the extra funcgen
    } else {
        P_DEBUG("%s: serving from cache\n", __func__);
    }

    rctx = fgen->list[fgen->free-1];
    fgen->list[fgen->free-1] = NULL;
    fgen->free--;

    // on non-error, return the response object upward.
    return rctx;
}

mcp_rcontext_t *mcp_funcgen_start(lua_State *L, mcp_funcgen_t *fgen, mcp_parser_t *pr) {
    if (fgen->is_router) {
        fgen = mcp_funcgen_route(L, fgen, pr);
        if (fgen == NULL) {
            return NULL;
        }
    }
    // fgen->self_ref must be valid because we cannot start a function that
    // hasn't been referenced anywhere.
    mcp_rcontext_t *rctx = mcp_funcgen_get_rctx(L, fgen->self_ref, fgen);

    if (rctx == NULL) {
        return NULL;
    }

    // only top level rctx's can have a request object assigned to them.
    // so we create them late here, in the start function.
    // Note that we can _technically_ fail with an OOM here, but we've not set
    // up lua in a way that OOM's are possible.
    if (rctx->request_ref == 0) {
        mcp_request_t *rq = lua_newuserdatauv(L, sizeof(mcp_request_t) + MCP_REQUEST_MAXLEN, 0);
        memset(rq, 0, sizeof(mcp_request_t));
        luaL_getmetatable(L, "mcp.request");
        lua_setmetatable(L, -2);

        rctx->request_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pop the request
        rctx->request = rq;
    }

    // TODO: could probably move a few more lines from proto_proxy into here,
    // but that's splitting hairs.
    WSTAT_INCR(fgen->thread, proxy_req_active, 1);
    return rctx;
}

// calling either with self_ref set, or with fgen in stack -1 (ie; from GC
// function without ever being attached to anything)
static void mcp_funcgen_cleanup(lua_State *L, mcp_funcgen_t *fgen) {
    int fgen_idx = 0;
    lua_checkstack(L, 5); // paranoia. this can recurse from a router.
    // pull the fgen into the stack.
    if (fgen->self_ref) {
        // pull self onto the stack and hold until the end of the func.
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->self_ref);
        fgen_idx = lua_absindex(L, -1); // remember fgen offset
        // remove the C reference to the fgen
        luaL_unref(L, LUA_REGISTRYINDEX, fgen->self_ref);
        fgen->self_ref = 0;
    } else if (fgen->closed) {
        // we've already cleaned up, probably redundant call from _gc()
        return;
    } else {
        // not closed, no self-ref, so must be unattached and coming from GC
        fgen_idx = lua_absindex(L, -1);
    }

    if (fgen->is_router) {
        // we're actually a "router", send this out for cleanup.
        mcp_funcgen_router_cleanup(L, fgen);
    }

    // decrement the slot counter
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    mcp_sharedvm_delta(t->proxy_ctx, SHAREDVM_FGEN_IDX, fgen->name, -1);

    // Walk every request context and issue cleanup.
    for (int x = 0; x < fgen->free_max; x++) {
        mcp_rcontext_t *rctx = fgen->list[x];
        if (rctx == NULL) {
            continue;
        }
        mcp_rcontext_cleanup(L, fgen, rctx, fgen_idx);
    }

    if (fgen->argument_ref) {
        luaL_unref(L, LUA_REGISTRYINDEX, fgen->argument_ref);
        fgen->argument_ref = 0;
    }

    if (fgen->generator_ref) {
        luaL_unref(L, LUA_REGISTRYINDEX, fgen->generator_ref);
        fgen->generator_ref = 0;
    }

    if (fgen->queue_list) {
        for (int x = 0; x < fgen->max_queues; x++) {
            struct mcp_rqueue_s *rqu = &fgen->queue_list[x];
            if (rqu->obj_type == RQUEUE_TYPE_POOL) {
                // just the obj_ref
                luaL_unref(L, LUA_REGISTRYINDEX, rqu->obj_ref);
            } else if (rqu->obj_type == RQUEUE_TYPE_FGEN) {
                // don't need to recurse, just deref.
                mcp_funcgen_t *subfgen = rqu->obj;
                mcp_funcgen_dereference(L, subfgen);
            } else if (rqu->obj_type != RQUEUE_TYPE_NONE) {
                assert(1 == 0);
            }
        }
        free(fgen->queue_list);
    }

    free(fgen->list);
    fgen->list = NULL;
    lua_pop(L, 1); // drop funcgen reference
}

// Must be called with the function generator at on top of stack
// Pops the value from the stack.
void mcp_funcgen_reference(lua_State *L) {
    mcp_funcgen_t *fgen = luaL_checkudata(L, -1, "mcp.funcgen");
    if (fgen->self_ref) {
        fgen->refcount++;
        lua_pop(L, 1); // ensure we drop the extra value.
    } else {
        fgen->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        fgen->refcount = 1;
    }
    P_DEBUG("%s: funcgen referenced: %d\n", __func__, fgen->refcount);
}

void mcp_funcgen_dereference(lua_State *L, mcp_funcgen_t *fgen) {
    assert(fgen->refcount > 0);
    fgen->refcount--;
    P_DEBUG("%s: funcgen dereferenced: %d\n", __func__, fgen->refcount);
    if (fgen->refcount == 0) {
        fgen->closed = true;

        P_DEBUG("%s: funcgen cleaning up\n", __func__);
        if (fgen->free == fgen->total) {
            mcp_funcgen_cleanup(L, fgen);
        }
    }
}

// All we need to do here is copy the function reference we've stashed into
// the C closure's upvalue and return it.
static int _mcplib_funcgenbare_generator(lua_State *L) {
    lua_pushvalue(L, lua_upvalueindex(1));
    return 1;
}

// helper function to create a function generator with a "default" function.
// the function passed in here is a standard 'function(r) etc end' prototype,
// which we want to always return instead of calling a real generator
// function.
int mcplib_funcgenbare_new(lua_State *L) {
    if (!lua_isfunction(L, -1)) {
        proxy_lua_error(L, "Must pass a function to mcp.funcgenbare_new");
        return 0;
    }

    // Pops the function into the upvalue of this C closure function.
    lua_pushcclosure(L, _mcplib_funcgenbare_generator, 1);
    // FIXME: not urgent, but this function chain isn't stack balanced, and its caller has
    // to drop an extra reference.
    // Need to re-audit and decide if we still need this pushvalue here or if
    // we can drop the pop from the caller and leave this function balanced.
    lua_pushvalue(L, -1);
    int gen_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // Pass our fakeish generator function down the line.
    mcplib_funcgen_new(L);

    mcp_funcgen_t *fgen = lua_touserdata(L, -1);
    strncpy(fgen->name, "anonymous", FGEN_NAME_MAXLEN);
    mcp_sharedvm_delta(fgen->thread->proxy_ctx, SHAREDVM_FGEN_IDX, fgen->name, 1);

    fgen->generator_ref = gen_ref;
    fgen->ready = true;
    return 1;
}

#define FGEN_DEFAULT_FREELIST_SIZE 8
int mcplib_funcgen_new(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);

    mcp_funcgen_t *fgen = lua_newuserdatauv(L, sizeof(mcp_funcgen_t), 2);
    memset(fgen, 0, sizeof(mcp_funcgen_t));
    fgen->thread = t;
    fgen->free_max = FGEN_DEFAULT_FREELIST_SIZE;
    fgen->list = calloc(fgen->free_max, sizeof(mcp_rcontext_t *));

    luaL_getmetatable(L, "mcp.funcgen");
    lua_setmetatable(L, -2);

    // the table we will use to hold references to rctx's
    lua_createtable(L, 8, 0);
    // set our table into the uservalue 1 of fgen (idx -2)
    // pops the table.
    lua_setiuservalue(L, -2, 1);

    return 1;
}

int mcplib_funcgen_new_handle(lua_State *L) {
    mcp_funcgen_t *fgen = lua_touserdata(L, 1);
    mcp_pool_proxy_t *pp = NULL;
    mcp_funcgen_t *fg = NULL;

    if (fgen->ready) {
        proxy_lua_error(L, "cannot modify function generator after calling ready");
        return 0;
    }

    if ((pp = luaL_testudata(L, 2, "mcp.pool_proxy")) != NULL) {
        // good.
    } else if ((fg = luaL_testudata(L, 2, "mcp.funcgen")) != NULL) {
        if (fg->is_router) {
            proxy_lua_error(L, "cannot assign a router to a handle in new_handle");
            return 0;
        }
        if (fg->closed) {
            proxy_lua_error(L, "cannot use a replaced function in new_handle");
            return 0;
        }
    } else {
        proxy_lua_error(L, "invalid argument to new_handle");
        return 0;
    }

    fgen->max_queues++;
    if (fgen->queue_list == NULL) {
        fgen->queue_list = malloc(sizeof(struct mcp_rqueue_s));
    } else {
        fgen->queue_list = realloc(fgen->queue_list, fgen->max_queues * sizeof(struct mcp_rqueue_s));
    }
    if (fgen->queue_list == NULL) {
        proxy_lua_error(L, "failed to realloc queue list during new_handle()");
        return 0;
    }

    struct mcp_rqueue_s *rqu = &fgen->queue_list[fgen->max_queues-1];
    memset(rqu, 0, sizeof(*rqu));

    if (pp) {
        // pops pp from the stack
        rqu->obj_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        rqu->obj_type = RQUEUE_TYPE_POOL;
        rqu->obj = pp;
    } else {
        // pops the fgen from the stack.
        mcp_funcgen_reference(L);
        rqu->obj_type = RQUEUE_TYPE_FGEN;
        rqu->obj = fg;
    }

    lua_pushinteger(L, fgen->max_queues-1);
    return 1;
}

int mcplib_funcgen_ready(lua_State *L) {
    mcp_funcgen_t *fgen = lua_touserdata(L, 1);
    luaL_checktype(L, 2, LUA_TTABLE);

    if (fgen->ready) {
        proxy_lua_error(L, "cannot modify function generator after calling ready");
        return 0;
    }

    if (lua_getfield(L, 2, "f") != LUA_TFUNCTION) {
        proxy_lua_error(L, "Must specify generator function ('f') to fgen:ready");
        return 0;
    }
    fgen->generator_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    if (lua_getfield(L, 2, "a") != LUA_TNIL) {
        fgen->argument_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_pop(L, 1);
    }

    if (lua_getfield(L, 2, "n") == LUA_TSTRING) {
        size_t len = 0;
        const char *name = lua_tolstring(L, -1, &len);
        strncpy(fgen->name, name, FGEN_NAME_MAXLEN);
    } else {
        strncpy(fgen->name, "anonymous", FGEN_NAME_MAXLEN);
        lua_pop(L, 1);
    }

    if (lua_getfield(L, 2, "u") == LUA_TNUMBER) {
        int uobj_queues = luaL_checkinteger(L, -1);
        if (uobj_queues < 1 || uobj_queues > RQUEUE_UOBJ_MAX) {
            proxy_lua_ferror(L, "user obj ('u') in fgen:ready must be between 1 and %d", RQUEUE_UOBJ_MAX);
            return 0;
        }
        fgen->uobj_queues = uobj_queues;
    }
    lua_pop(L, 1);

    // now we test the generator function and create the first slot.
    lua_pushvalue(L, 1); // copy the funcgen to pass into gencall
    lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->generator_ref); // for gencall
    _mcplib_funcgen_gencall(L);
    lua_pop(L, 1); // drop extra funcgen ref.

    // add us to the global state
    mcp_sharedvm_delta(fgen->thread->proxy_ctx, SHAREDVM_FGEN_IDX, fgen->name, 1);

    fgen->ready = true;
    return 1;
}

// Handlers for request contexts

int mcplib_rcontext_handle_set_cb(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    luaL_checktype(L, 2, LUA_TNUMBER);
    luaL_checktype(L, 3, LUA_TFUNCTION);

    int handle = lua_tointeger(L, 2);
    if (handle < 0 || handle >= rctx->fgen->max_queues) {
        proxy_lua_error(L, "invalid handle passed to queue_set_cb");
        return 0;
    }

    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    if (rqu->cb_ref) {
        luaL_unref(L, LUA_REGISTRYINDEX, rqu->cb_ref);
    }
    rqu->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    return 0;
}

// call with request object on top of stack.
// pops the request object
// FIXME: callers are doing a pushvalue(L, 2) and then in here we're also
// pushvalue(L, 2)
// Think this should just document as needing the request object top of stack
// and xmove without the extra push bits.
static void _mcplib_rcontext_queue(lua_State *L, mcp_rcontext_t *rctx, mcp_request_t *rq, int handle) {
    if (handle < 0 || handle >= rctx->fgen->max_queues) {
        proxy_lua_error(L, "attempted to enqueue an invalid handle");
        return;
    }
    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];

    if (rqu->state != RQUEUE_IDLE) {
        lua_pop(L, 1);
        return;
    }

    // If we're queueing to an fgen, arm the coroutine while we have the
    // objects handy. Else this requires roundtripping a luaL_ref/luaL_unref
    // later.
    if (rqu->obj_type == RQUEUE_TYPE_FGEN) {
        mcp_rcontext_t *subrctx = rqu->obj;
        lua_pushvalue(L, 2); // duplicate the request obj
        lua_rawgeti(subrctx->Lc, LUA_REGISTRYINDEX, subrctx->function_ref);
        lua_xmove(L, subrctx->Lc, 1); // move the requet object.
        subrctx->pending_reqs++;
    }

    // hold the request reference.
    rqu->req_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    rqu->state = RQUEUE_QUEUED;
    rqu->rq = rq;
}

// first arg is rcontext
// then a request object
// then either a handle (integer) or array style table of handles
int mcplib_rcontext_enqueue(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    mcp_request_t *rq = luaL_checkudata(L, 2, "mcp.request");

    if (rctx->wait_mode != QWAIT_IDLE) {
        proxy_lua_error(L, "enqueue: cannot enqueue new requests while in a wait");
        return 0;
    }

    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot queue requests without a key");
        return 0;
    }

    int type = lua_type(L, 3);
    if (type == LUA_TNUMBER) {
        int handle = lua_tointeger(L, 3);

        lua_pushvalue(L, 2);
        _mcplib_rcontext_queue(L, rctx, rq, handle);
    } else if (type == LUA_TTABLE) {
        unsigned int len = lua_rawlen(L, 3);
        for (int x = 0; x < len; x++) {
            type = lua_rawgeti(L, 3, x+1);
            if (type != LUA_TNUMBER) {
                proxy_lua_error(L, "invalid handle passed to queue via array table");
                return 0;
            }

            int handle = lua_tointeger(L, 4);
            lua_pop(L, 1);

            lua_pushvalue(L, 2);
            _mcplib_rcontext_queue(L, rctx, rq, handle);
        }
    } else {
        proxy_lua_error(L, "must pass a handle or a table to queue");
        return 0;
    }

    return 0;
}

// TODO: pre-generate a result object into sub-rctx's that we can pull up for
// this, instead of allocating outside of a protected call.
static void _mcp_resume_rctx_process_error(mcp_rcontext_t *rctx, struct mcp_rqueue_s *rqu) {
    // we have an error. need to mark the error into the parent rqu
    rqu->flags |= RQUEUE_R_ERROR|RQUEUE_R_ANY;
    mcp_resp_t *r = mcp_prep_bare_resobj(rctx->Lc, rctx->fgen->thread);
    r->status = MCMC_ERR;
    r->resp.code = MCMC_CODE_SERVER_ERROR;
    assert(rqu->res_ref == 0);
    rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
    mcp_process_rqueue_return(rctx->parent, rctx->parent_handle, r);
    if (rctx->parent->wait_count) {
        mcp_process_rctx_wait(rctx->parent, rctx->parent_handle);
    }
}

static void _mcp_start_rctx_process_error(mcp_rcontext_t *rctx, struct mcp_rqueue_s *rqu) {
    // we have an error. need to mark the error into the parent rqu
    rqu->flags |= RQUEUE_R_ERROR|RQUEUE_R_ANY;
    mcp_resp_t *r = mcp_prep_bare_resobj(rctx->Lc, rctx->fgen->thread);
    r->status = MCMC_ERR;
    r->resp.code = MCMC_CODE_SERVER_ERROR;
    assert(rqu->res_ref == 0);
    rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);

    // queue an IO to return later.
    io_pending_proxy_t *p = mcp_queue_rctx_io(rctx->parent, NULL, NULL, r);
    p->return_cb = proxy_return_rqu_cb;
    p->queue_handle = rctx->parent_handle;
    p->background = true;
}

static void mcp_start_subrctx(mcp_rcontext_t *rctx) {
    int res = proxy_run_rcontext(rctx);
    struct mcp_rqueue_s *rqu = &rctx->parent->qslots[rctx->parent_handle];
    if (res == LUA_OK) {
        int type = lua_type(rctx->Lc, 1);
        mcp_resp_t *r = NULL;
        if (type == LUA_TUSERDATA && (r = luaL_testudata(rctx->Lc, 1, "mcp.response")) != NULL) {
            // move stack result object into parent rctx rqu slot.
            assert(rqu->res_ref == 0);
            rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);

            io_pending_proxy_t *p = mcp_queue_rctx_io(rctx->parent, NULL, NULL, r);
            p->return_cb = proxy_return_rqu_cb;
            p->queue_handle = rctx->parent_handle;
            // TODO: change name of property to fast-return once mcp.await is
            // retired.
            p->background = true;
        } else if (type == LUA_TSTRING) {
            // TODO: wrap with a resobj and parse it.
            // for now we bypass the rqueue process handling
            // meaning no callbacks/etc.
            assert(rqu->res_ref == 0);
            rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
            rqu->flags |= RQUEUE_R_ANY;
            rqu->state = RQUEUE_COMPLETE;
            io_pending_proxy_t *p = mcp_queue_rctx_io(rctx->parent, NULL, NULL, NULL);
            p->return_cb = proxy_return_rqu_cb;
            p->queue_handle = rctx->parent_handle;
            p->background = true;
        } else {
            // generate a generic object with an error.
            _mcp_start_rctx_process_error(rctx, rqu);
        }
    } else if (res == LUA_YIELD) {
        // normal.
    } else {
        lua_pop(rctx->Lc, 1); // drop the error message.
        _mcp_start_rctx_process_error(rctx, rqu);
    }
}

static void mcp_resume_rctx_from_cb(mcp_rcontext_t *rctx) {
    int res = proxy_run_rcontext(rctx);
    if (rctx->parent) {
        struct mcp_rqueue_s *rqu = &rctx->parent->qslots[rctx->parent_handle];
        if (res == LUA_OK) {
            mcp_rcontext_t *parent = rctx->parent;
            int handle = rctx->parent_handle;
            int type = lua_type(rctx->Lc, 1);
            mcp_resp_t *r = NULL;
            if (type == LUA_TUSERDATA && (r = luaL_testudata(rctx->Lc, 1, "mcp.response")) != NULL) {
                // move stack result object into parent rctx rqu slot.
                assert(rqu->res_ref == 0);
                rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
                mcp_process_rqueue_return(rctx->parent, rctx->parent_handle, r);
            } else if (type == LUA_TSTRING) {
                // TODO: wrap with a resobj and parse it.
                // for now we bypass the rqueue process handling
                // meaning no callbacks/etc.
                assert(rqu->res_ref == 0);
                rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
                rqu->flags |= RQUEUE_R_ANY;
                rqu->state = RQUEUE_COMPLETE;
            } else {
                // generate a generic object with an error.
                _mcp_resume_rctx_process_error(rctx, rqu);
            }

            // return ourself before telling the parent to wait.
            mcp_funcgen_return_rctx(rctx);
            if (parent->wait_count) {
                mcp_process_rctx_wait(parent, handle);
            }
        } else if (res == LUA_YIELD) {
            // normal.
            _mcp_queue_hack(rctx->c);
        } else {
            lua_pop(rctx->Lc, 1); // drop the error message.
            _mcp_resume_rctx_process_error(rctx, rqu);
            mcp_funcgen_return_rctx(rctx);
        }
    } else {
        // Parent rctx has returned either a response or error to its top
        // level resp object and is now complete.
        // HACK
        // see notes in proxy_run_rcontext()
        // NOTE: this function is called from rqu_cb(), which pushes the
        // submission loop. This code below can call drive_machine(), which
        // calls submission loop if stuff is queued.
        // Would remove redundancy if we can signal up to rqu_cb() and either
        // q->count-- or do the inline submission at that level.
        if (res != LUA_YIELD) {
            mcp_funcgen_return_rctx(rctx);
            io_queue_t *q = conn_io_queue_get(rctx->c, IO_QUEUE_PROXY);
            q->count--;
            if (q->count == 0) {
                // call re-add directly since we're already in the worker thread.
                conn_worker_readd(rctx->c);
            }
        } else if (res == LUA_YIELD) {
            _mcp_queue_hack(rctx->c);
        }
    }
}

// This "Dummy" IO immediately resumes the yielded function, without a result
// attached.
static void proxy_return_rqu_dummy_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;
    mcp_rcontext_t *rctx = p->rctx;

    rctx->pending_reqs--;
    assert(rctx->pending_reqs > -1);

    lua_settop(rctx->Lc, 0);
    lua_pushinteger(rctx->Lc, 0); // return a "0" done count to the function.
    mcp_resume_rctx_from_cb(rctx);

    do_cache_free(p->thread->io_cache, p);
}

void mcp_process_rctx_wait(mcp_rcontext_t *rctx, int handle) {
    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    int status = rqu->flags;
    assert(rqu->state == RQUEUE_COMPLETE);
    // waiting for some IO's to complete before continuing.
    // meaning if we "match good" here, we can resume.
    // we can also resume if we are in wait mode but pending_reqs is down
    // to 1.
    switch (rctx->wait_mode) {
        case QWAIT_IDLE:
            // should be impossible to get here.
            // TODO: find a better path for throwing real errors from these
            // side cases. would feel better long term.
            abort();
            break;
        case QWAIT_GOOD:
            if (status & RQUEUE_R_GOOD) {
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
            }
            break;
        case QWAIT_OK:
            if (status & (RQUEUE_R_GOOD|RQUEUE_R_OK)) {
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
            }
            break;
        case QWAIT_ANY:
            rctx->wait_done++;
            rqu->state = RQUEUE_WAITED;
            break;
        case QWAIT_FASTGOOD:
            if (status & RQUEUE_R_GOOD) {
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
                // resume early if "good"
                status |= RQUEUE_R_RESUME;
            } else if (status & RQUEUE_R_OK) {
                // count but don't resume early if "ok"
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
            }
            break;
        case QWAIT_HANDLE:
            // waiting for a specific handle to return
            if (handle == rctx->wait_handle) {
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
            }
            break;
        case QWAIT_SLEEP:
            assert(1 == 0); // should not get here.
            break;
    }

    assert(rctx->pending_reqs != 0);
    if ((status & RQUEUE_R_RESUME) || rctx->wait_done == rctx->wait_count || rctx->pending_reqs == 1) {
        // ran out of stuff to wait for. time to resume.
        // TODO: can we do the settop at the yield? nothing we need to
        // keep in the stack in this mode.
        lua_settop(rctx->Lc, 0);
        rctx->wait_count = 0;
        if (rctx->wait_mode == QWAIT_HANDLE) {
            mcp_rcontext_push_rqu_res(rctx->Lc, rctx, handle);
        } else {
            lua_pushinteger(rctx->Lc, rctx->wait_done);
        }
        rctx->wait_mode = QWAIT_IDLE;

        // nuke alarm if set.
        if (event_pending(&rctx->timeout_event, EV_TIMEOUT, NULL)) {
            event_del(&rctx->timeout_event);
        }

        mcp_resume_rctx_from_cb(rctx);
    }
}

// sets the slot's return status code, to be used for filtering responses
// later.
// if a callback was set, execute it now.
int mcp_process_rqueue_return(mcp_rcontext_t *rctx, int handle, mcp_resp_t *res) {
    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    uint8_t flag = RQUEUE_R_ANY;

    assert(rqu->state == RQUEUE_ACTIVE);
    rqu->state = RQUEUE_COMPLETE;
    if (res->status == MCMC_OK) {
        if (res->resp.code != MCMC_CODE_END) {
            flag = RQUEUE_R_GOOD;
        } else {
            flag = RQUEUE_R_OK;
        }
    }

    if (rqu->cb_ref) {
        lua_settop(rctx->Lc, 0);
        lua_rawgeti(rctx->Lc, LUA_REGISTRYINDEX, rqu->cb_ref);
        lua_rawgeti(rctx->Lc, LUA_REGISTRYINDEX, rqu->res_ref);
        lua_rawgeti(rctx->Lc, LUA_REGISTRYINDEX, rqu->req_ref);
        if (lua_pcall(rctx->Lc, 2, 2, 0) != LUA_OK) {
            LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_ERROR, NULL, lua_tostring(rctx->Lc, -1));
        } else if (lua_isinteger(rctx->Lc, 1)) {
            // allow overriding the result flag from the callback.
            enum mcp_rqueue_e mode = lua_tointeger(rctx->Lc, 1);
            switch (mode) {
                case QWAIT_GOOD:
                    flag = RQUEUE_R_GOOD;
                    break;
                case QWAIT_OK:
                    flag = RQUEUE_R_OK;
                    break;
                case QWAIT_ANY:
                    break;
                default:
                    // ANY
                    break;
            }

            // if second result return shortcut status code
            if (lua_toboolean(rctx->Lc, 2)) {
                flag |= RQUEUE_R_RESUME;
            }
        }
        lua_settop(rctx->Lc, 0); // FIXME: This might not be necessary.
                                 // we settop _before_ calling cb's and
                                 // _before_ setting up for a coro resume.
    }
    rqu->flags |= flag;
    return rqu->flags;
}

// specific function for queue-based returns.
static void proxy_return_rqu_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;
    mcp_rcontext_t *rctx = p->rctx;

    if (p->client_resp) {
        mcp_process_rqueue_return(rctx, p->queue_handle, p->client_resp);
    }
    rctx->pending_reqs--;
    assert(rctx->pending_reqs > -1);

    if (rctx->wait_count) {
        mcp_process_rctx_wait(rctx, p->queue_handle);
    } else {
        mcp_funcgen_return_rctx(rctx);
    }

    do_cache_free(p->thread->io_cache, p);
}

void mcp_run_rcontext_handle(mcp_rcontext_t *rctx, int handle) {
    struct mcp_rqueue_s *rqu = NULL;
    rqu = &rctx->qslots[handle];

    if (rqu->state == RQUEUE_QUEUED) {
        rqu->state = RQUEUE_ACTIVE;
        if (rqu->obj_type == RQUEUE_TYPE_POOL) {
            mcp_request_t *rq = rqu->rq;
            mcp_backend_t *be = mcplib_pool_proxy_call_helper(rqu->obj, MCP_PARSER_KEY(rq->pr), rq->pr.klen);
            // FIXME: queue requires conn because we're stacking objects
            // into the connection for later submission, which means we
            // absolutely cannot queue things once *c becomes invalid.
            // need to assert/block this from happening.
            mcp_set_resobj(rqu->res_obj, rq, be, rctx->fgen->thread);
            io_pending_proxy_t *p = mcp_queue_rctx_io(rctx, rq, be, rqu->res_obj);
            p->return_cb = proxy_return_rqu_cb;
            p->queue_handle = handle;
            rctx->pending_reqs++;
        } else if (rqu->obj_type == RQUEUE_TYPE_FGEN) {
            // TODO: NULL the ->c post-return?
            mcp_rcontext_t *subrctx = rqu->obj;
            subrctx->c = rctx->c;
            rctx->pending_reqs++;
            mcp_start_subrctx(subrctx);
        } else {
            assert(1==0);
        }
    } else if (rqu->state == RQUEUE_COMPLETE && rctx->wait_count) {
        // The slot was previously completed from an earlier dispatch, but we
        // haven't "waited" on it yet.
        mcp_process_rctx_wait(rctx, handle);
    }
}

static inline void _mcplib_set_rctx_alarm(lua_State *L, mcp_rcontext_t *rctx, int arg) {
    int isnum = 0;
    lua_Number secondsf = lua_tonumberx(L, arg, &isnum);
    if (!isnum) {
        proxy_lua_error(L, "timeout argument to wait or sleep must be a number");
        return;
    }
    int pending = event_pending(&rctx->timeout_event, EV_TIMEOUT, NULL);
    if ((pending & (EV_TIMEOUT)) == 0) {
        struct timeval tv = { .tv_sec = 0, .tv_usec = 0 };
        lua_Integer secondsi = (lua_Integer) secondsf;
        lua_Number subseconds = secondsf - secondsi;

        tv.tv_sec = secondsi;
        tv.tv_usec = MICROSECONDS(subseconds);
        event_add(&rctx->timeout_event, &tv);
    }
}

// TODO: one more function to wait on a list of handles? to queue and wait on
// a list of handles? expand wait_cond()

static inline int _mcplib_rcontext_wait_prep(lua_State *L, mcp_rcontext_t *rctx, int argc) {
    int mode = QWAIT_ANY;
    int wait = 0;

    if (rctx->wait_mode != QWAIT_IDLE) {
        proxy_lua_error(L, "wait_cond: cannot call while already in wait mode");
        return 0;
    }

    if (argc < 2) {
        proxy_lua_error(L, "must pass at least count to wait_cond");
        return 0;
    }

    int isnum = 0;
    wait = lua_tointegerx(L, 2, &isnum);
    if (!isnum || wait < 0) {
        proxy_lua_error(L, "wait count for wait_cond must be a positive integer");
        return 0;
    }

    if (argc > 2) {
        mode = lua_tointeger(L, 3);
    }

    switch (mode) {
        case QWAIT_ANY:
        case QWAIT_OK:
        case QWAIT_GOOD:
        case QWAIT_FASTGOOD:
            break;
        default:
            proxy_lua_error(L, "invalid mode sent to wait_cond");
            return 0;
    }

    rctx->wait_count = wait;
    rctx->wait_done = 0;
    rctx->wait_mode = mode;

    return 0;
}

// takes num, filter mode
int mcplib_rcontext_wait_cond(lua_State *L) {
    int argc = lua_gettop(L);
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);

    _mcplib_rcontext_wait_prep(L, rctx, argc);

    // waiting for none, meaning just execute the queues.
    if (rctx->wait_count == 0) {
        io_pending_proxy_t *p = mcp_queue_rctx_io(rctx, NULL, NULL, NULL);
        p->return_cb = proxy_return_rqu_dummy_cb;
        p->background = true;
        rctx->pending_reqs++;
        rctx->wait_mode = QWAIT_IDLE; // not actually waiting.
    } else if (argc > 3) {
        // optional wait timeout. does not cancel existing request!
        _mcplib_set_rctx_alarm(L, rctx, 4);
    }

    lua_pushinteger(L, MCP_YIELD_WAITCOND);
    return lua_yield(L, 1);
}

int mcplib_rcontext_enqueue_and_wait(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    mcp_request_t *rq = luaL_checkudata(L, 2, "mcp.request");
    int isnum = 0;
    int handle = lua_tointegerx(L, 3, &isnum);

    if (rctx->wait_mode != QWAIT_IDLE) {
        proxy_lua_error(L, "wait_cond: cannot call while already in wait mode");
        return 0;
    }

    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot queue requests without a key");
        return 0;
    }

    if (!isnum) {
        proxy_lua_error(L, "invalid handle passed to enqueue_and_wait");
        return 0;
    }

    // queue up this handle and yield for the direct wait.
    lua_pushvalue(L, 2);
    _mcplib_rcontext_queue(L, rctx, rq, handle);

    if (lua_gettop(L) > 3) {
        _mcplib_set_rctx_alarm(L, rctx, 4);
    }

    rctx->wait_done = 0;
    rctx->wait_count = 1;
    rctx->wait_mode = QWAIT_HANDLE;
    rctx->wait_handle = handle;

    lua_pushinteger(L, MCP_YIELD_WAITHANDLE);
    return lua_yield(L, 1);
}

int mcplib_rcontext_wait_handle(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    int isnum = 0;
    int handle = lua_tointegerx(L, 2, &isnum);

    if (rctx->wait_mode != QWAIT_IDLE) {
        proxy_lua_error(L, "wait: cannot call while already in wait mode");
        return 0;
    }

    if (!isnum || handle < 0 || handle >= rctx->fgen->max_queues) {
        proxy_lua_error(L, "invalid handle passed to wait_handle");
        return 0;
    }

    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    if (rqu->state == RQUEUE_IDLE) {
        proxy_lua_error(L, "wait_handle called on unqueued handle");
        return 0;
    }

    if (lua_gettop(L) > 2) {
        _mcplib_set_rctx_alarm(L, rctx, 3);
    }

    rctx->wait_done = 0;
    rctx->wait_count = 1;
    rctx->wait_mode = QWAIT_HANDLE;
    rctx->wait_handle = handle;

    lua_pushinteger(L, MCP_YIELD_WAITHANDLE);
    return lua_yield(L, 1);
}

// TODO: This is disabled due to issues with the IO subsystem. Fixing this
// requires retiring of API1 to allow refactoring or some extra roundtrip
// work.
// - if rctx:sleep() is called, the coroutine is suspended.
// - once resumed after the timeout, we may later suspend again and make
// backend requests
// - once the coroutine is completed, we need to check if the owning client
// conn is ready to be resumed
// - BUG: we can only get into the "conn is in IO queue wait" state if a
// sub-IO was created and submitted somewhere.
// - This means either rctx:sleep() needs to be implemented by submitting a
// dummy IO req (as other code does)
// - OR we need to refactor the IO system so the dummies aren't required
// anymore.
//
// If a dummy is used, we would have to implement this as:
// - immediately submit a dummy IO if sleep is called.
// - this allows the IO system to move the connection into the right state
// - will immediately circle back then set an alarm for the sleep timeout
// - once the sleep resumes, run code as normal. resumption should work
// properly since we've entered the correct state originally.
//
// This adds a lot of CPU overhead to sleep, which should be fine given the
// nature of the function, but also adds a lot of code and increases the
// chances of bugs. So I'm leaving it out until this can be implemented more
// simply.
int mcplib_rcontext_sleep(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    if (rctx->wait_mode != QWAIT_IDLE) {
        proxy_lua_error(L, "sleep: cannot call while already in wait mode");
        return 0;
    };

    _mcplib_set_rctx_alarm(L, rctx, 2);
    rctx->wait_mode = QWAIT_SLEEP;

    lua_pushinteger(L, MCP_YIELD_SLEEP);
    return lua_yield(L, 1);
}

static inline struct mcp_rqueue_s *_mcplib_rcontext_checkhandle(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    int isnum = 0;
    int handle = lua_tointegerx(L, 2, &isnum);
    if (!isnum || handle < 0 || handle >= rctx->fgen->max_queues) {
        proxy_lua_error(L, "invalid queue handle passed to :good/:ok:/:any");
        return NULL;
    }

    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    return rqu;
}

int mcplib_rcontext_res_good(lua_State *L) {
    struct mcp_rqueue_s *rqu = _mcplib_rcontext_checkhandle(L);
    if (rqu->flags & RQUEUE_R_GOOD) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int mcplib_rcontext_res_ok(lua_State *L) {
    struct mcp_rqueue_s *rqu = _mcplib_rcontext_checkhandle(L);
    if (rqu->flags & (RQUEUE_R_OK|RQUEUE_R_GOOD)) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int mcplib_rcontext_res_any(lua_State *L) {
    struct mcp_rqueue_s *rqu = _mcplib_rcontext_checkhandle(L);
    if (rqu->flags & (RQUEUE_R_ANY|RQUEUE_R_OK|RQUEUE_R_GOOD)) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
    } else {
        // Shouldn't be possible to get here, unless you're asking about a
        // queue that was never armed or hasn't completed yet.
        lua_pushnil(L);
    }
    return 1;
}

// returns res, RES_GOOD|OK|ANY
int mcplib_rcontext_result(lua_State *L) {
    struct mcp_rqueue_s *rqu = _mcplib_rcontext_checkhandle(L);
    if (rqu->flags & (RQUEUE_R_ANY|RQUEUE_R_OK|RQUEUE_R_GOOD)) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
        // mask away any other queue flags.
        lua_pushinteger(L, rqu->flags & (RQUEUE_R_ANY|RQUEUE_R_OK|RQUEUE_R_GOOD));
    } else {
        lua_pushnil(L);
        lua_pushnil(L);
    }

    return 2;
}

int mcplib_rcontext_cfd(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    lua_pushinteger(L, rctx->conn_fd);
    return 1;
}

// Must not call this if rctx has returned result to client already.
int mcplib_rcontext_tls_peer_cn(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    if (!rctx->c) {
        lua_pushnil(L);
        return 1;
    }

#ifdef TLS
    int len = 0;
    const unsigned char *cn = ssl_get_peer_cn(rctx->c, &len);
    if (cn) {
        lua_pushlstring(L, (const char *)cn, len);
    } else {
        lua_pushnil(L);
    }
#else
    lua_pushnil(L);
#endif
    return 1;
}

// call with uobj on top of stack
static void _mcplib_rcontext_ref_uobj(lua_State *L, mcp_rcontext_t *rctx, void *obj, int otype) {
    lua_pushvalue(L, -1); // dupe rq for the rqueue slot
    struct mcp_rqueue_s *rqu = &rctx->qslots[rctx->fgen->max_queues + rctx->uobj_count];
    rctx->uobj_count++;
    // hold the request reference into the rctx for memory management.
    rqu->obj_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    rqu->obj_type = otype;
    rqu->obj = obj;
}

// Creates request object that's tracked by request context so we can call
// cleanup routines post-run.
int mcplib_rcontext_request_new(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    if (rctx->uobj_count == rctx->fgen->uobj_queues) {
        proxy_lua_error(L, "rctx request new: object count limit reached");
        return 0;
    }

    // create new request object
    mcp_parser_t pr = {0};
    mcp_request_t *rq = mcp_new_request(L, &pr, " ", 1);

    _mcplib_rcontext_ref_uobj(L, rctx, rq, RQUEUE_TYPE_UOBJ_REQ);
    return 1;
}

int mcplib_rcontext_response_new(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    if (rctx->uobj_count == rctx->fgen->uobj_queues) {
        proxy_lua_error(L, "rctx request new: object count limit reached");
        return 0;
    }

    mcp_resp_t *r = lua_newuserdatauv(L, sizeof(mcp_resp_t), 0);
    memset(r, 0, sizeof(mcp_resp_t));
    luaL_getmetatable(L, "mcp.response");
    lua_setmetatable(L, -2);

    _mcplib_rcontext_ref_uobj(L, rctx, r, RQUEUE_TYPE_UOBJ_RES);
    return 1;
}

// the supplied handle must be valid.
void mcp_rcontext_push_rqu_res(lua_State *L, mcp_rcontext_t *rctx, int handle) {
    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
}

/*
 * Specialized router funcgen.
 * For routing a key across a map of possible function generators, we use a
 * specialized function generator. This is to keep the attach and start code
 * consistent, as they only need to think about function generators.
 * It also keeps the cleanup code consistent, as when a "router" funcgen is
 * replaced by mcp.attach() during a reload, we can immediately dereference
 * all of the route fgens, rather than have to wait for GC.
 *
 * Another upside is when we're starting a new request, we can immediately
 * swap out the top level fgen object, rather than force all routes to be
 * processed as sub-funcs, which is a tiny bit slower and disallows custom
 * request object sizes.
 *
 * The downside is this will appear to be bolted onto the side of the existing
 * structs rather than be its own object, like I initially wanted.
 */

static inline const char *_mcp_router_shortsep(const char *key, const int klen, const char needle, size_t *len) {
    const char *end = NULL;
    const char *lookup = NULL;

    end = memchr(key, needle, klen);
    if (end == NULL) {
        lookup = key;
    } else {
        lookup = key;
        *len = end - key;
    }

    return lookup;
}

// we take some liberties here because we know needle and key can't be zero
// this isn't the most hyper optimized search but prefixes and separators
// should both be short.
static inline const char *_mcp_router_longsep(const char *key, const int klen, const char *needle, size_t *len) {
    const char *end = NULL;
    const char *lookup = key;
    size_t nlen = strlen(needle);

    end = memchr(key, needle[0], klen);
    if (end == NULL) {
        // definitely no needle in this haystack.
        return key;
    }

    // find the last possible position
    const char *last = key + (klen - nlen);

    while (end <= last) {
        if (*end == needle[0] && memcmp(end, needle, nlen) == 0) {
            lookup = key;
            *len = end - key;
            break;
        }
        end++;
    }

    return lookup;
}

static inline const char *_mcp_router_anchorsm(const char *key, const int klen, const char *needle, size_t *len) {
    // check the first byte anchor.
    if (key[0] != needle[0]) {
        return NULL;
    }

    // rest is same as shortsep.
    return _mcp_router_shortsep(key+1, klen-1, needle[1], len);
}

static inline const char *_mcp_router_anchorbig(const char *key, const int klen, const struct mcp_router_long_s *conf, size_t *len) {
    // check long anchored prefix.
    size_t slen = strlen(conf->start);
    // check for start len+2 to avoid sending a zero byte haystack to longsep
    if (slen+2 > klen || memcmp(key, conf->start, slen) != 0) {
        return NULL;
    }

    // rest is same as longsep
    return _mcp_router_longsep(key+slen, klen-slen, conf->stop, len);
}

static inline mcp_funcgen_t *_mcp_funcgen_route_fallback(struct mcp_funcgen_router *fr, int cmd) {
    if (fr->cmap[cmd]) {
        return fr->cmap[cmd];
    }
    return fr->def_fgen;
}

static mcp_funcgen_t *mcp_funcgen_route(lua_State *L, mcp_funcgen_t *fgen, mcp_parser_t *pr) {
    struct mcp_funcgen_router *fr = (struct mcp_funcgen_router *)fgen;
    if (pr->klen == 0) {
        return NULL;
    }
    const char *key = &pr->request[pr->tokens[pr->keytoken]];
    const char *lookup = NULL;
    size_t lookuplen = 0;
    switch(fr->type) {
        case FGEN_ROUTER_NONE:
            break;
        case FGEN_ROUTER_CMDMAP:
            // short circuit if all we can do is cmap and default.
            return _mcp_funcgen_route_fallback(fr, pr->command);
            break;
        case FGEN_ROUTER_SHORTSEP:
            lookup = _mcp_router_shortsep(key, pr->klen, fr->conf.sep, &lookuplen);
            break;
        case FGEN_ROUTER_LONGSEP:
            lookup = _mcp_router_longsep(key, pr->klen, fr->conf.lsep, &lookuplen);
            break;
        case FGEN_ROUTER_ANCHORSM:
            lookup = _mcp_router_anchorsm(key, pr->klen, fr->conf.anchorsm, &lookuplen);
            break;
        case FGEN_ROUTER_ANCHORBIG:
            lookup = _mcp_router_anchorbig(key, pr->klen, &fr->conf.big, &lookuplen);
            break;
    }

    if (lookuplen == 0) {
        return _mcp_funcgen_route_fallback(fr, pr->command);
    }

    // hoping the lua short string cache helps us avoid allocations at least.
    // since this lookup code is internal to the router object we can optimize
    // this later and remove the lua bits.
    lua_rawgeti(L, LUA_REGISTRYINDEX, fr->map_ref);
    lua_pushlstring(L, lookup, lookuplen);
    lua_rawget(L, -2); // pops key, returns value
    if (lua_isnil(L, -1)) {
        lua_pop(L, 2); // drop nil and map.
        return _mcp_funcgen_route_fallback(fr, pr->command);
    } else {
        int type = lua_type(L, -1);
        if (type == LUA_TUSERDATA) {
            mcp_funcgen_t *nfgen = lua_touserdata(L, -1);
            lua_pop(L, 2); // drop fgen and map.
            return nfgen;
        } else if (type == LUA_TTABLE) {
            lua_rawgeti(L, -1, pr->command);
            // If nil, check CMD_ANY_STORAGE index for a cmap default
            if (lua_isnil(L, -1)) {
                lua_pop(L, 1); // drop nil.
                // check if we have a local-default
                lua_rawgeti(L, -1, CMD_ANY_STORAGE);
                if (lua_isnil(L, -1)) {
                    lua_pop(L, 3); // drop map, cmd map, nil
                    return _mcp_funcgen_route_fallback(fr, pr->command);
                } else {
                    mcp_funcgen_t *nfgen = lua_touserdata(L, -1);
                    lua_pop(L, 3); // drop map, cmd map, fgen
                    return nfgen;
                }
            }
            mcp_funcgen_t *nfgen = lua_touserdata(L, -1);
            lua_pop(L, 3); // drop fgen, cmd map, map
            return nfgen;
        } else {
            return _mcp_funcgen_route_fallback(fr, pr->command);
        }
    }
}

// called from mcp_funcgen_cleanup if necessary.
static int mcp_funcgen_router_cleanup(lua_State *L, mcp_funcgen_t *fgen) {
    struct mcp_funcgen_router *fr = (struct mcp_funcgen_router *)fgen;
    if (fr->map_ref) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, fr->map_ref);

        // walk the map, de-ref any funcgens found.
        int tidx = lua_absindex(L, -1);
        lua_pushnil(L);
        while (lua_next(L, tidx) != 0) {
            int type = lua_type(L, -1);
            if (type == LUA_TUSERDATA) {
                mcp_funcgen_t *mfgen = lua_touserdata(L, -1);
                mcp_funcgen_dereference(L, mfgen);
                lua_pop(L, 1);
            } else if (type == LUA_TTABLE) {
                int midx = lua_absindex(L, -1);
                lua_pushnil(L);
                while (lua_next(L, midx) != 0) {
                    mcp_funcgen_t *mfgen = lua_touserdata(L, -1);
                    mcp_funcgen_dereference(L, mfgen);
                    lua_pop(L, 1); // drop value
                }
                lua_pop(L, 1); // drop command map table
            }
        }

        lua_pop(L, 1); // drop the table.
        luaL_unref(L, LUA_REGISTRYINDEX, fr->map_ref);
        fr->map_ref = 0;
    }

    // release any command map entries.
    for (int x = 0; x < CMD_END_STORAGE; x++) {
        if (fr->cmap[x]) {
            mcp_funcgen_dereference(L, fr->cmap[x]);
            fr->cmap[x] = NULL;
        }
    }

    if (fr->def_fgen) {
        mcp_funcgen_dereference(L, fr->def_fgen);
        fr->def_fgen = NULL;
    }

    return 0;
}

// Note: the string should be safe to use after popping it here, because we
// were fetching it from a table, but I might consider copying it into a
// buffer from the caller first.
static const char *_mcplib_router_new_check(lua_State *L, const char *arg, size_t *len) {
    int type = lua_getfield(L, 1, arg);
    if (type == LUA_TSTRING) {
        const char *sep = lua_tolstring(L, -1, len);
        if (*len == 0) {
            proxy_lua_ferror(L, "must pass a non-zero length string to %s in mcp.router_new", arg);
        } else if (*len > KEY_HASH_FILTER_MAX) {
            proxy_lua_ferror(L, "%s is too long in mcp.router_new", arg);
        }
        lua_pop(L, 1); // drop key
        return sep;
    } else if (type != LUA_TNIL) {
        proxy_lua_ferror(L, "must pass a string to %s in mcp.router_new", arg);
    }
    return NULL;
}

static void _mcplib_router_new_cmapcheck(lua_State *L) {
    int tidx = lua_absindex(L, -1);
    lua_pushnil(L); // init next table key.
    while (lua_next(L, tidx) != 0) {
        if (!lua_isinteger(L, -2)) {
            proxy_lua_error(L, "Non integer key in router command map in router_new");
        }
        int cmd = lua_tointeger(L, -2);
        if ((cmd <= 0 || cmd >= CMD_END_STORAGE) && cmd != CMD_ANY_STORAGE) {
            proxy_lua_error(L, "Bad command in router command map in router_new");
        }
        luaL_checkudata(L, -1, "mcp.funcgen");
        lua_pop(L, 1); // drop val, keep key.
    }
}

static size_t _mcplib_router_new_mapcheck(lua_State *L) {
    size_t route_count = 0;
    if (!lua_istable(L, -1)) {
        proxy_lua_error(L, "Must pass a table to map argument of router_new");
    }
    // walk map table, get size count.
    lua_pushnil(L); // init table key.
    while (lua_next(L, 2) != 0) {
        int type = lua_type(L, -1);
        if (type == LUA_TUSERDATA) {
            luaL_checkudata(L, -1, "mcp.funcgen");
        } else if (type == LUA_TTABLE) {
            // If table, it's a command map, poke in and validate.
            _mcplib_router_new_cmapcheck(L);
        } else {
            proxy_lua_error(L, "unhandled data in router_new map");
        }
        route_count++;
        lua_pop(L, 1); // drop val, keep key.
    }

    return route_count;
}

// reads the configuration for the router based on the mode.
static void _mcplib_router_new_mode(lua_State *L, struct mcp_funcgen_router *fr) {
    const char *type = lua_tostring(L, -1);
    size_t len = 0;
    const char *sep = NULL;

    // change internal type based on length of separator
    if (strcmp(type, "prefix") == 0) {
        sep = _mcplib_router_new_check(L, "stop", &len);
        if (sep == NULL) {
            // defaults
            fr->type = FGEN_ROUTER_SHORTSEP;
            fr->conf.sep = '/';
        } else if (len == 1) {
            // optimized shortsep case.
            fr->type = FGEN_ROUTER_SHORTSEP;
            fr->conf.sep = sep[0];
        } else {
            // len is long.
            fr->type = FGEN_ROUTER_LONGSEP;
            memcpy(fr->conf.lsep, sep, len);
            fr->conf.lsep[len] = '\0'; // cap it.
        }
    } else if (strcmp(type, "anchor") == 0) {
        size_t elen = 0; // stop len.
        const char *usep = _mcplib_router_new_check(L, "stop", &elen);
        sep = _mcplib_router_new_check(L, "start", &len);
        if (sep == NULL && usep == NULL) {
            // no arguments, use a default.
            fr->type = FGEN_ROUTER_ANCHORSM;
            fr->conf.anchorsm[0] = '/';
            fr->conf.anchorsm[1] = '/';
        } else if (sep == NULL || usep == NULL) {
            // reduce the combinatorial space because I'm lazy.
            proxy_lua_error(L, "must specify start and stop if mode is anchor in mcp.router_new");
        } else if (len == 1 && elen == 1) {
            fr->type = FGEN_ROUTER_ANCHORSM;
            fr->conf.anchorsm[0] = sep[0];
            fr->conf.anchorsm[1] = usep[0];
        } else {
            fr->type = FGEN_ROUTER_ANCHORBIG;
            memcpy(fr->conf.big.start, sep, len);
            memcpy(fr->conf.big.stop, usep, elen);
            fr->conf.big.start[len] = '\0';
            fr->conf.big.stop[elen] = '\0';
        }
    } else {
        proxy_lua_error(L, "unknown type passed to mcp.router_new");
    }
}

// FIXME: error if map or cmap not passed in?
int mcplib_router_new(lua_State *L) {
    struct mcp_funcgen_router fr = {0};
    size_t route_count = 0;
    bool has_map = false;

    if (!lua_istable(L, 1)) {
        proxy_lua_error(L, "Must pass a table of arguments to mcp.router_new");
    }

    if (lua_getfield(L, 1, "map") != LUA_TNIL) {
        route_count = _mcplib_router_new_mapcheck(L);
        has_map = true;
    }
    lua_pop(L, 1); // drop map or nil

    if (lua_getfield(L, 1, "cmap") != LUA_TNIL) {
        if (!lua_istable(L, -1)) {
            proxy_lua_error(L, "Must pass a table to cmap argument of mcp.router_new");
        }
        _mcplib_router_new_cmapcheck(L);
    } else {
        if (!has_map) {
            proxy_lua_error(L, "Must pass map and/or cmap to mcp.router_new");
        }
    }
    lua_pop(L, 1);

    fr.fgen_self.is_router = true;

    // config:
    // { mode = "anchor", start = "/", stop = "/" }
    // { mode = "prefix", stop = "/" }
    if (has_map) {
        // default to a short prefix type with a single byte separator.
        fr.type = FGEN_ROUTER_SHORTSEP;
        fr.conf.sep = '/';

        if (lua_getfield(L, 1, "mode") == LUA_TSTRING) {
            _mcplib_router_new_mode(L, &fr);
        }
        lua_pop(L, 1); // drop mode or nil.
    } else {
        // pure command map router.
        fr.type = FGEN_ROUTER_CMDMAP;
    }

    struct mcp_funcgen_router *router = lua_newuserdatauv(L, sizeof(struct mcp_funcgen_router), 0);
    memset(router, 0, sizeof(*router));
    mcp_funcgen_t *fgen = &router->fgen_self;

    luaL_getmetatable(L, "mcp.funcgen");
    lua_setmetatable(L, -2);

    int type = lua_getfield(L, 1, "default");
    if (type == LUA_TUSERDATA) {
        fr.def_fgen = luaL_checkudata(L, -1, "mcp.funcgen");
        mcp_funcgen_reference(L); // pops the funcgen.
    } else {
        lua_pop(L, 1);
    }

    memcpy(router, &fr, sizeof(struct mcp_funcgen_router));
    strncpy(fgen->name, "mcp_router", FGEN_NAME_MAXLEN);

    if (has_map) {
        // walk map table again, funcgen_ref everyone.
        lua_createtable(L, 0, route_count);
        lua_pushvalue(L, -1); // dupe table ref for a moment.
        router->map_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops extra map

        int mymap = lua_absindex(L, -1);
        lua_getfield(L, 1, "map");
        int argmap = lua_absindex(L, -1);
        lua_pushnil(L); // seed walk of the passed in map

        while (lua_next(L, argmap) != 0) {
            // types are already validated.
            int type = lua_type(L, -1);
            if (type == LUA_TUSERDATA) {
                // first lets reference the function generator.
                lua_pushvalue(L, -1); // duplicate value.
                mcp_funcgen_reference(L); // pops the funcgen after referencing.

                // duplicate key.
                lua_pushvalue(L, -2);
                // move key underneath value
                lua_insert(L, -2); // take top (key) and move it down one.
                // now key, key, value
                lua_rawset(L, mymap); // pops k, v into our internal table.
            } else if (type == LUA_TTABLE) {
                int tidx = lua_absindex(L, -1); // idx of our command map table.
                lua_createtable(L, CMD_END_STORAGE, 0);
                int midx = lua_absindex(L, -1); // idx of our new command map.
                lua_pushnil(L); // seed the iterator
                while (lua_next(L, tidx) != 0) {
                    lua_pushvalue(L, -1); // duplicate value.
                    mcp_funcgen_reference(L); // pop funcgen.

                    lua_pushvalue(L, -2); // dupe key.
                    lua_insert(L, -2); // move key down one.
                    lua_rawset(L, midx); // set to new map table.
                }

                // -1: new command map
                // -2: input command map
                // -3: key
                lua_pushvalue(L, -3); // dupe key
                lua_insert(L, -2); // move key down below new cmd map
                lua_rawset(L, mymap); // pop key, new map into main map.
                lua_pop(L, 1); // drop input table.
            }
        }

        lua_pop(L, 2); // drop argmap, mymap.
    }

    // process a command map directly into our internal table.
    if (lua_getfield(L, 1, "cmap") != LUA_TNIL) {
        int tidx = lua_absindex(L, -1); // idx of our command map table.
        lua_pushnil(L); // seed the iterator
        while (lua_next(L, tidx) != 0) {
            int cmd = lua_tointeger(L, -2);
            mcp_funcgen_t *cfgen = lua_touserdata(L, -1);
            mcp_funcgen_reference(L); // pop funcgen.
            router->cmap[cmd] = cfgen;
        }
    }
    lua_pop(L, 1);

    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    fgen->thread = t;
    mcp_sharedvm_delta(t->proxy_ctx, SHAREDVM_FGEN_IDX, "mcp_router", 1);

    return 1;
}

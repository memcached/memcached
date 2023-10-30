/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

static void mcp_funcgen_cleanup(lua_State *L, mcp_funcgen_t *fgen);
static void proxy_return_rqu_cb(io_pending_t *pending);

// If we're GC'ed but not closed, it means it was created but never
// attached to a function, so ensure everything is closed properly.
int mcplib_funcgen_gc(lua_State *L) {
    mcp_funcgen_t *fgen = luaL_checkudata(L, -1, "mcp.funcgen");
    if (fgen->closed) {
        return 0;
    }
    assert(fgen->self_ref == 0);

    mcp_funcgen_cleanup(L, fgen);
    return 0;
}

// For describing functions which generate functions which can execute
// requests.
// These "generator functions" handle pre-allocating and creating a memory
// heirarchy, allowing dynamic runtimes at high speed.

// TODO: switch from an array to a STAILQ so we can avoid the memory
// management and error handling.
// Realistically it's impossible for these to error so we're safe for now.
static void _mcplib_funcgen_cache(mcp_funcgen_t *fgen, mcp_rcontext_t *rctx) {
    if (fgen->free + 1 >= fgen->free_max) {
        fgen->free_max *= 2;
        fgen->list = realloc(fgen->list, fgen->free_max * sizeof(mcp_rcontext_t *));
    }
    fgen->list[fgen->free] = rctx;
    fgen->free++;

    // we're closed and every outstanding request slot has been
    // returned.
    if (fgen->closed && fgen->free == fgen->total) {
        mcp_funcgen_cleanup(fgen->thread->L, fgen);
    }
}

// call with stack: mcp.funcgen -2, function -1
static mcp_rcontext_t *_mcplib_funcgen_gencall(lua_State *L, mcp_funcgen_t *fgen) {
    // create the ctx object.
    size_t rctx_len = sizeof(mcp_rcontext_t) + sizeof(struct mcp_rqueue_s) * fgen->max_queues;
    mcp_rcontext_t *rc = lua_newuserdatauv(L, rctx_len, 0);
    memset(rc, 0, rctx_len);

    luaL_getmetatable(L, "mcp.rcontext");
    lua_setmetatable(L, -2);

    // link the rcontext into the function generator.
    // FIXME: triple check this actually cleans up if we bail.
    // TODO: copy the func then the rcontext again and do this after the pcall
    // to avoid having to unwind it post-failure.
    rc->fgen = fgen;
    fgen->total++;

    lua_getiuservalue(L, -3, 1); // get the reference table.
    lua_pushvalue(L, -2); // copy rcontext
    lua_rawseti(L, -2, fgen->total); // pop rcontext
    lua_pop(L, 1); // pop ref table.

    // FIXME: move this to the end, so we only cache on success.
    _mcplib_funcgen_cache(fgen, rc);

    // pre-create a top level request object.
    mcp_request_t *rq = lua_newuserdatauv(L, sizeof(mcp_request_t) + MCP_REQUEST_MAXLEN + KEY_MAX_LENGTH, 0);
    memset(rq, 0, sizeof(mcp_request_t));
    luaL_getmetatable(L, "mcp.request");
    lua_setmetatable(L, -2);

    rc->request_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pop the request
    rc->request = rq;

    // current stack should be func, mcp.rcontext.
    int call_argnum = 1;
    // stack will be func, rctx, arg if there is an arg.
    if (fgen->argument_ref) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->argument_ref);
        call_argnum++;
    }

    // TODO: lua_call instead of pcall?
    int res = lua_pcall(L, call_argnum, 1, 0);
    if (res != LUA_OK) {
        // TODO: give this a proxy_lua_error.
        lua_error(L);
        return 0;
    }

    // we should have a top level function as a result.
    if (!lua_isfunction(L, -1)) {
        proxy_lua_error(L, "function generator didn't return a function");
        return 0;
    }

    // TODO: copy the function, return "rcontext, rfunction"
    // so it can be immediately executed?
    // pop the returned function.
    rc->function_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // associate a coroutine thread with this context.
    lua_newthread(L);
    rc->Lc = lua_tothread(L, -1);
    rc->coroutine_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // increment the slot counter
    if (fgen->name_ref) {
        LIBEVENT_THREAD *t = PROXY_GET_THR(L);
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->name_ref);
        const char *name = lua_tostring(L, -1);
        mcp_sharedvm_delta(t->proxy_ctx, SHAREDVM_FGENSLOT_IDX, name, 1);
        lua_pop(L, 1);
    }

    // return the rcontext
    return rc;
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
        lua_newthread(L);
        rctx->Lc = lua_tothread(L, -1);
        rctx->coroutine_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_settop(rctx->Lc, 0);
    }
    // TODO: only do resetthread if an error was previously returned?
    rctx->resp = NULL;
    rctx->first_queue = false; // HACK
    mcp_request_cleanup(fgen->thread, rctx->request);

    // reset each rqu.
    // TODO: keep the res obj but reset it internally.
    for (int x = 0; x < fgen->max_queues; x++) {
        struct mcp_rqueue_s *rqu = &rctx->qslots[x];
        if (rqu->res_ref) {
            luaL_unref(rctx->Lc, LUA_REGISTRYINDEX, rqu->res_ref);
        }
        assert(rqu->state != RQUEUE_ACTIVE);
        rqu->state = RQUEUE_IDLE;
        rqu->res_ref = 0;
        rqu->flags = 0;
        rqu->rq = NULL;
        if (rqu->obj_type == RQUEUE_TYPE_FGEN) {
            _mcp_funcgen_return_rctx(rqu->obj);
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
    _mcp_funcgen_return_rctx(rctx);
    _mcplib_funcgen_cache(fgen, rctx);
}

// FIXME: should be able to avoid the fgen ref, because we only need the fgen lua
// object if there were no empty slots.
// FIXME: mcplib -> mcp?
mcp_rcontext_t *mcplib_funcgen_get_rctx(lua_State *L, int fgen_ref, mcp_funcgen_t *fgen) {
    mcp_rcontext_t *rctx = NULL;
    // nothing left in slot cache, generate a new function.
    if (fgen->free == 0) {
        // pull in the funcgen object
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen_ref);
        // then generator function
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->generator_ref);
        // then generate a new function slot.
        // FIXME: do a lua_pcall here so the arguments make sense?
        _mcplib_funcgen_gencall(L, fgen);
        lua_pop(L, 1); // drop the extra funcgen ref
    } else {
        P_DEBUG("%s: serving from cache\n", __func__);
    }

    rctx = fgen->list[fgen->free-1];
    fgen->free--;

    // on non-error, return the response object upward.
    return rctx;
}

// calling either with self_ref set, or with fgen in stack -1 (ie; from GC
// function without ever being attached to anything)
static void mcp_funcgen_cleanup(lua_State *L, mcp_funcgen_t *fgen) {
    assert(fgen->closed);
    // pull the fgen into the stack.
    if (fgen->self_ref) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->self_ref);
        // remove the C reference to the fgen
        luaL_unref(L, LUA_REGISTRYINDEX, fgen->self_ref);
        fgen->self_ref = 0;
    }

    // Walk every requets context and issue cleanup.
    for (int x = 0; x < fgen->total; x++) {
        mcp_rcontext_t *rctx = fgen->list[x];

        luaL_unref(L, LUA_REGISTRYINDEX, rctx->coroutine_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, rctx->function_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, rctx->request_ref);
        // TODO: cleanup of request queue entries. recurse funcgen cleanup.
    }

    // Finally, get the rctx reference table and nil each reference to allow
    // garbage collection to happen sooner on the rctx's
    lua_getiuservalue(L, -1, 1);
    for (int x = 0; x < fgen->total; x++) {
        lua_pushnil(L);
        lua_rawseti(L, -2, x+1);
    }
    // drop the reference table and the funcgen reference.
    lua_pop(L, 2);
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

    // Pass our fakeish generator function down the line.
    return mcplib_funcgen_new(L);
}

// TODO: find a better name for this function. _after_ its final placement.
int mcplib_funcgen_new(lua_State *L) {
    LIBEVENT_THREAD *t = PROXY_GET_THR(L);
    int max_queues = 1; // FIXME: define.
    int tidx = 0;

    if (lua_istable(L, -1)) {
        tidx = lua_absindex(L, -1);
        if (lua_getfield(L, -1, "max_queues") != LUA_TNIL) {
            max_queues = lua_tointeger(L, -1);
        }
        lua_pop(L, 1);

        if (lua_getfield(L, -1, "func") != LUA_TFUNCTION) {
            proxy_lua_error(L, "Must specify generator function ('func') in mcp.funcgen_new");
            return 0;
        }

        // now the generator function is at the top of the stack.
    } else if (!lua_isfunction(L, -1)) {
        proxy_lua_error(L, "Must pass a function or table to mcp.funcgen_new");
        return 0;
    }

    mcp_funcgen_t *fgen = lua_newuserdatauv(L, sizeof(mcp_funcgen_t), 1);
    memset(fgen, 0, sizeof(mcp_funcgen_t));
    fgen->thread = t;
    fgen->max_queues = max_queues;
    fgen->free_max = 8; // FIXME: define
    fgen->list = calloc(fgen->free_max, sizeof(mcp_rcontext_t *));

    luaL_getmetatable(L, "mcp.funcgen");
    lua_setmetatable(L, -2);

    // the table we will use to hold references to rctx's
    lua_createtable(L, 8, 0);
    // set our table into the uservalue 1 of fgen (idx -2)
    // pops the table.
    lua_setiuservalue(L, -2, 1);

    if (tidx) {
        // check for a generator argument.
        if (lua_getfield(L, tidx, "arg") != LUA_TNIL) {
            fgen->argument_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        } else {
            lua_pop(L, 1);
        }

        if (lua_getfield(L, tidx, "name") == LUA_TSTRING) {
            fgen->name_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        } else {
            lua_pop(L, 1);
        }
    }

    // stack should now be: -2: func -1: mcp.funcgen

    // copy the generator function.
    lua_pushvalue(L, -2);
    // run the generator function once, which caches a new function call
    // object.
    _mcplib_funcgen_gencall(L, fgen);

    // we've survived one call to the function generator, so lets reference it
    // now.
    lua_pushvalue(L, -2); // copy the generator again
    fgen->generator_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // top of stack is now: gfunc, fgen

    // add us to the global state
    if (fgen->name_ref) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, fgen->name_ref);
        const char *name = lua_tostring(L, -1);
        mcp_sharedvm_delta(t->proxy_ctx, SHAREDVM_FGEN_IDX, name, 1);
        lua_pop(L, 1);
    }

    // return the generator for attach() later.
    return 1;
}

// Handlers for request contexts

// first arg is rcontext
// next is either a pool proxy or another function generator
// TODO LATER: create a static result object
int mcplib_rcontext_queue_assign(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    mcp_pool_proxy_t *pp = NULL;
    mcp_funcgen_t *fgen = NULL;
    // FIXME: ensure only two or three arguments, else the references break.
    int argc = lua_gettop(L);

    // find the next unused queue slot.
    struct mcp_rqueue_s *rqu = NULL;
    int x;
    for (x = 0; x < rctx->fgen->max_queues; x++) {
        if (rctx->qslots[x].obj_type == RQUEUE_TYPE_NONE) {
            rqu = &rctx->qslots[x];
            break;
        }
    }
    if (!rqu) {
        proxy_lua_error(L, "ran out of queue slots during queue_assign()");
        return 0;
    }

    if (argc == 3) {
        if (!lua_isfunction(L, 3)) {
            proxy_lua_error(L, "second argument to queue_assign must be a callback function");
        }

        // pops top argument.
        rqu->cb_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    if ((pp = luaL_testudata(L, 2, "mcp.pool_proxy")) != NULL) {
        // pops *pp from the stack.
        rqu->obj_ref = luaL_ref(L, LUA_REGISTRYINDEX);
        rqu->obj_type = RQUEUE_TYPE_POOL;
        rqu->obj = pp;
        // TODO: ref incr on the pool proxy.
    } else if ((fgen = luaL_testudata(L, 2, "mcp.funcgen")) != NULL) {
        // pops the fgen from the stack.
        mcp_funcgen_reference(L);
        // now run the generator once to get an rctx to peg into this slot.
        // FIXME: fix this self_ref business.
        // this is okay temporarily since the above reference ensures fgen's
        // self ref is set.
        mcp_rcontext_t *subrctx = mcplib_funcgen_get_rctx(L, fgen->self_ref, fgen);
        // link the new rctx into this chain; we'll hold onto it until the
        // parent de-allocates.
        subrctx->parent = rctx;
        subrctx->parent_handle = x;
        rqu->obj_type = RQUEUE_TYPE_FGEN;
        rqu->obj = subrctx;
    } else {
        // unwind and throw error
        if (rqu->cb_ref) {
            luaL_unref(L, LUA_REGISTRYINDEX, rqu->cb_ref);
            rqu->cb_ref = 0;
        }
        proxy_lua_error(L, "invalid argument to queue_assign");
        return 0;
    }

    // return the "handle" of the queue slot.
    lua_pushinteger(L, x);
    return 1;
}

static void _mcplib_rcontext_queue(lua_State *L, mcp_rcontext_t *rctx, mcp_request_t *rq, int handle) {
    if (handle < 0 || handle > rctx->fgen->max_queues) {
        proxy_lua_error(L, "invalid handle passed to queue");
        return;
    }
    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];

    if (rqu->state != RQUEUE_IDLE) {
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

    rqu->state = RQUEUE_QUEUED;
    rqu->rq = rq;
}

// first arg is rcontext
// then a request object
// then either a handle (integer) or array style table of handles
// TODO: block queueing if the rctx is currently waiting
// TODO: if passing to an fgen:
// - prep the function reference into its coroutine
// - lua_xmove the request object into place
// - but don't execute it yet.
int mcplib_rcontext_queue(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    mcp_request_t *rq = luaL_checkudata(L, 2, "mcp.request");

    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot queue requests without a key");
        return 0;
    }

    int type = lua_type(L, 3);
    if (type == LUA_TNUMBER) {
        int handle = lua_tointeger(L, 3);

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
    rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);

    // queue an IO to return later.
    io_pending_proxy_t *p = mcp_queue_rctx_io(rctx->parent, NULL, NULL, r);
    p->return_cb = proxy_return_rqu_cb;
    p->queue_handle = rctx->parent_handle;
    p->await_background = true;
}

static void mcp_start_subrctx(mcp_rcontext_t *rctx) {
    int res = proxy_run_rcontext(rctx);
    struct mcp_rqueue_s *rqu = &rctx->parent->qslots[rctx->parent_handle];
    if (res == LUA_OK) {
        int type = lua_type(rctx->Lc, 1);
        if (type == LUA_TUSERDATA) {
            // move stack result object into parent rctx rqu slot.
            // FIXME: crashes. use testudata and internal error handling.
            mcp_resp_t *r = luaL_checkudata(rctx->Lc, 1, "mcp.response");
            rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);

            io_pending_proxy_t *p = mcp_queue_rctx_io(rctx->parent, NULL, NULL, r);
            p->return_cb = proxy_return_rqu_cb;
            p->queue_handle = rctx->parent_handle;
            p->await_background = true; // FIXME: change name of property to
                                        // fast-return.
        } else if (type == LUA_TSTRING) {
            // TODO: wrap with a resobj and parse it.
            // for now we bypass the rqueue process handling
            // meaning no callbacks/etc.
            rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
            rqu->flags |= RQUEUE_R_ANY;
            rqu->state = RQUEUE_COMPLETE;
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
            int type = lua_type(rctx->Lc, 1);
            if (type == LUA_TUSERDATA) {
                // move stack result object into parent rctx rqu slot.
                // FIXME: crashes. use testudata and internal error handling.
                mcp_resp_t *r = luaL_checkudata(rctx->Lc, 1, "mcp.response");
                rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
                mcp_process_rqueue_return(rctx->parent, rctx->parent_handle, r);
            } else if (type == LUA_TSTRING) {
                // TODO: wrap with a resobj and parse it.
                // for now we bypass the rqueue process handling
                // meaning no callbacks/etc.
                rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
                rqu->flags |= RQUEUE_R_ANY;
                rqu->state = RQUEUE_COMPLETE;
            } else {
                // generate a generic object with an error.
                _mcp_resume_rctx_process_error(rctx, rqu);
            }
            if (rctx->parent->wait_count) {
                mcp_process_rctx_wait(rctx->parent, rctx->parent_handle);
            }
            mcp_funcgen_return_rctx(rctx);
        } else if (res == LUA_YIELD) {
            // normal.
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
        // FIXME: this may be incomplete, as mcp.internal() can make
        // IO_QUEUE_EXTSTORE requests; need to audit the callbacks for that.
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
        }
    }
}

// This "Dummy" IO immediately resumes the yielded function, without a result
// attached.
static void proxy_return_rqu_dummy_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;
    mcp_rcontext_t *rctx = p->rctx;
    conn *c = rctx->c;

    rctx->pending_reqs--;
    assert(rctx->pending_reqs > -1);

    lua_settop(rctx->Lc, 0);
    lua_pushinteger(rctx->Lc, 0); // return a "0" done count to the function.
    mcp_resume_rctx_from_cb(rctx);

    do_cache_free(p->thread->io_cache, p);
    // We always need a C object right now, but just in case.
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

void mcp_process_rctx_wait(mcp_rcontext_t *rctx, int handle) {
    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    int status = rqu->flags;
    assert(rqu->state == RQUEUE_COMPLETE);
    // waiting for some IO's to complete before continuing.
    // meaning if we "match good" here, we can resume.
    // we can also resume if we are in wait mode but pending_reqs is down
    // to 1.
    switch (rctx->wait_mode) {
        case WAIT_GOOD:
            if (status & RQUEUE_R_GOOD) {
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
            }
            break;
        case WAIT_OK:
            if (status & (RQUEUE_R_GOOD|RQUEUE_R_OK)) {
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
            }
            break;
        case WAIT_ANY:
            rctx->wait_done++;
            rqu->state = RQUEUE_WAITED;
            break;
        case WAIT_HANDLE:
            // waiting for a specific handle to return
            if (handle == rctx->wait_handle) {
                rctx->wait_done++;
                rqu->state = RQUEUE_WAITED;
            }
            break;
    }

    assert(rctx->pending_reqs != 0);
    // FIXME: need to only check R_RESUME if NOT WAIT_HANDLE?
    if ((status & RQUEUE_R_RESUME) || rctx->wait_done == rctx->wait_count || rctx->pending_reqs == 1) {
        // ran out of stuff to wait for. time to resume.
        // TODO: can we do the settop at the yield? nothing we need to
        // keep in the stack in this mode.
        lua_settop(rctx->Lc, 0);
        rctx->wait_count = 0;
        if (rctx->wait_mode == WAIT_HANDLE) {
            mcp_rcontext_push_rqu_res(rctx->Lc, rctx, handle);
        } else {
            lua_pushinteger(rctx->Lc, rctx->wait_done);
        }
        rctx->wait_mode = WAIT_ANY;

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
    if (!rqu->cb_ref) {
        if (res->status == MCMC_OK) {
            if (res->resp.code != MCMC_CODE_END) {
                flag = RQUEUE_R_GOOD;
            } else {
                flag = RQUEUE_R_OK;
            }
        }
        rqu->flags |= flag;
        return flag;
    } else {
        lua_settop(rctx->Lc, 0);
        lua_rawgeti(rctx->Lc, LUA_REGISTRYINDEX, rqu->cb_ref);
        lua_rawgeti(rctx->Lc, LUA_REGISTRYINDEX, rqu->res_ref);
        if (lua_pcall(rctx->Lc, 1, 2, 0) != LUA_OK) {
            LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_ERROR, NULL, lua_tostring(rctx->Lc, -1));
            flag = RQUEUE_R_ANY;
        } else {
            enum mcp_rqueue_e mode = lua_tointeger(rctx->Lc, 1);
            switch (mode) {
                case WAIT_GOOD:
                    flag = RQUEUE_R_GOOD;
                    break;
                case WAIT_OK:
                    flag = RQUEUE_R_OK;
                    break;
                case WAIT_ANY:
                    break;
                default:
                    fprintf(stderr, "BAD RESULT!!!\n");
                    // FIXME:
                    break;
            }

            // if second result return shortcut status code
            if (lua_toboolean(rctx->Lc, 2)) {
                flag |= RQUEUE_R_RESUME;
            }
        }
        rqu->flags |= flag;
        lua_settop(rctx->Lc, 0); // FIXME: This might not be necessary.
                                 // we settop _before_ calling cb's and
                                 // _before_ setting up for a coro resume.
        return rqu->flags;
    }
}

// specific function for queue-based returns.
static void proxy_return_rqu_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;
    mcp_rcontext_t *rctx = p->rctx;
    // Hold the client object before we potentially return the rctx below.
    conn *c = rctx->c;

    mcp_process_rqueue_return(rctx, p->queue_handle, p->client_resp);
    rctx->pending_reqs--;
    assert(rctx->pending_reqs > -1);

    if (rctx->wait_count) {
        mcp_process_rctx_wait(rctx, p->queue_handle);
    } else {
        mcp_funcgen_return_rctx(rctx);
    }

    do_cache_free(p->thread->io_cache, p);

    // We always need a C object right now, but just in case.
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
            mcp_resp_t *r = mcp_prep_resobj(rctx->Lc, rq, be, rctx->fgen->thread);
            // FIXME: check for NULL on the IO object and handle.
            io_pending_proxy_t *p = mcp_queue_rctx_io(rctx, rq, be, r);
            p->return_cb = proxy_return_rqu_cb;
            p->queue_handle = handle;
            // need to reference the res object into the queue slot.
            rqu->res_ref = luaL_ref(rctx->Lc, LUA_REGISTRYINDEX);
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

// TODO: one more function to wait on a list of handles? to queue and wait on
// a list of handles? expand wait_for()

// takes num, filter mode
// TODO: if count is zero, queue dummy IO to force submission.
int mcplib_rcontext_wait_for(lua_State *L) {
    // TODO: protect against double waitfor?
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    int mode = WAIT_ANY;
    int wait = 0;

    if (!lua_isnumber(L, 2)) {
        proxy_lua_error(L, "must pass number to wait_for");
        return 0;
    } else {
        wait = lua_tointeger(L, 2);
        if (wait < 0) {
            proxy_lua_error(L, "wait count for wait_for must be positive");
            return 0;
        }
        rctx->wait_count = wait;
    }

    if (lua_isnumber(L, 3)) {
        mode = lua_tointeger(L, 3);
    }

    switch (mode) {
        case WAIT_ANY:
        case WAIT_OK:
        case WAIT_GOOD:
            break;
        default:
            proxy_lua_error(L, "invalid mode sent to wait_for");
            return 0;
    }
    rctx->wait_done = 0;
    rctx->wait_mode = mode;

    // waiting for none, meaning just execute the queues.
    if (wait == 0) {
        // FIXME: error handling for p == NULL
        io_pending_proxy_t *p = mcp_queue_rctx_io(rctx, NULL, NULL, NULL);
        p->return_cb = proxy_return_rqu_dummy_cb;
        p->await_background = true;
        rctx->pending_reqs++;
    }

    lua_pushinteger(L, MCP_YIELD_WAITFOR);
    return lua_yield(L, 1);
}

int mcplib_rcontext_wait_handle(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    mcp_request_t *rq = luaL_checkudata(L, 2, "mcp.request");
    int isnum = 0;
    int handle = lua_tointegerx(L, 3, &isnum);

    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot queue requests without a key");
        return 0;
    }

    if (!isnum) {
        proxy_lua_error(L, "invalid handle passed to wait_handle");
        return 0;
    }

    // queue up this handle and yield for the direct wait.
    _mcplib_rcontext_queue(L, rctx, rq, handle);
    rctx->wait_done = 0;
    rctx->wait_count = 1;
    rctx->wait_mode = WAIT_HANDLE;
    rctx->wait_handle = handle;

    lua_pushinteger(L, MCP_YIELD_WAITHANDLE);
    return lua_yield(L, 1);
}

static inline struct mcp_rqueue_s *_mcplib_rcontext_checkhandle(lua_State *L) {
    mcp_rcontext_t *rctx = lua_touserdata(L, 1);
    int isnum = 0;
    int handle = lua_tointegerx(L, 2, &isnum);
    if (!isnum || handle < 0 || handle > rctx->fgen->max_queues) {
        proxy_lua_error(L, "invalid queue handle passed to :good/:ok:/:any");
        return NULL;
    }

    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    return rqu;
}

int mcplib_rcontext_good(lua_State *L) {
    struct mcp_rqueue_s *rqu = _mcplib_rcontext_checkhandle(L);
    if (rqu->flags & RQUEUE_R_GOOD) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int mcplib_rcontext_ok(lua_State *L) {
    struct mcp_rqueue_s *rqu = _mcplib_rcontext_checkhandle(L);
    if (rqu->flags & (RQUEUE_R_OK|RQUEUE_R_GOOD)) {
        lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
    } else {
        lua_pushnil(L);
    }
    return 1;
}

int mcplib_rcontext_any(lua_State *L) {
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

// the supplied handle must be valid.
void mcp_rcontext_push_rqu_res(lua_State *L, mcp_rcontext_t *rctx, int handle) {
    struct mcp_rqueue_s *rqu = &rctx->qslots[handle];
    lua_rawgeti(L, LUA_REGISTRYINDEX, rqu->res_ref);
}

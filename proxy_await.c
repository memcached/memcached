/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "proxy.h"

typedef struct mcp_await_s {
    int pending;
    int wait_for;
    int req_ref;
    int argtable_ref; // need to hold refs to any potential hash selectors
    int restable_ref; // table of result objects
    int detail_ref; // reference to detail string.
    enum mcp_await_e type;
    bool completed; // have we completed the parent coroutine or not
    bool logerr; // create log_req entries for error responses
    mcp_request_t *rq;
    mc_resp *resp; // the top level mc_resp to fill in (as if we were an iop)
    mcp_rcontext_t *rctx; // request context
} mcp_await_t;

// TODO (v2): mcplib_await_gc()
// - needs to handle cases where an await is created, but a rare error happens
// before it completes and the coroutine is killed. must check and free its
// references.

// local restable = mcp.await(request, pools, num_wait)
// NOTE: need to hold onto the pool objects since those hold backend
// references. Here we just keep a reference to the argument table.
static int _mcplib_await(lua_State *L, bool logerr) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    luaL_checktype(L, 2, LUA_TTABLE);
    int n = 0; // length of table of pools
    int wait_for = 0; // 0 means wait for all responses
    enum mcp_await_e type = AWAIT_GOOD;
    int detail_ref = 0;

    lua_pushnil(L); // init table key
    while (lua_next(L, 2) != 0) {
        luaL_checkudata(L, -1, "mcp.pool_proxy");
        lua_pop(L, 1); // remove value, keep key.
        n++;
    }

    if (n <= 0) {
        proxy_lua_error(L, "mcp.await arguments must have at least one pool");
    }

    if (lua_isstring(L, 5)) {
        // pops the detail string.
        detail_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    }

    if (lua_isnumber(L, 4)) {
        type = lua_tointeger(L, 4);
        lua_pop(L, 1);
        switch (type) {
            case AWAIT_GOOD:
            case AWAIT_ANY:
            case AWAIT_OK:
            case AWAIT_FIRST:
            case AWAIT_FASTGOOD:
            case AWAIT_BACKGROUND:
                break;
            default:
                proxy_lua_error(L, "invalid type argument tp mcp.await");
        }
    }

    if (lua_isnumber(L, 3)) {
        wait_for = lua_tointeger(L, 3);
        lua_pop(L, 1);
        if (wait_for > n) {
            wait_for = n;
        }
    }

    // FIRST is only looking for one valid request.
    if (type == AWAIT_FIRST) {
        wait_for = 1;
    }

    // TODO (v2): quickly loop table once and ensure they're all pools?
    // TODO (v2) in case of newuserdatauv throwing an error, we need to grab
    // these references after allocating *aw else can leak memory.
    int argtable_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops the arg table
    int req_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops request object.

    // stack will be only the await object now
    // allocate before grabbing references so an error won't cause leaks.
    mcp_await_t *aw = lua_newuserdatauv(L, sizeof(mcp_await_t), 0);
    memset(aw, 0, sizeof(mcp_await_t));

    // create result table
    lua_newtable(L); // -> 2
    aw->restable_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pop the result table

    aw->wait_for = wait_for;
    aw->pending = n;
    aw->argtable_ref = argtable_ref;
    aw->rq = rq;
    aw->req_ref = req_ref;
    aw->detail_ref = detail_ref;
    aw->type = type;
    aw->logerr = logerr;
    P_DEBUG("%s: about to yield [len: %d]\n", __func__, n);

    lua_pushinteger(L, MCP_YIELD_AWAIT);
    return lua_yield(L, 2);
}

// default await, no logging.
int mcplib_await(lua_State *L) {
    return _mcplib_await(L, false);
}

int mcplib_await_logerrors(lua_State *L) {
    return _mcplib_await(L, true);
}

// TODO (v2): need to get this code running under pcall().
// It looks like a bulk of this code can move into mcplib_await(),
// and then here post-yield we can add the rcontext to the right
// places. Else these errors currently crash the daemon.
int mcplib_await_run_rctx(mcp_rcontext_t *rctx) {
    P_DEBUG("%s: start\n", __func__);
    conn *c = rctx->c;
    lua_State *L = rctx->Lc;
    WSTAT_INCR(c->thread, proxy_await_active, 1);
    mcp_await_t *aw = lua_touserdata(L, -1);
    assert(aw != NULL);
    int await_ref = luaL_ref(L, LUA_REGISTRYINDEX); // await is popped.
    lua_rawgeti(L, LUA_REGISTRYINDEX, aw->argtable_ref); // -> 1
    mcp_request_t *rq = aw->rq;
    aw->rctx = rctx;

    // prepare the request key
    const char *key = MCP_PARSER_KEY(rq->pr);
    size_t len = rq->pr.klen;
    // TODO (v3) await_first is used as a marker for upping the "wait for
    // IO's" queue count, which means we need to force it off if we're in
    // background mode, else we would accidentally wait for a response anyway.
    // This note is for finding a less convoluted method for this.
    bool await_first = (aw->type == AWAIT_BACKGROUND) ? false : true;
    // loop arg table and run each pool backend selector
    lua_pushnil(L); // -> 3
    while (lua_next(L, 1) != 0) {
        P_DEBUG("%s: top of loop\n", __func__);
        // (key, -2), (val, -1)
        // skip the metatable checking here as we already check this in
        // mcp.await()'s top level call.
        mcp_pool_proxy_t *pp = lua_touserdata(L, -1);
        if (pp == NULL) {
            proxy_lua_error(L, "mcp.await must be supplied with a pool");
        }

        // NOTE: rq->be is only held to help pass the backend into the IOP in
        // mcp_queue call. Could be a local variable and an argument too.
        mcp_backend_t *be = mcplib_pool_proxy_call_helper(pp, key, len);
        if (be == NULL) {
            proxy_lua_error(L, "key dist hasher tried to use out of bounds index");
        }

        mcp_resp_t *res = mcp_prep_resobj(L, rq, be, rctx->c->thread);
        io_pending_proxy_t *p = mcp_queue_rctx_io(rctx, rq, be, res);
        if (p == NULL) {
            // TODO: need to unroll this. _gc func?
        }
        rctx->async_pending++;
        p->is_await = true;
        p->await_ref = await_ref;
        p->await_first = await_first;
        // io_p needs to hold onto its own response reference, because we may or
        // may not include it in the final await() result.
        p->mcpres_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops mcp.response

        await_first = false;

        // pop value, keep key.
        lua_pop(L, 1);
    }

    if (aw->type == AWAIT_BACKGROUND) {
        io_pending_proxy_t *p = mcp_queue_rctx_io(rctx, NULL, NULL, NULL);
        p->is_await = true;
        p->await_ref = await_ref;
        p->await_background = true;

        rctx->async_pending++;
        aw->pending++;
        aw->wait_for = 0;
    }

    lua_pop(L, 1); // remove table key.

    P_DEBUG("%s: end\n", __func__);

    return 0;
}

// NOTE: This is unprotected lua/C code. There are no lua-style errors thrown
// purposefully as of this writing, but it's still not safe. Either the code
// can be restructured to use less lua (which I think is better long term
// anyway) or it can be pushed behind a cfunc pcall so we don't crash the
// daemon if something bad happens.
int mcplib_await_return(io_pending_proxy_t *p) {
    mcp_await_t *aw;
    lua_State *L = p->thread->L; // use the main VM coroutine for work
    bool cleanup = false;
    bool valid = false; // is response valid to add to the result table.
    bool completing = false;

    // TODO (v2): just push the await ptr into *p?
    lua_rawgeti(L, LUA_REGISTRYINDEX, p->await_ref);
    aw = lua_touserdata(L, -1);
    lua_pop(L, 1); // remove AW object from stack
    assert(aw != NULL);
    P_DEBUG("%s: start [pending: %d]\n", __func__, aw->pending);
    //dump_stack(L);

    aw->pending--;
    assert(aw->pending >= 0);
    // Await not yet satisfied.
    // If wait_for != 0 check for response success
    // if success and wait_for is *now* 0, we complete.
    // add successful response to response table
    // Also, if no wait_for, add response to response table
    // TODO (v2): for GOOD or OK cases, it might be better to return the
    // last object as valid if there are otherwise zero valids?
    // Think we just have to count valids...
    if (aw->type == AWAIT_BACKGROUND) {
        // in the background case, we never want to collect responses.
        if (p->await_background) {
            // found the dummy IO, complete and return conn to worker.
            completing = true;
        }
    } else if (!aw->completed) {
        valid = true; // always collect results unless we are completed.
        if (aw->wait_for > 0) {
            bool is_good = false;
            switch (aw->type) {
                case AWAIT_GOOD:
                    if (p->client_resp->status == MCMC_OK && p->client_resp->resp.code != MCMC_CODE_END) {
                        is_good = true;
                    }
                    break;
                case AWAIT_ANY:
                    is_good = true;
                    break;
                case AWAIT_OK:
                    if (p->client_resp->status == MCMC_OK) {
                        is_good = true;
                    }
                    break;
                case AWAIT_FIRST:
                    if (p->await_first) {
                        is_good = true;
                    } else {
                        // user only wants the first pool's result.
                        valid = false;
                    }
                    break;
                case AWAIT_FASTGOOD:
                    if (p->client_resp->status == MCMC_OK) {
                        // End early on a hit.
                        if (p->client_resp->resp.code != MCMC_CODE_END) {
                            aw->wait_for = 0;
                        } else {
                            is_good = true;
                        }
                    }
                    break;
                case AWAIT_BACKGROUND:
                    // In background mode we don't wait for any response.
                    break;
            }

            if (is_good) {
                aw->wait_for--;
            }

            if (aw->wait_for == 0) {
                completing = true;
            }
        }
    }

    // note that post-completion, we stop gathering responses into the
    // response table... because it's already been returned.
    // So "valid" can only be true if also !completed
    if (aw->pending == 0) {
        if (!aw->completed) {
            // were waiting for all responses.
            completing = true;
        }
        cleanup = true;
        P_DEBUG("%s: pending == 0\n", __func__);
    }

    // a valid response to add to the result table.
    if (valid) {
        P_DEBUG("%s: valid\n", __func__);
        lua_rawgeti(L, LUA_REGISTRYINDEX, aw->restable_ref); // -> 1
        lua_rawgeti(L, LUA_REGISTRYINDEX, p->mcpres_ref); // -> 2
        // couldn't find a table.insert() equivalent; so this is
        // inserting into the length + 1 position manually.
        //dump_stack(L);
        lua_rawseti(L, -2, lua_rawlen(L, 1) + 1); // pops mcpres
        lua_pop(L, 1); // pops restable
    }

    // lose our internal mcpres reference regardless.
    // also tag the elapsed time into the response.
    if (p->mcpres_ref) {
        // NOTE: this is redundant but the code is going away soon. not worth
        // testing changing it.
        mcp_resp_set_elapsed(p->client_resp);

        // instructed to generate log_req entries for each failed request,
        // this is useful to do here as these can be asynchronous.
        // NOTE: this may be a temporary feature.
        if (aw->logerr && p->client_resp->status != MCMC_OK && aw->completed) {
            size_t dlen = 0;
            const char *detail = NULL;
            logger *l = p->thread->l;
            // only process logs if someone is listening.
            if (l->eflags & LOG_PROXYREQS) {
                lua_rawgeti(L, LUA_REGISTRYINDEX, aw->req_ref);
                mcp_request_t *rq = lua_touserdata(L, -1);
                lua_pop(L, 1); // references still held, just clearing stack.
                mcp_resp_t *rs = p->client_resp;

                if (aw->detail_ref) {
                    lua_rawgeti(L, LUA_REGISTRYINDEX, aw->detail_ref);
                    detail = luaL_tolstring(L, -1, &dlen);
                    lua_pop(L, 1);
                }

                logger_log(l, LOGGER_PROXY_REQ, NULL, rq->pr.request, rq->pr.reqlen, rs->elapsed, rs->resp.type, rs->resp.code, rs->status, aw->rctx->conn_fd, detail, dlen, rs->be_name, rs->be_port);
            }
        }

        luaL_unref(L, LUA_REGISTRYINDEX, p->mcpres_ref);
    }
    // our await_ref is shared, so we don't need to release it.

    if (completing) {
        P_DEBUG("%s: completing\n", __func__);
        assert(p->c->thread == p->thread);
        aw->completed = true;
        lua_State *Lc = p->rctx->Lc;
        lua_rawgeti(Lc, LUA_REGISTRYINDEX, aw->restable_ref); // -> 1
        luaL_unref(L, LUA_REGISTRYINDEX, aw->restable_ref);
        proxy_run_rcontext(p->rctx);

        io_queue_t *q = conn_io_queue_get(p->c, p->io_queue_type);
        q->count--;
        if (q->count == 0) {
            // call re-add directly since we're already in the worker thread.
            conn_worker_readd(p->c);
        }

    }

    if (cleanup) {
        P_DEBUG("%s: cleanup [completed: %d]\n", __func__, aw->completed);
        luaL_unref(L, LUA_REGISTRYINDEX, aw->argtable_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, aw->req_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, p->await_ref);
        if (aw->detail_ref) {
            luaL_unref(L, LUA_REGISTRYINDEX, aw->detail_ref);
        }
        WSTAT_DECR(p->thread, proxy_await_active, 1);
    }

    // Just remove anything we could have left on the primary VM stack
    lua_settop(L, 0);

    // always return free this sub-IO object.
    do_cache_free(p->thread->io_cache, p);

    return 0;
}


function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12141)
    local b2 = mcp.backend('b2', '127.0.0.1', 12142)
    local b3 = mcp.backend('b3', '127.0.0.1', 12143)

    return {
        z1 = mcp.pool({b1}),
        z2 = mcp.pool({b2}),
        z3 = mcp.pool({b3})
    }
end

function cond_timeout(p)
    local fgen = mcp.funcgen_new()
    local near = fgen:new_handle(p.z1)
    local far = { fgen:new_handle(p.z2),
        fgen:new_handle(p.z3) }

    local all = { near, far[1], far[2] }

    fgen:ready({ n = "cond_timeout", f = function(rctx)
        return function(r)
            rctx:enqueue(r, near)
            local done, timeout = rctx:wait_cond(1, mcp.WAIT_GOOD, 0.5)

            if timeout then
                rctx:enqueue(r, far)
                local done = rctx:wait_cond(1, mcp.WAIT_GOOD)
                for x=1,#all do
                    local res = rctx:res_any(all[x])
                    if res then
                        return res
                    end
                end
                return "SERVER_ERROR no responses\r\n"
            else
                return rctx:res_any(near)
            end
        end
    end})
    return fgen
end

function enqueue_timeout(p)
    local fgen = mcp.funcgen_new()
    local near = fgen:new_handle(p.z1)
    local far = { fgen:new_handle(p.z2),
        fgen:new_handle(p.z3) }

    local all = { near, far[1], far[2] }
    fgen:ready({ n = "enqueue_timeout", f = function(rctx)
        return function(r)
            local nres, timeout = rctx:enqueue_and_wait(r, near, 0.5)

            if timeout then
                rctx:enqueue(r, far)
                local done = rctx:wait_cond(1, mcp.WAIT_GOOD)
                for x=1,#all do
                    local res = rctx:res_any(all[x])
                    if res then
                        return res
                    end
                end
                return "SERVER_ERROR no responses\r\n"
            else
                return nres
            end
        end
    end})
    return fgen
end

function wait_handle_timeout(p)
    local fgen = mcp.funcgen_new()
    local near = fgen:new_handle(p.z1)
    local far = { fgen:new_handle(p.z2),
        fgen:new_handle(p.z3) }

    local all = { near, far[1], far[2] }
    fgen:ready({ n = "handle_timeout", f = function(rctx)
        return function(r)
            rctx:enqueue(r, near)
            local nres, timeout = rctx:wait_handle(near, 0.5)

            if timeout then
                rctx:enqueue(r, far)
                local done = rctx:wait_cond(1, mcp.WAIT_GOOD)
                for x=1,#all do
                    local res = rctx:res_any(all[x])
                    if res then
                        return res
                    end
                end
                return "SERVER_ERROR no responses\r\n"
            else
                return nres
            end
        end
    end})
    return fgen
end

function wait_more(p)
    local fgen = mcp.funcgen_new()
    local near = fgen:new_handle(p.z1)

    fgen:ready({ n = "wait_more", f = function(rctx)
        return function(r)
            rctx:enqueue(r, near)
            local nres, timeout = rctx:wait_handle(near, 0.25)

            -- wait on the same handle twice.
            if timeout then
                local xres = rctx:wait_handle(near)
                return xres
            else
                return "SERVER_ERROR no timeout\r\n"
            end
        end
    end})
    return fgen
end

function wait_double(p)
    local fgen = mcp.funcgen_new()
    local near = fgen:new_handle(p.z1)

    fgen:ready({ n = "wait_double", f = function(rctx)
        return function(r)
            rctx:enqueue(r, near)
            -- timeout via sleep twice, then continue to function.
            local nres, timeout = rctx:wait_handle(near, 0.1)
            nres, timeout = rctx:wait_handle(near, 0.1)

            -- wait on the same handle twice.
            if timeout then
                local xres = rctx:wait_handle(near)
                return xres
            else
                return "SERVER_ERROR no timeout\r\n"
            end
        end
    end})
    return fgen
end

function rctx_sleep(p)
    local fgen = mcp.funcgen_new()
    local near = fgen:new_handle(p.z1)

    fgen:ready({ n = "sleep", f = function(rctx)
        return function(r)
            rctx:sleep(0.5)
            local nres = rctx:enqueue_and_wait(r, near)
            return nres
        end
    end})
    return fgen
end

-- TODO: different cond_timeout test with 2/3 instead of 1

function mcp_config_routes(p)
    local map = {
        ["cond_timeout"] = cond_timeout(p),
        ["enqueue_timeout"] = enqueue_timeout(p),
        ["handle_timeout"] = wait_handle_timeout(p),
        ["wait_more"] = wait_more(p),
        ["wait_double"] = wait_double(p),
        ["sleep"] = rctx_sleep(p),
    }

    -- defaults are fine. "prefix/etc"
    local router = mcp.router_new({
        map = map,
    })

    mcp.attach(mcp.CMD_MG, router)
end

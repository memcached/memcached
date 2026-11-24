-- rctx:handle_reset(): send to the same pool handle more than once within
-- one request.

function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12211)
    return mcp.pool({b1})
end

local function failed(res)
    return res == nil or not res:ok() or res:code() == mcp.MCMC_CODE_SERVER_ERROR
end

function mcp_config_routes(p)
    local map = {}
    local function route(name, gen)
        local fg = mcp.funcgen_new()
        local h = fg:new_handle(p)
        fg:ready({ n = name, f = function(rctx) return gen(rctx, h) end })
        map[name] = fg
    end

    -- up to three attempts on one handle, until the backend does not answer
    -- with SERVER_ERROR.
    route("retry", function(rctx, h)
        return function(r)
            local res
            for attempt = 1, 3 do
                if attempt > 1 and not rctx:handle_reset(h) then
                    return "SERVER_ERROR reset failed\r\n"
                end
                res = rctx:enqueue_and_wait(r, h)
                if not failed(res) then
                    break
                end
            end
            return res
        end
    end)

    -- resetting a handle that was never queued is fine.
    route("idle", function(rctx, h)
        return function(r)
            if not rctx:handle_reset(h) then
                return "SERVER_ERROR reset failed\r\n"
            end
            return rctx:enqueue_and_wait(r, h)
        end
    end)

    -- a handle whose request is still in flight is not reset.
    route("inflight", function(rctx, h)
        return function(r)
            rctx:enqueue(r, h)
            rctx:wait_cond(1, mcp.WAIT_ANY, 0.2)
            return "SERVER_ERROR reset " .. tostring(rctx:handle_reset(h)) .. "\r\n"
        end
    end)

    -- not allowed while the route is waiting (ie; from a callback).
    route("inwait", function(rctx, h)
        local err
        rctx:handle_set_cb(h, function(res)
            local ok, msg = pcall(rctx.handle_reset, rctx, h)
            err = ok and "allowed" or msg
            return mcp.WAIT_ANY
        end)
        return function(r)
            err = nil
            rctx:enqueue_and_wait(r, h)
            return "SERVER_ERROR " .. tostring(err) .. "\r\n"
        end
    end)

    mcp.attach(mcp.CMD_MG, mcp.router_new({ map = map }))
end

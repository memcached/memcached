function mcp_config_pools()
    mcp.backend_read_timeout(30)
    local b1 = mcp.backend('b1', '127.0.0.1', 12174)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local fgen = mcp.funcgen_new()
    local handle = fgen:new_handle(p)

    fgen:ready({ f = function(rctx)
        return function(r)
            return rctx:enqueue_and_wait(r, handle)
        end
    end})

    mcp.attach(mcp.CMD_ANY_STORAGE, fgen)
end

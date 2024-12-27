function mcp_config_pools()
    return true
end

function mcp_config_routes(p)
    local fg = mcp.funcgen_new()
    local h = fg:new_handle(mcp.internal_handler)
    fg:ready({ n = "internal", f = function(rctx)
        return function(r)
            return rctx:enqueue_and_wait(r, h)
        end
    end})

    mcp.attach(mcp.CMD_ANY_STORAGE, fg)
end

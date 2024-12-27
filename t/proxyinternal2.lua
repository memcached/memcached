function mcp_config_pools()
    return true
end

function mcp_config_routes(zones)
    local fg = mcp.funcgen_new()
    local h1 = fg:new_handle(mcp.internal_handler)
    local h2 = fg:new_handle(mcp.internal_handler)
    fg:ready({ n = "internal", f = function(rctx)
        return function(r)
            -- ensure we can't leak by grabbing a result we then don't use.
            local cmd = r:command()
            if cmd == mcp.CMD_GET or cmd == mcp.CMD_MG then
                local res1 = rctx:enqueue_and_wait(r, h1)
            end
            return rctx:enqueue_and_wait(r, h2)
        end
    end})

    mcp.attach(mcp.CMD_ANY_STORAGE, fg)
end

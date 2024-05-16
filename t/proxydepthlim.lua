function mcp_config_pools()
    mcp.backend_depth_limit(3)
    mcp.backend_connect_timeout(60)
    mcp.backend_read_timeout(60)
    mcp.backend_retry_timeout(60)
    local b1 = mcp.backend('b1', '127.0.0.1', 12161)
    return mcp.pool({b1})
end

-- not making requests, just opening/closing backends
function mcp_config_routes(p)
    local fg = mcp.funcgen_new()
    local h = fg:new_handle(p)
    fg:ready({
        n = "depth", f = function(rctx)
            return function(r)
                return rctx:enqueue_and_wait(r, h)
            end
        end
    })
    mcp.attach(mcp.CMD_MG, fg)
end

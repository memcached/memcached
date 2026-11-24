-- answers the client at once and sends the request to the backend in the
-- background, like an asynchronous fan-out route.
function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12201)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local fg = mcp.funcgen_new()
    local h = fg:new_handle(p)
    fg:ready({
        n = "background",
        f = function(rctx)
            return function(r)
                rctx:enqueue(r, h)
                rctx:wait_cond(0)
                return "HD\r\n"
            end
        end
    })
    mcp.attach(mcp.CMD_MG, fg)
end

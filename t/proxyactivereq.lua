-- mcp.active_requests(): requests active on this worker thread, including
-- background requests that were already answered to the client.

function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12221)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local bg = mcp.funcgen_new()
    local h = bg:new_handle(p)
    bg:ready({
        n = "background",
        f = function(rctx)
            return function(r)
                rctx:enqueue(r, h)
                rctx:wait_cond(0)
                return "HD\r\n"
            end
        end
    })

    local count = mcp.funcgen_new()
    count:ready({
        n = "count",
        f = function(rctx)
            return function(r)
                return "SERVER_ERROR active " .. mcp.active_requests() .. "\r\n"
            end
        end
    })

    mcp.attach(mcp.CMD_MG, mcp.router_new({ map = { bg = bg, count = count } }))
end

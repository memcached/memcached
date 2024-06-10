function mcp_config_pools()
    mcp.backend_connect_timeout(60)
    mcp.backend_read_timeout(60)
    mcp.backend_retry_timeout(60)
    local b1 = mcp.backend('b1', '127.0.0.1', 12171)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local fg = mcp.funcgen_new()
    local h = fg:new_handle(p)
    fg:ready({
        n = "match", f = function(rctx)
            return function(r)
                local res = rctx:enqueue_and_wait(r, h)
                local match, token = r:match_res(res)
                if match then
                    mcp.log("match succeeded")
                else
                    if token then
                        mcp.log("match failed: " .. token)
                    else
                        mcp.log("match failed: no token")
                    end
                end
                return res
            end
        end
    })
    mcp.attach(mcp.CMD_MG, fg)
    mcp.attach(mcp.CMD_MS, fg)
end

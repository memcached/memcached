
function mcp_config_routes(p)
    local fg = mcp.funcgen_new()
    local h = fg:new_handle(p)
    fg:ready({
        f = function(rctx)
            return function(r)
                return rctx:enqueue_and_wait(r, h)
            end
        end
    })
    mcp.attach(mcp.CMD_MG, fg)
end

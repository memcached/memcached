
function mcp_config_pools()
    local hlc = mcp.global_hlc({ opaque = 127 })
    local be = mcp.backend('b1', '127.0.0.1', 19211)
    local p = mcp.pool({be})
    return { hlc = hlc, p = p }
end

function mcp_config_routes(c)
    local hlc = c.hlc
    local p = c.p

    local ms = mcp.funcgen_new()
    local ms_h = ms:new_handle(p)
    ms:ready({
        f = function(rctx)
            return function(r)
                -- slap on a timer
                hlc:add_to_req(r)
                return rctx:enqueue_and_wait(r, ms_h)
            end
        end,
    })

    local mg = mcp.funcgen_new()
    local mg_h = mg:new_handle(p)
    mg:ready({
        f = function(rctx)
            return function(r)
                local res = rctx:enqueue_and_wait(r, mg_h)
                local time, opaque = hlc:get_from_res(res)
                return res
            end
        end,
    })

    mcp.attach(mcp.CMD_MS, ms)
    mcp.attach(mcp.CMD_MG, mg)
end

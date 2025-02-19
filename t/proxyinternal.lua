function mcp_config_pools()
    return true
end

function make_sub()
    local fg = mcp.funcgen_new()
    local h = fg:new_handle(mcp.internal_handler)
    fg:ready({ n = "subint", f = function(rctx)
        return function(r)
            return rctx:enqueue_and_wait(r, h)
        end
    end})
    return fg
end

function mcp_config_routes(zones)
    local fg = mcp.funcgen_new()
    local subfg = make_sub()
    local h = fg:new_handle(mcp.internal_handler)
    local hsub = fg:new_handle(subfg)
    fg:ready({ n = "internal", f = function(rctx)
        return function(r)
            local k = r:key()
            local cmd = r:command()
            if string.find(k, "^/sub/") then
                return rctx:enqueue_and_wait(r, hsub)
            else
                if k == "log" then
                    local res = rctx:enqueue_and_wait(r, h)
                    mcp.log_req(r, res, "testing")
                    return res
                elseif cmd == mcp.CMD_MG and k == "response/hit" then
                    local res = rctx:enqueue_and_wait(r, h)
                    return string.format("SERVER_ERROR res:hit = %q\r\n", res:hit())
                elseif cmd == mcp.CMD_MG and k == "response/code" then
                    local res = rctx:enqueue_and_wait(r, h)
                    return string.format("SERVER_ERROR res:code = %q\r\n", res:code())
                elseif cmd == mcp.CMD_MG and k == "response/line" then
                    local res = rctx:enqueue_and_wait(r, h)
                    return string.format("SERVER_ERROR res:line = %q\r\n", res:line())
                elseif cmd == mcp.CMD_MG and k == "response/vlen" then
                    local res = rctx:enqueue_and_wait(r, h)
                    return string.format("SERVER_ERROR res:vlen = %q\r\n", res:vlen())
                else
                    return rctx:enqueue_and_wait(r, h)
                end
            end
        end
    end})

    mcp.attach(mcp.CMD_ANY_STORAGE, fg)
end

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
            if string.find(k, "^/sub/") then
                return rctx:enqueue_and_wait(r, hsub)
            else
                if k == "log" then
                    local res = rctx:enqueue_and_wait(r, h)
                    mcp.log_req(r, res, "testing")
                    return res
                else
                    return rctx:enqueue_and_wait(r, h)
                end
            end
        end
    end})

    mcp.attach(mcp.CMD_ANY_STORAGE, fg)
end

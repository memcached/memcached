function mcp_config_pools()
    -- print("CONFIG GARBAGE: " .. collectgarbage("count"))
    local b1 = mcp.backend('b1', '127.0.0.1', 12101)
    return mcp.pool({b1})
end

-- the same fgen should be fine for the whole test. it doesn't matter how
-- complicated each individual fgen is, just that we're stacking them and
-- routing them.
-- Even with just one item linked they'll have all of the request/result/etc
-- objects referenced.
function basic_fgen(p)
    local fgen = mcp.funcgen_new()
    local h = fgen:new_handle(p)
    fgen:ready({ n = "foo", f = function(rctx)
        return function(r)
            local k = r:key()

            if string.find(k, "collect$") then
                collectgarbage()
                collectgarbage()
                local mem = collectgarbage("count")
                return "SERVER_ERROR " .. tostring(mem) .. "\r\n"
            elseif string.find(k, "go$") then
                return rctx:enqueue_and_wait(r, h)
            else
                return "SERVER_ERROR unknown key: " .. k .. "\r\n"
            end
        end
    end})
    return fgen
end

function mcp_config_routes(p)
    local map = {
        ["one"] = basic_fgen(p),
        ["two"] = basic_fgen(basic_fgen(p)),
        ["three"] = basic_fgen(basic_fgen(basic_fgen(p))),
    }
    -- "leak" an fgen on purpose.
    -- this gets a cleanup routine through the GC instead of directly during
    -- dereferencing.
    basic_fgen(p)

    -- defaults are fine. "prefix/etc"
    local router = mcp.router_new({
        map = map,
    })

    mcp.attach(mcp.CMD_MG, router)
end

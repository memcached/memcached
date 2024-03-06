
function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12091)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local fgen = mcp.funcgen_new()
    local h = fgen:new_handle(p)
    fgen:ready({ f = function(rctx)
        return function(r)
            local k = r:key()

            if k == "add1" then
                r:flag_add("F")
                return rctx:enqueue_and_wait(r, h)
            elseif k == "addstr" then
                r:flag_add("F", "1234")
                return rctx:enqueue_and_wait(r, h)
            elseif k == "addnum" then
                r:flag_add("F", 5678)
                return rctx:enqueue_and_wait(r, h)
            elseif k == "addexist" then
                if r:flag_add("O", "overwrite") then
                    return "SERVER_ERROR flag overwritten"
                else
                    return "HD\r\n"
                end
            end

            if k == "set1" then
                r:flag_set("F")
                return rctx:enqueue_and_wait(r, h)
            elseif k == "setstr" then
                r:flag_set("F", "4321")
                return rctx:enqueue_and_wait(r, h)
            elseif k == "setnum" then
                r:flag_set("F", 8765)
                return rctx:enqueue_and_wait(r, h)
            elseif k == "setexist" then
                if r:flag_set("O", "overwrite") then
                    return rctx:enqueue_and_wait(r, h)
                else
                    return "HD\r\n"
                end
            elseif k == "setflag" then
                -- technically protocol invalid but should work.
                if r:flag_set("O") then
                    return rctx:enqueue_and_wait(r, h)
                else
                    return "HD\r\n"
                end
            end

            -- don't need full set of tests anymore since this function reuses
            -- the code for add/set.
            if k == "repl1" then
                r:flag_replace("F", "O", "foo")
                return rctx:enqueue_and_wait(r, h)
            elseif k == "repl2" then
                r:flag_replace("F", "O")
                return rctx:enqueue_and_wait(r, h)
            end

            if k == "del1" then
                r:flag_del("O")
                return rctx:enqueue_and_wait(r, h)
            end
        end
    end})

    mcp.attach(mcp.CMD_MG, fgen)
    -- TODO: test MS as well to ensure it doesn't eat the value line
end

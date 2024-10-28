
function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12091)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local setfg = mcp.funcgen_new()
    local sh = setfg:new_handle(p)
    setfg:ready({ f = function(rctx)
        return function(r)
            local k = r:key()

            if k == "setints" then
                local flags = r:token_int(3)
                local ttl = r:token_int(4)
                local bytes = r:token_int(5)
                flags = flags + ttl + bytes
                r:token(3, flags)
                return rctx:enqueue_and_wait(r, sh)
            end
        end
    end})

    local mgfg = mcp.funcgen_new()
    local h = mgfg:new_handle(p)
    mgfg:ready({ f = function(rctx)
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

            if k == "fint" then
                -- avoids creating string junk if we only need to treat this
                -- token as an integer.
                local found, token = r:flag_token_int("F")
                if type(token) ~= "number" then
                    error("token wasn't converted to a number")
                end
                token = token * 10 + 1
                r:flag_set("F", token)
                return rctx:enqueue_and_wait(r, h)
            end

            if k == "toolong" then
                local str = {"."}
                while true do
                    local res, err = pcall(function()
                        local nreq = mcp.request("mg P" .. table.concat(str))
                        table.insert(str, ".")
                    end)
                    -- ensure that we do eventually error
                    if res == false then
                        return rctx:enqueue_and_wait(r, h)
                    end
                end
            end
        end
    end})

    mcp.attach(mcp.CMD_MG, mgfg)
    mcp.attach(mcp.CMD_SET, setfg)
    -- TODO: test MS as well to ensure it doesn't eat the value line
end

function mcp_config_pools(oldss)
    local srv = mcp.backend
    mcp.backend_read_timeout(0.5)
    mcp.backend_connect_timeout(5)
    mcp.backend_retry_timeout(5)

    -- Single backend for zones to ease testing.
    -- For purposes of this config the proxy is always "zone 1" (z1)
    local b1 = srv('b1', '127.0.0.1', 11411)
    local b2 = srv('b2', '127.0.0.1', 11412)
    local b3 = srv('b3', '127.0.0.1', 11413)

    local b1z = {b1}
    local b2z = {b2}
    local b3z = {b3}

    local dead = srv('dead', '127.9.9.9', 11011);

    local no_label = srv('', '127.0.0.1', 11414)

    -- convert the backends to pools.
    local zones = {
        z1 = mcp.pool(b1z),
        z2 = mcp.pool(b2z),
        z3 = mcp.pool(b3z),
        dead = mcp.pool({dead}),
        no_label = mcp.pool({no_label})
    }

    return zones
end

-- WORKER CODE:
function new_basic(zones, func)
    local fgen = mcp.funcgen_new()
    local o = { t = {}, c = 0 }

    o.t.z1 = fgen:new_handle(zones.z1)
    o.t.z2 = fgen:new_handle(zones.z2)
    o.t.z3 = fgen:new_handle(zones.z3)
    o.t.dead = fgen:new_handle(zones.dead)
    o.t.no_label = fgen:new_handle(zones.no_label)

    fgen:ready({ f = func, a = o})
    return fgen
end

-- Do specialized testing based on the key prefix.
function mcp_config_routes(zones)
    local map = {}

    map.b = new_basic(zones, function(rctx, a)
        return function(r)
            return rctx:enqueue_and_wait(r, a.t.z1)
        end
    end)

    map.errcheck = new_basic(zones, function(rctx, a)
        return function(r)
            local res = rctx:enqueue_and_wait(r, a.t.z1)
            -- expect an error
            if res:ok() then
                return "FAIL\r\n"
            end
            if res:code() == mcp.MCMC_CODE_ERROR then
                return "ERROR\r\n"
            elseif res:code() == mcp.MCMC_CODE_CLIENT_ERROR then
                return "CLIENT_ERROR\r\n"
            elseif res:code() == mcp.MCMC_CODE_SERVER_ERROR then
                return "SERVER_ERROR\r\n"
            end
            return "FAIL"
        end
    end)

    -- show that we fetched the key by generating our own response string.
    map.getkey = new_basic(zones, function(rctx, a)
        return function(r)
            return "VALUE |" .. r:key() .. " 0 2\r\nts\r\nEND\r\n"
        end
    end)

    map.rtrimkey = new_basic(zones, function(rctx, a)
        return function(r)
            r:rtrimkey(4)
            return rctx:enqueue_and_wait(r, a.t.z1)
        end
    end)

    map.ltrimkey = new_basic(zones, function(rctx, a)
        return function(r)
            r:ltrimkey(10)
            return rctx:enqueue_and_wait(r, a.t.z1)
        end
    end)

    map.nolabel = new_basic(zones, function(rctx, a)
        return function(r)
            return rctx:enqueue_and_wait(r, a.t.no_label)
        end
    end)

    map.ntokens = new_basic(zones, function(rctx, a)
        return function(r)
            return "VA 1 C123 v\r\n" .. r:ntokens() .. "\r\n"
        end
    end)

    map.hasflag = {
        [mcp.CMD_MG] = new_basic(zones, function(rctx, a)
            return function(r)
                if r:has_flag("c") then
                    return "HD C123\r\n"
                elseif r:has_flag("O") then
                    return "HD Oabc\r\n"
                end
                return "NF\r\n"
            end
        end),
        [mcp.CMD_GET] = new_basic(zones, function(rctx, a)
            return function(r)
                if r:has_flag("F") then
                    return "ERROR flag found\r\n"
                end
                return "END\r\n"
            end
        end)
    }

    -- Input flags: N10 k c R10
    -- Output flags: N100 k R100
    map.flagtoken = new_basic(zones, function(rctx, a)
        return function(r)
            -- flag_token on non-existing flags: no effect
            local Ttoken = r:flag_token("T", "T100")
            local Otoken = r:flag_token("O", nil)
            local vtoken = r:flag_token("v", "")
            if vtoken or Otoken or Ttoken then
                return "ERROR found non-existing flag.\r\n"
            end

            -- flag_token to replace: N10 -> N100
            local found, Ntoken = r:flag_token("N", "N100")
            if not found or Ntoken ~= "10" then
                return "ERROR unexpected N token.\r\n"
            end

            -- flag_token with nil 2nd arg: equvalent to fetch
            r:flag_token("k", nil)
            if not r:has_flag("k") then
                return "ERROR unexpected k token.\r\n"
            end

            -- flag_token with self 2nd arg: no effect
            r:flag_token("c", "c")
            if not r:has_flag("c") then
                return "ERROR unexpected c token 1.\r\n"
            end

            -- flag_token with "" 2nd arg: remove
            r:flag_token("c", "")
            if r:has_flag("c") then
                return "ERROR unexpected c token 2.\r\n"
            end

            -- repeated flag_token calls: new value is returned.
            local _, Rtoken = r:flag_token("R", "R100")
            if Rtoken ~= '10' then
                return "ERROR unexpected R token 1.\r\n"
            end
            _, Rtoken = r:flag_token("R", "R100")
            if Rtoken ~= '100' then
                return "ERROR unexpected R token 2.\r\n"
            end

            return "HD\r\n"
        end
    end)

    map.request = {
        [mcp.CMD_MS] = new_basic(zones, function(rctx, a)
            return function(r)
                local key = r:key()
                local newReq = mcp.request("ms /request/edit 2\r\n", "ab\r\n")
                return rctx:enqueue_and_wait(newReq, a.t.z1)
            end
        end),
        [mcp.CMD_MG] = new_basic(zones, function(rctx, a)
            return function(r)
                local key = r:key()
                if key == "/request/old" then
                    local newReq = mcp.request("mg /request/new c\r\n")
                    return rctx:enqueue_and_wait(newReq, a.t.z1)
                else
                    local res = rctx:enqueue_and_wait(r, a.t.z1)
                    local newReq = mcp.request("ms /request/a " .. res:vlen() .. "\r\n", res)
                    return rctx:enqueue_and_wait(newReq, a.t.z2)
                end
            end
        end)
    }

    map.response = {
        [mcp.CMD_GET] = new_basic(zones, function(rctx, a)
            return function(r)
                local res = rctx:enqueue_and_wait(r, a.t.z1)
                local key = r:key()
                if key == "/response/hit" then
                    local hit = res:hit()
                    if hit then
                        return res
                    end
                    return "ERROR hit is false\r\n"
                elseif key == "/response/not_hit" then
                    local hit = res:hit()
                    if not hit then
                        return "SERVER_ERROR\r\n"
                    end
                    return res
                end
                return "ERROR unhandled key\r\n"

            end
        end),
        [mcp.CMD_MG] = new_basic(zones, function(rctx, a)
            return function(r)
                local res = rctx:enqueue_and_wait(r, a.t.z1)
                local key = r:key()
                if key == "/response/elapsed" then
                    local elapsed = res:elapsed()
                    if elapsed > 100000 then
                        return res
                    end
                    return "ERROR elapsed is invalid.\r\n"
                elseif key == "/response/ok" then
                    local ok = res:ok()
                    if ok then
                        return res
                    end
                    return "ERROR ok is false\r\n"
                elseif key == "/response/not_ok" then
                    local ok = res:ok()
                    if not ok then
                        return "SERVER_ERROR\r\n"
                    end
                    return "HD\r\n"
                elseif key == "/response/hit" then
                    local hit = res:hit()
                    if hit then
                        return res
                    end
                    return "ERROR hit is false\r\n"
                elseif key == "/response/not_hit" then
                    local hit = res:hit()
                    if not hit then
                        return "SERVER_ERROR\r\n"
                    end
                    return "HD\r\n"
                elseif key == "/response/vlen" then
                    local vlen = res:vlen()
                    if vlen == 1 then
                        return res
                    end
                    return "ERROR vlen is not 1\r\n"
                elseif key == "/response/code_ok" then
                    local code = res:code()
                    if code == mcp.MCMC_CODE_OK then
                        return res
                    end
                    return "ERROR expect MCMC_CODE_OK, but got " .. code .. "\r\n"
                elseif key == "/response/code_miss" then
                    local code = res:code()
                    if code == mcp.MCMC_CODE_END then
                        return res
                    end
                    return "ERROR expect MCMC_CODE_END, but got " .. code .. "\r\n"
                elseif key == "/response/line" then
                    local line = res:line()
                    if line == "v c123" then
                        return res
                    end
                    return "ERROR unexpected line, got [" .. line .. "]\r\n"
                elseif key == "/response/blank" then
                    res:flag_blank("O")
                    return res
                end
                return "ERROR unhandled key\r\n"

            end
        end),
        [mcp.CMD_MS] = new_basic(zones, function(rctx, a)
            return function(r)
                local key = r:key()
                local res = rctx:enqueue_and_wait(r, a.t.z1)
                local code = res:code()

                if key == "/response/code_ok" then
                    if code == mcp.MCMC_CODE_OK then
                        return res
                    end
                    return "ERROR expect MCMC_CODE_OK, but got " .. code .. "\r\n"
                elseif key == "/response/line" then
                    local line = res:line()
                    if line == "O123 C123" then
                        return res
                    end
                    return "ERROR unexpected line, got [" .. line .. "]\r\n"
                end
                return "ERROR unhandled key\r\n"
            end
        end),
        [mcp.CMD_SET] = new_basic(zones, function(rctx, a)
            return function(r)
                local res = rctx:enqueue_and_wait(r, a.t.z1)
                local key = r:key()
                if key == "/response/code_stored" then
                    local code = res:code()
                    if code == mcp.MCMC_CODE_STORED then
                        return res
                    end
                    return "ERROR expect MCMC_CODE_STORED, but got " .. code .. "\r\n"
                elseif key == "/response/code_exists" then
                    local code = res:code()
                    if code == mcp.MCMC_CODE_EXISTS then
                        return res
                    end
                    return "ERROR expect MCMC_CODE_EXISTS, but got " .. code .. "\r\n"
                elseif key == "/response/code_not_stored" then
                    local code = res:code()
                    if code == mcp.MCMC_CODE_NOT_STORED then
                        return res
                    end
                    return "ERROR expect MCMC_CODE_NOT_STORED, but got " .. code .. "\r\n"
                elseif key == "/response/code_not_found" then
                    local code = res:code()
                    if code == mcp.MCMC_CODE_NOT_FOUND then
                        return res
                    end
                    return "ERROR expect MCMC_CODE_NOT_FOUND, but got " .. code .. "\r\n"
                end
                return "ERROR unhandled key\r\n"
            end
        end),
        [mcp.CMD_TOUCH] = new_basic(zones, function(rctx, a)
            return function(r)
                local res = rctx:enqueue_and_wait(r, a.t.z1)
                local key = r:key()
                local code = res:code()
                if code == mcp.MCMC_CODE_TOUCHED then
                    return res
                end
                return "ERROR expect MCMC_CODE_TOUCHED, but got " .. code .. "\r\n"
            end
        end),
        [mcp.CMD_DELETE] = new_basic(zones, function(rctx, a)
            return function(r)
                local res = rctx:enqueue_and_wait(r, a.t.z1)
                local key = r:key()
                local code = res:code()
                if code == mcp.MCMC_CODE_DELETED then
                    return res
                end
                return "ERROR expect MCMC_CODE_DELETED, but got " .. code .. "\r\n"
            end
        end),
    }

    map.token = new_basic(zones, function(rctx, a)
        return function(r)
            local key = r:key()
            if key == "/token/replacement" then
                r:token(4, "C456")
            elseif key == "/token/removal" then
                r:token(4, "")
            else
                local token = r:token(2)
                r:flag_token("P", "P" .. token)
            end
            return rctx:enqueue_and_wait(r, a.t.z1)
        end
    end)

    map.zonetest = new_basic(zones, function(rctx, a)
        return function(r)
            local key = r:key()
            if key == "/zonetest/a" then
                return rctx:enqueue_and_wait(r, a.t.z1)
            elseif key == "/zonetest/b" then
                return rctx:enqueue_and_wait(r, a.t.z2)
            elseif key == "/zonetest/c" then
                return rctx:enqueue_and_wait(r, a.t.z3)
            else
                return "END\r\n"
            end
        end
    end)

    map.logtest = new_basic(zones, function(rctx, a)
        return function(r)
            mcp.log("testing manual log messages")
            return "END\r\n"
        end
    end)

    map.logreqtest = new_basic(zones, function(rctx, a)
        return function(r)
            local res = rctx:enqueue_and_wait(r, a.t.z1)
            mcp.log_req(r, res, "logreqtest")
            return res
        end
    end)

    map.logreqstest = new_basic(zones, function(rctx, a)
        return function(r)
            local res = rctx:enqueue_and_wait(r, a.t.z1)
            mcp.log_reqsample(150, 0, true, r, res, "logsampletest")
            return res
        end
    end)

    map.sanity = new_basic(zones, function(rctx, a)
        local z = {a.t.z1, a.t.z2, a.t.z3}
        return function(r)
            rctx:enqueue(r, z)
            rctx:wait_cond(3)
            return rctx:result(a.t.z3)
        end
    end)

    map.dead = new_basic(zones, function(rctx, a)
        return function(r)
            return rctx:enqueue_and_wait(r, a.t.dead)
        end
    end)

    map.deadrespcode = new_basic(zones, function(rctx, a)
        return function(r)
            local res = rctx:enqueue_and_wait(r, a.t.dead)
            if res:code() == mcp.MCMC_CODE_SERVER_ERROR then
             return "ERROR code_correct\r\n"
            end
            return "ERROR code_incorrect: " .. res:code() .. "\r\n"
        end
    end)

    map.millis = new_basic(zones, function(rctx, a)
        return function(r)
            local time = mcp.time_real_millis()
            return "HD t" .. time .. "\r\n"
        end
    end)

    local def_fg = mcp.funcgen_new()
    def_fg:ready({
        f = function(rctx)
            return function(r)
                return "SERVER_ERROR no set route\r\n"
            end
        end
    })

    mcp.attach(mcp.CMD_ANY_STORAGE, mcp.router_new({
    map = map, mode = "anchor", start = "/", stop = "/", default = def_fg
    }))
end

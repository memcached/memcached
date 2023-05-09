function mcp_config_pools(oldss)
    local srv = mcp.backend
    mcp.backend_read_timeout(0.5)
    mcp.backend_connect_timeout(5)

    -- Single backend for zones to ease testing.
    -- For purposes of this config the proxy is always "zone 1" (z1)
    local b1 = srv('b1', '127.0.0.1', 11411)
    local b2 = srv('b2', '127.0.0.1', 11412)
    local b3 = srv('b3', '127.0.0.1', 11413)

    local b1z = {b1}
    local b2z = {b2}
    local b3z = {b3}

    -- convert the backends to pools.
    -- as per a normal full config see simple.lua or t/startfile.lua
    local zones = {
        z1 = mcp.pool(b1z),
        z2 = mcp.pool(b2z),
        z3 = mcp.pool(b3z),
    }

    return zones
end

-- WORKER CODE:

-- Using a very simple route handler only to allow testing the three
-- workarounds in the same configuration file.
function prefix_factory(pattern, list, default)
    local p = pattern
    local l = list
    local d = default
    return function(r)
        local route = l[string.match(r:key(), p)]
        if route == nil then
            return d(r)
        end
        return route(r)
    end
end

-- just for golfing the code in mcp_config_routes()
function toproute_factory(pfx, label)
    local err = "SERVER_ERROR no " .. label .. " route\r\n"
    return prefix_factory("^/(%a+)/", pfx, function(r) return err end)
end

-- Do specialized testing based on the key prefix.
function mcp_config_routes(zones)
    local pfx_get = {}
    local pfx_set = {}
    local pfx_touch = {}
    local pfx_gets = {}
    local pfx_gat = {}
    local pfx_gats = {}
    local pfx_cas = {}
    local pfx_add = {}
    local pfx_delete = {}
    local pfx_incr = {}
    local pfx_decr = {}
    local pfx_append = {}
    local pfx_prepend = {}
    local pfx_mg = {}
    local pfx_ms = {}
    local pfx_md = {}
    local pfx_ma = {}

    local basic = function(r)
        return zones.z1(r)
    end

    pfx_get["b"] = basic
    pfx_set["b"] = basic
    pfx_touch["b"] = basic
    pfx_gets["b"] = basic
    pfx_gat["b"] = basic
    pfx_gats["b"] = basic
    pfx_cas["b"] = basic
    pfx_add["b"] = basic
    pfx_delete["b"] = basic
    pfx_incr["b"] = basic
    pfx_decr["b"] = basic
    pfx_append["b"] = basic
    pfx_prepend["b"] = basic
    pfx_mg["b"] = basic
    pfx_ms["b"] = basic
    pfx_md["b"] = basic
    pfx_ma["b"] = basic

    pfx_get["errcheck"] = function(r)
        local res = zones.z1(r)
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

    -- show that we fetched the key by generating our own response string.
    pfx_get["getkey"] = function(r)
        return "VALUE |" .. r:key() .. " 0 2\r\nts\r\nEND\r\n"
    end

    pfx_get["rtrimkey"] = function(r)
        r:rtrimkey(4)
        return zones.z1(r)
    end

    pfx_get["ltrimkey"] = function(r)
        r:ltrimkey(10)
        return zones.z1(r)
    end

    pfx_mg["ntokens"] = function(r)
        return "VA 1 C123 v\r\n" .. r:ntokens() .. "\r\n"
    end

    pfx_mg["hasflag"] = function(r)
        if r:has_flag("c") then
            return "HD C123\r\n"
        elseif r:has_flag("O") then
            return "HD Oabc\r\n"
        end
        return "NF\r\n"
    end

    -- Input flags: N10 k c R10
    -- Output flags: N100 k R100
    pfx_mg["flagtoken"] = function(r)
        -- flag_token on non-existing flags: no effect
        local Ttoken = r:flag_token("T", "T100")
        local Otoken = r:flag_token("O", nil)
        local vtoken = r:flag_token("v", "")
        if vtoken or Otoken or Ttoken then
            return "ERROR found non-existing flag."
        end

        -- flag_token to replace: N10 -> N100
        local found, Ntoken = r:flag_token("N", "N100")
        if not found or Ntoken ~= "10" then
            return "ERROR unexpected N token."
        end

        -- flag_token with nil 2nd arg: equvalent to fetch
        r:flag_token("k", nil)
        if not r:has_flag("k") then
            return "ERROR unexpected k token."
        end

        -- flag_token with self 2nd arg: no effect
        r:flag_token("c", "c")
        if not r:has_flag("c") then
            return "ERROR unexpected c token 1."
        end

        -- flag_token with "" 2nd arg: remove
        r:flag_token("c", "")
        if r:has_flag("c") then
            return "ERROR unexpected c token 2."
        end

        -- repeated flag_token calls: new value is returned.
        local _, Rtoken = r:flag_token("R", "R100")
        if Rtoken ~= '10' then
            return "ERROR unexpected R token 1."
        end
        _, Rtoken = r:flag_token("R", "R100")
        if Rtoken ~= '100' then
            return "ERROR unexpected R token 2."
        end

        return "HD\r\n"
    end

    pfx_ms["request"] = function(r)
        local key = r:key()
        local newReq = mcp.request("ms /request/edit 2\r\n", "ab\r\n")
        return zones.z1(newReq)
    end

    pfx_mg["request"] = function(r)
        local key = r:key()
        if key == "/request/old" then
            local newReq = mcp.request("mg /request/new c\r\n")
            return zones.z1(newReq)
        else
            local res = zones.z1(r)
            local newReq = mcp.request("ms /request/a " .. res:vlen() .. "\r\n", res)
            return zones.z1(newReq)
        end
    end

    pfx_get["hasflag"] = function(r)
        if r:has_flag("F") then
            return "ERROR flag found\r\n"
        end
        return "END\r\n"
    end

    pfx_ms["token"] = function(r)
        local key = r:key()
        if key == "/token/replacement" then
            r:token(4, "C456")
            return zones.z1(r)
        elseif key == "/token/removal" then
            r:token(4, "")
            return zones.z1(r)
        else
            local token = r:token(2)
            r:flag_token("P", "P" .. token)
            return zones.z1(r)
        end
    end

    -- Basic test for routing requests to specific pools.
    -- Not sure how this could possibly break but testing for completeness.
    pfx_get["zonetest"] = function(r)
        local key = r:key()
        if key == "/zonetest/a" then
            return zones.z1(r)
        elseif key == "/zonetest/b" then
            return zones.z2(r)
        elseif key == "/zonetest/c" then
            return zones.z3(r)
        else
            return "END\r\n"
        end
    end

    pfx_get["logtest"] = function(r)
        mcp.log("testing manual log messages")
        return "END\r\n"
    end

    pfx_get["logreqtest"] = function(r)
        local res = zones.z1(r)
        mcp.log_req(r, res, "logreqtest")
        return res
    end

    -- tell caller what we got back via a fake response
    pfx_get["awaitbasic"] = function(r)
        local vals = {}
        local rtable = mcp.await(r, { zones.z1, zones.z2, zones.z3 })

        for i, res in pairs(rtable) do
            if res:hit() == true then
                vals[i] = "hit"
            elseif res:ok() == true then
                vals[i] = "ok"
            else
                vals[i] = "err"
            end
        end

        local val = table.concat(vals, " ")
        local vlen = string.len(val)
        -- convenience functions for creating responses would be nice :)
        return "VALUE " .. r:key() .. " 0 " .. vlen .. "\r\n" .. val .. "\r\nEND\r\n"
    end

    pfx_get["awaitone"] = function(r)
        local mode = string.sub(r:key(), -1, -1)
        local num = 0
        if mode == "a" then
            num = 1
        elseif mode == "b" then
            num = 2
        end
        local rtable = mcp.await(r, { zones.z1, zones.z2, zones.z3 }, num)

        local count = 0
        for i, res in pairs(rtable) do
            count = count + 1
        end

        local vlen = string.len(count)
        return "VALUE " .. r:key() .. " 0 " .. vlen .. "\r\n" .. count .. "\r\nEND\r\n"
    end

    -- should be the same as awaitone
    pfx_get["awaitgood"] = function(r)
        local mode = string.sub(r:key(), -1, -1)
        local num = 0
        if mode == "a" then
            num = 1
        elseif mode == "b" then
            num = 2
        end
        local rtable = mcp.await(r, { zones.z1, zones.z2, zones.z3 }, num, mcp.AWAIT_GOOD)

        local count = 0
        for i, res in pairs(rtable) do
            count = count + 1
        end

        local vlen = string.len(count)
        return "VALUE " .. r:key() .. " 0 " .. vlen .. "\r\n" .. count .. "\r\nEND\r\n"
    end

    -- not sure if anything else should be checked here? if err or not?
    pfx_get["awaitany"] = function(r)
        local rtable = mcp.await(r, { zones.z1, zones.z2, zones.z3 }, 2, mcp.AWAIT_ANY)
        local count = 0
        for i, res in pairs(rtable) do
            count = count + 1
        end

        local vlen = string.len(count)
        return "VALUE " .. r:key() .. " 0 " .. vlen .. "\r\n" .. count .. "\r\nEND\r\n"
    end

    pfx_get["awaitbg"] = function(r)
        local rtable = mcp.await(r, { zones.z1, zones.z2, zones.z3 }, 1, mcp.AWAIT_BACKGROUND)
        local count = 0
        for i, res in pairs(rtable) do
            count = count + 1
        end

        local vlen = string.len(count)
        return "VALUE " .. r:key() .. " 0 " .. vlen .. "\r\n" .. count .. "\r\nEND\r\n"
    end

    pfx_set["awaitlogerr"] = function(r)
        local rtable = mcp.await_logerrors(r, { zones.z1, zones.z2, zones.z3 }, 1, mcp.AWAIT_FASTGOOD, "write_failed")
        return rtable[1]
    end

    -- testing different styles of building the table argument for mcp.await()
    pfx_get["awaitfastgood"] = function(r)
        local all_zones = {}
        for k, v in pairs(zones) do
            all_zones[k] = v
        end

        local restable = mcp.await(r, all_zones, 2, mcp.AWAIT_FASTGOOD)

        local final_res = restable[1]
        local count = 0
        for _, res in pairs(restable) do
            if res:hit() then
                final_res = res
            end
            count = count + 1
        end

        return final_res
    end

    pfx_set["awaitfastgood"] = function(r)
        local all_zones = {}
        for _, v in pairs(zones) do
            table.insert(all_zones, v)
        end

        local restable = mcp.await(r, all_zones, 2)
        local count = 0
        local good_res = restable[1]
        for _, res in pairs(restable) do
            if res:ok() then
                good_res = res
            end
            count = count + 1
        end

        print("Set Response count: " .. count)
        return good_res
    end

    pfx_touch["sanity"] = function(r)
        local rtable = mcp.await(r, { zones.z1, zones.z2, zones.z3 })
        return rtable[3]
    end

    mcp.attach(mcp.CMD_GET, toproute_factory(pfx_get, "get"))
    mcp.attach(mcp.CMD_SET, toproute_factory(pfx_set, "set"))
    mcp.attach(mcp.CMD_TOUCH, toproute_factory(pfx_touch, "touch"))
    mcp.attach(mcp.CMD_GETS, toproute_factory(pfx_gets, "gets"))
    mcp.attach(mcp.CMD_GAT, toproute_factory(pfx_gat, "gat"))
    mcp.attach(mcp.CMD_GATS, toproute_factory(pfx_gats, "gats"))
    mcp.attach(mcp.CMD_CAS, toproute_factory(pfx_cas, "cas"))
    mcp.attach(mcp.CMD_ADD, toproute_factory(pfx_add, "add"))
    mcp.attach(mcp.CMD_DELETE, toproute_factory(pfx_delete, "delete"))
    mcp.attach(mcp.CMD_INCR, toproute_factory(pfx_incr, "incr"))
    mcp.attach(mcp.CMD_DECR, toproute_factory(pfx_decr, "decr"))
    mcp.attach(mcp.CMD_APPEND, toproute_factory(pfx_append, "append"))
    mcp.attach(mcp.CMD_PREPEND, toproute_factory(pfx_prepend, "prepend"))
    mcp.attach(mcp.CMD_MG, toproute_factory(pfx_mg, "mg"))
    mcp.attach(mcp.CMD_MS, toproute_factory(pfx_ms, "ms"))
    mcp.attach(mcp.CMD_MD, toproute_factory(pfx_md, "md"))
    mcp.attach(mcp.CMD_MA, toproute_factory(pfx_ma, "ma"))

end

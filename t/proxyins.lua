function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12172)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local mgsepkey = mcp.funcgen_new()
    local mgsepkeyh = mgsepkey:new_handle(p)

    local mgsepkey_ins = mcp.req_inspector_new(
        { t = "sepkey", sep = "/", pos = 2, map = {
            foo = 1, bar = 2,
        }},
        { t = "keybegin", str = "sepkey" }
    )

    local mgsepkeynomap_ins = mcp.req_inspector_new(
        { t = "sepkey", sep = "/", pos = 2 }
    )

    local mgsepkey1_ins = mcp.req_inspector_new(
        { t = "sepkey", sep = "/", pos = 1, map = {
            baz = 1, foo = 2, sepkey = 3,
        }}
    )

    local mgsepkey2_ins = mcp.req_inspector_new(
        { t = "sepkey", sep = "/", pos = 2, map = {
            baz = 1, foo = 2,
        }}
    )

    local mgsepkey3_ins = mcp.req_inspector_new(
        { t = "sepkey", sep = "/", pos = 3, map = {
            baz = 1, foo = 2, three = 3,
        }}
    )

    mgsepkey:ready({
        n = "sepkey", f = function(rctx)
            return function(r)
                local key = r:key()
                if key == "sepkey/baz" then
                    local idx = mgsepkey2_ins(r)
                    return string.format("SERVER_ERROR idx: %q\r\n", idx)
                elseif key == "sepkey/nomap" then
                    local str = mgsepkeynomap_ins(r)
                    return string.format("SERVER_ERROR str: %s\r\n", str)
                elseif key == "sepkey/one/two" then
                    local idx = mgsepkey1_ins(r)
                    return string.format("SERVER_ERROR idx: %q\r\n", idx)
                elseif key == "sepkey/two/three" then
                    local idx = mgsepkey3_ins(r)
                    return string.format("SERVER_ERROR idx: %q\r\n", idx)
                else
                    local idx, b = mgsepkey_ins(r)
                    local begin = "false"
                    if b then
                        begin = "true"
                    end
                    if idx == nil then
                        return "SERVER_ERROR nil index\r\n"
                    else
                        return string.format("SERVER_ERROR idx: %d %s\r\n", idx, begin)
                    end
                end
            end
        end
    })

    local mgreshasf = mcp.funcgen_new()
    local mgreshasfh = mgreshasf:new_handle(p)

    local mgreshasf_ins = mcp.res_inspector_new(
        { t = "hasflag", flag = "f" },
        { t = "hasflag", flag = "t" }
    )
    -- TODO: also test req version
    local mgresflaga_ins = mcp.res_inspector_new(
        { t = "flagtoken", flag = "O" },
        { t = "flagint", flag = "t" }
    )

    local mgreqflaga_ins = mcp.req_inspector_new(
        { t = "flagtoken", flag = "O" },
        { t = "flagint", flag = "T" }
    )

    local mgresflagis_ins = mcp.res_inspector_new(
        { t = "flagis", flag = "O", str = "baz" }
    )
    mgreshasf:ready({
        n = "reshasflag", f = function(rctx)
            return function(r)
                local key = r:key()
                local res = rctx:enqueue_and_wait(r, mgreshasfh)
                if key == "reshasf/flagis" then
                    local exists, matches = mgresflagis_ins(res)
                    return string.format("SERVER_ERROR exists[%q] matches[%q]\r\n", exists, matches)
                elseif key == "reshasf/tokenint" then
                    local has_O, O, has_t, t = mgresflaga_ins(res)
                    return string.format("SERVER_ERROR O[%q]: %s t[%q]: %q\r\n",
                        has_O, O, has_t, t)
                elseif key == "reshasf/reqhasf" then
                    local has_O, O, has_T, T = mgreqflaga_ins(r)
                    return string.format("SERVER_ERROR O[%q]: %s T[%q]: %q\r\n",
                        has_O, O, has_T, T)
                else
                    local f, t = mgreshasf_ins(res)
                    return "SERVER_ERROR f: " .. tostring(f) .. " t: " .. tostring(t) .. "\r\n"
                end
            end
        end
    })

    local mgreqkey = mcp.funcgen_new()
    local mgreqkeyh = mgreqkey:new_handle(p)

    local mgreqkeyis_ins = mcp.req_inspector_new(
        { t = "keyis", str = "reqkey/one" },
        { t = "keyis", str = "reqkey/two" },
        { t = "keyis", str = "reqkey/three" }
    )

    mgreqkey:ready({
        n = "reqkey", f = function(rctx)
            return function(r)
                local one, two, three = mgreqkeyis_ins(r)
                return string.format("SERVER_ERROR one[%q] two[%q] three[%q]\r\n",
                    one, two, three)
            end
        end
    })

    local mgintres = mcp.funcgen_new()
    -- no handle: using mcp.internal()
    mgintres:ready({
        n = "intres", f = function(rctx)
            return function(r)
                --local key = r:key()
                local res = mcp.internal(r)
                local has_O, O, has_t, t = mgresflaga_ins(res)
                return string.format("SERVER_ERROR O[%q]: %s t[%q]: %q\r\n",
                    has_O, O, has_t, t)
            end
        end
    })

    local mgr = mcp.router_new({ map = {
        sepkey = mgsepkey,
        reshasf = mgreshasf,
        reqkey = mgreqkey,
        intres = mgintres,
    }})
    mcp.attach(mcp.CMD_MG, mgr)
end

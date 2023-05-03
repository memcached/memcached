function mcp_config_pools(oldss)
    mcp.backend_read_timeout(0.5)
    mcp.backend_connect_timeout(5)

    local srv = mcp.backend

    -- Single backend for zones to ease testing.
    -- For purposes of this config the proxy is always "zone 1" (z1)
    local b1 = srv('b1', '127.0.0.1', 11611)
    local b2 = srv('b2', '127.0.0.1', 11612)
    local b3 = srv('b3', '127.0.0.1', 11613)

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
        return mcp.internal(r)
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

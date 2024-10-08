-- get some information about the test being run from an external file
-- so we can modify ourselves.
function mcp_config_pools(old)
    return {}
end

function default_route(rctx, a)
    return function(req)
        return mcp.internal(req)
    end
end

function default_route_wrapper()
    local fgen = mcp.funcgen_new()

    fgen:ready({
        f = default_route,
        n = "default",
        a = {},
    })

    return fgen
end

function mcp_config_routes(zones)
    mcp.attach(mcp.CMD_ANY_STORAGE, default_route_wrapper())
end

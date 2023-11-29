
verbose = true

function say(...)
    if verbose then
        print(...)
    end
end

function mcp_config_pools()
    local srv = mcp.backend
    local b1 = srv('b1', '127.0.0.1', 12021)
    return mcp.pool({b1})
end

function factory(rctx, h)
    return function(r)
        return rctx:queue_and_wait(r, h)
    end
end

function d_factory(rctx)
    return function(r)
        return "SERVER_ERROR default route\r\n"
    end
end

-- TODO: make default path and some other paths that return static data
function mcp_config_routes(p)
    local fg = mcp.funcgen_new()
    local fgh = fg:queue_assign(p)
    fg:ready({ f = factory, a = fgh })

    local def_fg = mcp.funcgen_new()
    def_fg:ready({ f = d_factory })

    local map = {
        ["one"] = fg,
        ["two"] = fg,
    }

    local rpfx_short = mcp.router_new({ map = map, mode = "prefix", stop = "|", default = def_fg })
    local rpfx_long = mcp.router_new({ map = map, mode = "prefix", stop = "+#+", default = def_fg })
    local ranc_short = mcp.router_new({ map = map, mode = "anchor", start = "_", stop = ",", default = def_fg })
    local ranc_long = mcp.router_new({ map = map, mode = "anchor", start = "=?=", stop = "__", default = def_fg })

    mcp.attach(mcp.CMD_MG, rpfx_short)
    mcp.attach(mcp.CMD_MS, rpfx_long)
    mcp.attach(mcp.CMD_MD, ranc_short)
    mcp.attach(mcp.CMD_MA, ranc_long)
end

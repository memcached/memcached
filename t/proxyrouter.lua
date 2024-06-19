
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
        return rctx:enqueue_and_wait(r, h)
    end
end

function d_factory(rctx)
    return function(r)
        return "SERVER_ERROR default route\r\n"
    end
end

function string_fgen(msg)
    local fg = mcp.funcgen_new()
    fg:ready({ f = function(rctx)
        return function(r)
            return msg
        end
    end})
    return fg
end

-- TODO: make default path and some other paths that return static data
function mcp_config_routes(p)
    local fg = mcp.funcgen_new()
    local fgh = fg:new_handle(p)
    fg:ready({ f = factory, a = fgh })

    local def_fg = mcp.funcgen_new()
    def_fg:ready({ f = d_factory })

    local map = {
        ["one"] = fg,
        ["two"] = fg,
        ["cmd"] = { [mcp.CMD_GET] = string_fgen("SERVER_ERROR cmd_get\r\n"),
            [mcp.CMD_SET] = string_fgen("SERVER_ERROR cmd_set\r\n") },
        ["cmdd"] = { [mcp.CMD_ANY_STORAGE] = string_fgen("SERVER_ERROR cmd_default\r\n"), },
    }

    local cmap = {
        [mcp.CMD_INCR] = string_fgen("SERVER_ERROR cmap incr\r\n"),
        [mcp.CMD_DECR] = string_fgen("SERVER_ERROR cmap decr\r\n")
    }

    local rpfx_short = mcp.router_new({ map = map, cmap = cmap, mode = "prefix", stop = "|", default = def_fg })
    local rpfx_long = mcp.router_new({ map = map, mode = "prefix", stop = "+#+", default = def_fg })
    local ranc_short = mcp.router_new({ map = map, mode = "anchor", start = "_", stop = ",", default = def_fg })
    local ranc_long = mcp.router_new({ map = map, mode = "anchor", start = "=?=", stop = "__", default = def_fg })

    local cmap_only = mcp.router_new({
        cmap = {
            [mcp.CMD_GETS] = string_fgen("SERVER_ERROR cmap_only gets\r\n")
        },
        default = string_fgen("SERVER_ERROR cmap_only default\r\n"),
    })

    mcp.attach(mcp.CMD_ANY_STORAGE, rpfx_short)
    mcp.attach(mcp.CMD_MG, rpfx_short)
    mcp.attach(mcp.CMD_MS, rpfx_long)
    mcp.attach(mcp.CMD_MD, ranc_short)
    mcp.attach(mcp.CMD_MA, ranc_long)
    mcp.attach(mcp.CMD_GETS, cmap_only)
    mcp.attach(mcp.CMD_GAT, cmap_only)
end

-- using mcp.internal() with extstore

function new_splitter(afg, bfg)
    local fg = mcp.funcgen_new()
    local h_a = fg:new_handle(afg)
    local h_b = fg:new_handle(bfg)

    fg:ready({ f = function(rctx)
        return function(r)
            rctx:enqueue(r, h_a)
            rctx:enqueue(r, h_b)
            rctx:wait_cond(2, mcp.WAIT_ANY)
            return rctx:res_any(h_a)
        end
    end
    })

    return fg
end

function mcp_config_pools()
end

function mcp_config_routes()
    local mfg = mcp.funcgen_new()
    mfg:ready({ f = function(rctx)
            return function(r)
                return mcp.internal(r)
            end
        end
    })

    -- test running internal from subrctx's
    local split = new_splitter(mfg, mfg)

    local map = {
        ["top"] = mfg,
        ["split"] = split,
    }

    local router = mcp.router_new({ map = map })

    mcp.attach(mcp.CMD_ANY_STORAGE, router)
end

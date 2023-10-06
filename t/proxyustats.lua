-- get some information about the test being run from an external file
-- so we can modify ourselves.
local config = dofile("/tmp/proxyustats.lua")

local idx = 1

function mcp_config_pools(old)
    mcp.backend_read_timeout(4)
    mcp.backend_connect_timeout(5)
    local pfx, f, l = string.match(config, "(%S+)%s*(%S+)%s*(%S+)")
    if pfx == "mask1" then
        mcp.add_stat(1, "maska")
        mcp.add_stat(2, "maskb")
    elseif pfx == "mask2" then
        mcp.add_stat(1, "")
        mcp.add_stat(2, "maskb")
    else
        local first = tonumber(f)
        local last = tonumber(l)
        while first <= last do
            mcp.add_stat(first, pfx .. first)
            first = first + 1
        end
    end

    return {}
end

function route_fn(zones)
    return function(r)
        local key = r:key()
        mcp.stat(math.abs(tonumber(key)), tonumber(key))
        return "HD\r\n"
    end
end

function mcp_config_routes(zones)
    mcp.attach(mcp.CMD_MG, route_fn(zones))
end

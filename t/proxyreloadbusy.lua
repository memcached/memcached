-- the test writes "<name> <seconds>" into an external file before each
-- reload. The config thread spends <seconds> in mcp_config_pools(), which
-- stands in for a large config or slow name resolution.
local config = dofile("/tmp/proxyreloadbusy.lua")

function mcp_config_pools(old)
    local name, busy = string.match(config, "(%S+)%s+(%S+)")
    local start = os.clock()
    while os.clock() - start < tonumber(busy) do end
    -- workers re-run this file, so hand them the name the config thread
    -- loaded instead of letting them read the file again.
    return { name = name }
end

function mcp_config_routes(c)
    local name = c.name
    mcp.attach(mcp.CMD_MG, function(r)
        return "SERVER_ERROR " .. name .. "\r\n"
    end)
end

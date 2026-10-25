-- the test writes the mode into an external file before each reload.
local mode = dofile("/tmp/proxyreloadfail.lua")

function mcp_config_pools(old)
    if mode == "pools_error" then
        error("mcp_config_pools failed on purpose")
    end
    return {}
end

function mcp_config_routes(c)
    if mode == "routes_error" then
        error("mcp_config_routes failed on purpose")
    end
    mcp.attach(mcp.CMD_MG, function(r)
        return "SERVER_ERROR " .. mode .. "\r\n"
    end)
end

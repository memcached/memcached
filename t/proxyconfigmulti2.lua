
function mcp_config_routes(p)
    mcp.attach(mcp.CMD_MG, function(r) return p(r) end)
end

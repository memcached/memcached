function mcp_config_pools()
    return true
end

function mcp_config_routes(p)
    mcp.attach(mcp.CMD_ANY_STORAGE, function(r)
        return mcp.internal(r)
    end)
end

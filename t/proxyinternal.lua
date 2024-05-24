function mcp_config_pools()
    return true
end

-- Do specialized testing based on the key prefix.
function mcp_config_routes(zones)
    mcp.attach(mcp.CMD_ANY_STORAGE, function(r)
        return mcp.internal(r)
    end)
end

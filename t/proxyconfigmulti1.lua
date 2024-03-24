
function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12111)
    return mcp.pool({b1})
end


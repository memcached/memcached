function mcp_config_pools()
    mcp.backend_read_timeout(0.25)
    mcp.backend_connect_timeout(0.5)
    mcp.backend_failure_limit(1)
    mcp.backend_retry_waittime(0.5) -- fast retry for test
    local b1 = mcp.backend('b1', '127.0.0.1', 12131)
    local b2 = mcp.backend('b2', '127.0.0.1', 12132)
    local b3 = mcp.backend('b3', '127.0.0.1', 12133)
    return mcp.pool({b1, b2, b3})
end

-- not making requests, just opening/closing backends
function mcp_config_routes(p)
    pool = p -- stash this in a global.
    mcp.attach(mcp.CMD_MG, function(r)
        return "SERVER_ERROR nothing\r\n"
    end)
end

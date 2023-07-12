if reload_count == nil then
    reload_count = 0
end

function mcp_config_pools()
    mcp.backend_read_timeout(0.25)
    mcp.backend_connect_timeout(5)
    mcp.backend_flap_time(30) -- need a long time to reset the flap counter
    mcp.backend_flap_backoff_ramp(1.2) -- very slow ramp
    mcp.backend_retry_waittime(1) -- a quick retry for the test.
    mcp.backend_failure_limit(2) -- reduced from default to speed up test.

    reload_count = reload_count + 1
    local arg = { label = 'b1', host = '127.0.0.1', port = 11799 }

    if reload_count == 1 then
        return mcp.pool({mcp.backend(arg)})
    elseif reload_count == 2 then
        mcp.backend_flap_time(2)
        return mcp.pool({mcp.backend(arg)})
    end
end

function mcp_config_routes(pool)
    mcp.attach(mcp.CMD_MG, function(r) return pool(r) end)
end

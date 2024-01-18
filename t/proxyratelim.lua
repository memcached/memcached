
function mcp_config_pools()
    local tbf_global = mcp.ratelim_global_tbf({limit = 25, fillrate = 5, tickrate = 500})
    return tbf_global
end

function mcp_config_routes(t)
    -- limit is an arbitrary token count (bytes, requests, etc)
    -- fillrate is tokens per tickrate
    -- tickrate is milliseconds
    local tbf = mcp.ratelim_tbf({limit = 50, fillrate = 4, tickrate = 500})

    local tbf_global = t

    mcp.attach(mcp.CMD_MG, function(r)
        if tbf(15) then
            return "HD\r\n"
        else
            return "SERVER_ERROR slow down\r\n"
        end
    end)

    mcp.attach(mcp.CMD_GET, function(r)
        if tbf_global(10) then
            return "END\r\n"
        else
            return "SERVER_ERROR global slow down\r\n"
        end
    end)
end


function mcp_config_pools()
    return {}
end

function mcp_config_routes(t)
    -- limit is an arbitrary token count (bytes, requests, etc)
    -- fillrate is tokens per tickrate
    -- tickrate is milliseconds
    local tbf = mcp.ratelim_tbf({limit = 50, fillrate = 4, tickrate = 500})

    mcp.attach(mcp.CMD_MG, function(r)
        if tbf(15) then
            return "HD\r\n"
        else
            return "SERVER_ERROR slow down\r\n"
        end
    end)
end

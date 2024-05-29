function mcp_config_pools()
    return true
end

local result_leak = {}
-- Do specialized testing based on the key prefix.
function mcp_config_routes(zones)
    mcp.attach(mcp.CMD_ANY_STORAGE, function(r)
        local cmd = r:command()
        if cmd == mcp.CMD_GET or cmd == mcp.CMD_MG then
            -- marking the object as <close> will clean up its internal
            -- references as soon as it drops out of scope.
            -- it is an error to try to use this 'res' outside of this 'if'
            -- statement!
            local res <close> = mcp.internal(r)
            local res2 = mcp.internal(r)
            res2:close() -- test manual closing.
            -- uncomment to test effects of leaking a res obj
            table.insert(result_leak, res)
        end
        return mcp.internal(r)
    end)
end

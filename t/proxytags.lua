-- get some information about the test being run from an external file
-- so we can modify ourselves.
local mode = dofile("/tmp/proxytagmode.lua")

function mcp_config_pools()
    -- we only ever need the one backend for this test.
    -- we're explicitly not testing for changes in the backend, but that
    -- routes are overwritten properly.
    local be = mcp.backend('be', '127.0.0.1', 12050)
    local p = mcp.pool({ be })
    return p
end

function mcp_config_routes(p)
    if mode == "start" then
        -- one without tag
        mcp.attach(mcp.CMD_MG, function(r) return p(r) end)
        -- no listener on a
        mcp.attach(mcp.CMD_MG, function(r) return "SERVER_ERROR tag A\r\n" end, "a")
        -- listener on b
        mcp.attach(mcp.CMD_MG, function(r) return "SERVER_ERROR tag B\r\n" end, "b")
        -- extra listener.
        mcp.attach(mcp.CMD_MG, function(r) return "SERVER_ERROR tag CCCC\r\n" end, "cccc")
    end
    -- TODO: reload to replace functions, ensure change.
    -- TODO: mcp.CMD_ANY_STORAGE on reload
    -- TODO: mcp.CMD_ANY_STORAGE and then replace a single CMD_MG
end

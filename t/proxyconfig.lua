-- get some information about the test being run from an external file
-- so we can modify ourselves.
local mode = dofile("/tmp/proxyconfigmode.lua")

function mcp_config_pools(old)
    mcp.backend_read_timeout(4)
    mcp.backend_connect_timeout(5)

    if mode == "none" then
        return {}
    elseif mode == "start" then
        local b1 = mcp.backend('b1', '127.0.0.1', 11511)
        local b2 = mcp.backend('b2', '127.0.0.1', 11512)
        local b3 = mcp.backend('b3', '127.0.0.1', 11513)

        local pools = {
            test = mcp.pool({b1, b2, b3})
        }
        return pools
    elseif mode == "betable" then
        local b1 = mcp.backend({ label = "b1", host = "127.0.0.1", port = 11511,
            connecttimeout = 2, retrytimeout = 5, readtimeout = 1,
            failurelimit = 0 })
        local b2 = mcp.backend({ label = "b2", host = "127.0.0.1", port = 11512,
            connecttimeout = 2, retrytimeout = 5, readtimeout = 5 })
        local b3 = mcp.backend({ label = "b3", host = "127.0.0.1", port = 11513,
            connecttimeout = 5, retrytimeout = 5, readtimeout = 5 })

        local pools = {
            test = mcp.pool({b1, b2, b3})
        }
        return pools
    elseif mode == "noiothread" then
        local b1 = mcp.backend('b1', '127.0.0.1', 11514)
        local b2 = mcp.backend('b2', '127.0.0.1', 11515)
        local b3 = mcp.backend('b3', '127.0.0.1', 11516)

        local pools = {
            test = mcp.pool({b1, b2, b3}, { iothread = false })
        }
        return pools
    elseif mode == "reqlimit" then
        mcp.active_req_limit(4)
        local b1 = mcp.backend('b1', '127.0.0.1', 11511)
        local b2 = mcp.backend('b2', '127.0.0.1', 11512)
        local b3 = mcp.backend('b3', '127.0.0.1', 11513)

        -- Direct all traffic at a single backend to simplify the test.
        local pools = {
            test = mcp.pool({b1}),
            hold = mcp.pool({b2, b3})
        }
        return pools
    elseif mode == "noreqlimit" then
        mcp.active_req_limit(0)
        local b1 = mcp.backend('b1', '127.0.0.1', 11511)
        local b2 = mcp.backend('b2', '127.0.0.1', 11512)
        local b3 = mcp.backend('b3', '127.0.0.1', 11513)

        -- Direct all traffic at a single backend to simplify the test.
        local pools = {
            test = mcp.pool({b1}),
            hold = mcp.pool({b2, b3})
        }
        return pools
    elseif mode == "buflimit" or mode == "buflimit2" then
        mcp.buffer_memory_limit(20)
        if mode == "buflimit2" then
            mcp.buffer_memory_limit(200)
        end
        local b1 = mcp.backend('b1', '127.0.0.1', 11511)
        local b2 = mcp.backend('b2', '127.0.0.1', 11512)
        local b3 = mcp.backend('b3', '127.0.0.1', 11513)

        -- Direct all traffic at a single backend to simplify the test.
        local pools = {
            test = mcp.pool({b1}),
            hold = mcp.pool({b2, b3})
        }
        return pools
    elseif mode == "nobuflimit" then
        mcp.buffer_memory_limit(0)
        local b1 = mcp.backend('b1', '127.0.0.1', 11511)
        local b2 = mcp.backend('b2', '127.0.0.1', 11512)
        local b3 = mcp.backend('b3', '127.0.0.1', 11513)

        -- Direct all traffic at a single backend to simplify the test.
        local pools = {
            test = mcp.pool({b1}),
            hold = mcp.pool({b2, b3})
        }
        return pools
    end
end

-- At least to start we don't need to test every command, but we should do
-- some tests against the two broad types of commands (gets vs sets with
-- payloads)
function mcp_config_routes(zones)
    if mode == "none" then
        mcp.attach(mcp.CMD_MG, function(r) return "SERVER_ERROR no mg route\r\n" end)
        mcp.attach(mcp.CMD_MS, function(r) return "SERVER_ERROR no ms route\r\n" end)
    else
        mcp.attach(mcp.CMD_MG, function(r) return zones["test"](r) end)
        mcp.attach(mcp.CMD_MS, function(r) return zones["test"](r) end)
    end
end

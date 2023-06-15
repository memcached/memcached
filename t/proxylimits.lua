-- need to use a global counter to avoid losing it on reload.
-- not really sure this'll work forever, but even if it doesn't I should allow
-- some method of persisting data across reloads.
if reload_count == nil then
    reload_count = 0
end

function mcp_config_pools(old)
    mcp.backend_read_timeout(4)
    mcp.backend_connect_timeout(5)
    reload_count = reload_count + 1

    if reload_count == 1 then
        -- set a low request limit.
        mcp.active_req_limit(4)
        local b1 = mcp.backend('b1', '127.0.0.1', 11711)
        local b2 = mcp.backend('b2', '127.0.0.1', 11712)
        local b3 = mcp.backend('b3', '127.0.0.1', 11713)

        -- Direct all traffic at a single backend to simplify the test.
        local pools = {
            test = mcp.pool({b1}),
            hold = mcp.pool({b2, b3})
        }
        return pools
    elseif reload_count == 2 then
        -- removing the request limit.
        mcp.active_req_limit(0)
        local b1 = mcp.backend('b1', '127.0.0.1', 11711)
        local b2 = mcp.backend('b2', '127.0.0.1', 11712)
        local b3 = mcp.backend('b3', '127.0.0.1', 11713)

        -- Direct all traffic at a single backend to simplify the test.
        local pools = {
            test = mcp.pool({b1}),
            hold = mcp.pool({b2, b3})
        }
        return pools
    elseif reload_count == 3 or reload_count == 4 then
        -- adding the memory buffer limit (abusrdly low)
        mcp.buffer_memory_limit(20)
        if reload_count == 4 then
            -- raise it a bit but still limited.
            mcp.buffer_memory_limit(200)
        end
        local b1 = mcp.backend('b1', '127.0.0.1', 11711)
        local b2 = mcp.backend('b2', '127.0.0.1', 11712)
        local b3 = mcp.backend('b3', '127.0.0.1', 11713)

        -- Direct all traffic at a single backend to simplify the test.
        local pools = {
            test = mcp.pool({b1}),
            hold = mcp.pool({b2, b3})
        }
        return pools
    elseif reload_count == 5 then
        -- remove the buffer limit entirely.
        mcp.buffer_memory_limit(0)
        local b1 = mcp.backend('b1', '127.0.0.1', 11711)
        local b2 = mcp.backend('b2', '127.0.0.1', 11712)
        local b3 = mcp.backend('b3', '127.0.0.1', 11713)

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
    mcp.attach(mcp.CMD_MG, function(r) return zones["test"](r) end)
    mcp.attach(mcp.CMD_MS, function(r) return zones["test"](r) end)
    mcp.attach(mcp.CMD_SET, function(r) return zones["test"](r) end)
    mcp.attach(mcp.CMD_GET, function(r) return zones["test"](r) end)
end

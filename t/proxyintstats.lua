function check_stats(cmd, min)
    local s
    if cmd then
        s = mcp.server_stats(cmd)
    else
        s = mcp.server_stats()
        cmd = "basic"
    end

    local count = 0
    for k, v in pairs(s) do
        count = count + 1
    end

    if min and count < min then
        mcp.log("ERROR: ["..cmd.."] count too low: " .. count)
    else
        mcp.log("SUCCESS: " .. cmd)
    end
end

function check_stats_sections(cmd, minsec, minval)
    local s = mcp.server_stats(cmd)

    local sec = 0
    local val = 0
    for k, v in pairs(s) do
        if type(k) == "number" then
            sec = sec + 1
            for sk, sv in pairs(v) do
                val = val + 1
            end
        else
            -- not a section.
        end
    end

    if minsec and sec < minsec then
        mcp.log("ERROR: ["..cmd.."] section count too low: " .. count)
        return
    end

    if minval and val < minval then
        mcp.log("ERROR: ["..cmd.."] value count too low: " .. count)
        return
    end

    mcp.log("SUCCESS: " .. cmd)
end

function mcp_config_pools()
    -- ensure that ustats print without crash/etc
    mcp.add_stat(1, "foo")
    mcp.add_stat(2, "bar")
    -- delay the stats run by a few seconds since some counters are weird
    -- until initialization completes.
    mcp.register_cron("stats", { every = 2, rerun = false, func = function()
        check_stats(nil, 10)
        check_stats("settings", 10)
        check_stats_sections("conns", 1, 2)
        check_stats("extstore")
        check_stats("proxy", 1)
        check_stats("proxyfuncs", 1)
        check_stats("proxybe")
        check_stats_sections("items", 1, 5)
        check_stats_sections("slabs", 1, 5)
    end })
end

function mcp_config_routes(c)
    mcp.attach(mcp.CMD_ANY_STORAGE, function(r)
        return mcp.internal(r)
    end)
end

function set_crons()
    mcp.register_cron("foo",
        { every = 2, func = function()
            foo_run = 1
        end })

    mcp.register_cron("reload",
        { every = 3, func = function()
            if foo_run and once_run then
                mcp.schedule_config_reload()
            end
        end })

    -- will run once per reload.
    mcp.register_cron("once",
        { every = 1, rerun = false, func = function()
            once_run = 1
        end })
end

function set_crons2()
    mcp.register_cron("bar",
        { every = 2, func = function()
            bar_run = 1
        end })

    mcp.register_cron("reload",
        { every = 3, func = function()
            -- ensure the old crons didn't also run.
            if bar_run and not foo_run and once_again and not once_run then
                mcp.schedule_config_reload()
            end
        end })

    -- will run once per reload.
    mcp.register_cron("onceagain",
        { every = 3, rerun = false, func = function()
            once_again = 1
        end })
end

function mcp_config_pools()
    if foo_run == nil then
        set_crons()
    else
        foo_run = nil
        once_run = nil
        set_crons2()
    end
end

function mcp_config_routes()
    -- do nothing.
end

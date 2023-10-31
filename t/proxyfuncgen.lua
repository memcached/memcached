-- New style request factories and backend request handling.
-- WARNING: UNDER DEVELOPMENT. MAY STILL CHANGE.
-- (though hopefully only subtly)
--
-- Please look at the examples below, and refer to the API notes here if
-- necessary.
--
-- First, this API adds a "request func generation" step when a new request
-- starts: if there is not already a cached function to use, call the
-- "generator" function, then use the response to run the request. This generated
-- function is reused until the parent generator is swapped out during reload.
-- This allows the user to pre-allocate and pre-calculate objects and data,
-- offering both safety and performance.
-- Future API revisions (such as stats) will rely on this generation step to
-- be more user friendly while retaining performance.
--
-- For backend IO's this unifies what was once two API's:
--  - result = pool(request): the non-async API
--  - table = mcp.await(etc)
--
-- It is now a single system governeed by a request context object (rctx).
-- This new system allows queueing a nearly arbitrary set of requests,
-- "blocking" a client on any individual response, and using callbacks to
-- make decisions on if a response is "good", to resume processing early, or
-- post-process once all responses are received.
--
-- The queueing system is now recursive: a fgen can queue_assign() another fgen.
-- Meaning configurations can be assembled as call graphs. IE: If you have a
-- route function A and want to "shadow" some of its requests onto route
-- function B, instead of making A more complex you can create a third
-- function C which splits the traffic.
--
-- This is demonstrated below with the prefix factory.
--
-- API:
-- fgen = mcp.funcgen_new({ func = generator, arg = a, max_queues = n})
--  - creates a new factory object. pass this object as the function argument
--  to mcp.attach() or rctx:queue_assign.
--
-- handle = rctx:queue_assign(pool||funcgen, [cb])
--  - to be called from the factory generator function, pre-assigns a pool or
--  child fgen and optional callback function. returns a handle.
--
-- rctx:queue(r, handle || table)
--  - to be called from the request function, queues up a request against the
--  designated slot handle, or an array style table of N handles
--
-- res = rctx:wait_handle(r, h)
--  - Directly returns a single result object after asynchronously waiting on
--  a specified queued handle.
--
-- num_good = rctx:wait_for(count, mode)
--  - Asynchronously waits for up to "count" results out of all currently
--  queued handles. Takes a mode to filter for valid responses to count:
--  - mcp.WAIT_OK, WAIT_GOOD, WAIT_ANY
--
-- rctx:good(handle)
--  - returns result object if the queue response was considered "Good", else
--  nil.
-- rctx:any(handle)
--  - same but "WAIT_ANY"
-- rctx:ok(handle)
--  - same but "WAIT_OK"

verbose = true
-- global for an error handling test
failgen_armed = false
failgenret_armed = false

function say(...)
    if verbose then
        print(...)
    end
end

function mcp_config_pools()
    local srv = mcp.backend

    local b1 = srv('b1', '127.0.0.1', 12011)
    local b2 = srv('b2', '127.0.0.1', 12012)
    local b3 = srv('b3', '127.0.0.1', 12013)
    local b4 = srv('b4', '127.0.0.1', 12014)
    local b1z = mcp.pool({b1})
    local b2z = mcp.pool({b2})
    local b3z = mcp.pool({b3})
    local b4z = mcp.pool({b4})
    local p = {p = {b1z, b2z, b3z}, b = b4z}

    --return mcp.pool(b1z, { iothread = false })
    return p
end

function prefix_factory(rctx, arg)
    local p = arg.pattern
    local d = rctx:queue_assign(arg.default)
    local map = {}

    say("generating a prefix factory function")
    -- get handler ids for each sub-route value
    -- convert the map.
    for k, v in pairs(arg.list) do
        map[k] = rctx:queue_assign(v)
    end

    return function(r)
        local key = r:key()
        -- failure scenarios that require a top-level request context
        if key == "reterror" then
            error("test error")
        elseif key == "retnil" then
            return nil
        elseif key == "retint" then
            return 5
        elseif key == "retnone" then
            return
        end

        local handle = map[string.match(key, p)]
        if handle == nil then
            return rctx:wait_handle(r, d)
        end
        return rctx:wait_handle(r, handle)
    end
end

function direct_factory(rctx, arg)
    say("generating direct factory function")
    local h = rctx:queue_assign(arg)

    return function(r)
        say("waiting on a single pool")
        return rctx:wait_handle(r, h)
    end
end

-- factory for proving slots have unique environmental memory.
function locality_factory(rctx, arg)
    say("generating locality factory function")
    local x = 0

    return function(r)
        say("returning from locality")
        x = x + 1
        return "HD t" .. x .. "\r\n"
    end
end

-- waits for only the _first_ queued handle to return.
-- ie; position 1 in the table.
-- we do a numeric for loop in the returned function to avoid allocations done
-- by a call to pairs()
function first_factory(rctx, arg)
    say("generating first factory function")
    local t = {}
    local count = 0

    for _, v in pairs(arg) do
        table.insert(t, rctx:queue_assign(v))
        count = count + 1
    end

    return function(r)
        say("waiting on first of " .. count .. " pools")
        for x=1, count do
            rctx:queue(r, t[x])
        end

        return rctx:wait_handle(r, t[1])
    end
end

-- wait on x out of y
function partial_factory(rctx, arg)
    say("generating partial factory function")
    local t = {}
    local count = 0
    local wait = arg.wait

    for _, v in pairs(arg.list) do
        table.insert(t, rctx:queue_assign(v))
        count = count + 1
    end

    return function(r)
        say("waiting on first " .. wait .. " out of " .. count)
        for x=1, count do
            rctx:queue(r, t[x])
        end

        local done = rctx:wait_for(wait)
        for x=1, count do
            -- :good will only return the result object if the handle's
            -- response was considered "good"
            local res = rctx:good(t[x])
            if res ~= nil then
                say("found a result")
                return res
            end
            -- TODO: tally up responses and send summary for test.
        end
        say("found nothing")
        -- didn't return anything good, so return one at random.
        for x=1, count do
            local res = rctx:any(t[x])
            if res ~= nil then
                return res
            end
        end
    end
end

-- wait on all pool arguments
function all_factory(rctx, arg)
    say("generating all factory function")
    local t = {}
    local count = 0
    -- should be a minor speedup avoiding the table lookup.
    local mode = mcp.WAIT_ANY

    for _, v in pairs(arg.list) do
        table.insert(t, rctx:queue_assign(v))
        count = count + 1
    end

    return function(r)
        say("waiting on " .. count)

        rctx:queue(r, t)
        local done = rctx:wait_for(count, mode)
        -- :any will give us the result object for that handle, regardless
        -- of return code/status.
        local res = rctx:any(t[1])

        -- TODO: tally up the responses and return summary for test.
        return res
    end
end

-- wait on the first good or N of total
function fastgood_factory(rctx, arg)
    say("generating fastgood factory function")
    local t = {}
    local count = 0
    local wait = arg.wait

    local cb = function(res)
        say("running in a callback!")
        if res:hit() then
            say("was a hit!")
            -- return an extra arg telling us to shortcut the wait count
            return mcp.WAIT_GOOD, mcp.WAIT_RESUME
        end
        -- default return code is mcp.WAIT_ANY
    end

    for _, v in pairs(arg.list) do
        table.insert(t, rctx:queue_assign(v, cb))
        count = count + 1
    end

    return function(r)
        say("first good or wait for N")

        rctx:queue(r, t)
        local done = rctx:wait_for(wait, mcp.WAIT_GOOD)
        say("fastgood done:", done)

        if done == 1 then
            -- if we just got one "good", we're probably happy.
            for x=1, count do
                -- loop to find the good handle.
                local res = rctx:good(t[x])
                if res ~= nil then
                    return res
                end
            end
        else
            -- else we had to wait and now need to decide if it was a miss or
            -- network error.
            -- but for this test we'll just return the first result.
            for x=1, count do
                local res = rctx:any(t[x])
                if res ~= nil then
                    return res
                end
            end
        end
    end
end

-- queue a bunch, but shortcut if a special auxiliary handle fails
function blocker_factory(rctx, arg)
    say("generating blocker factory function")
    local t = {}
    local count = 0
    local was_blocked = false

    local cb = function(res)
        -- check the response or tokens or anything special to indicate
        -- success.
        -- for this test we just check if it was a hit.
        if res:hit() then
            was_blocked = false
            return mcp.WAIT_GOOD
        else
            was_blocked = true
            return mcp.WAIT_ANY
        end
    end

    local blocker = rctx:queue_assign(arg.blocker, cb)

    for _, v in pairs(arg.list) do
        table.insert(t, rctx:queue_assign(v))
        count = count + 1
    end

    return function(r)
        say("function blocker test")

        -- queue up the real queries we wanted to run.
        rctx:queue(r, t)

        -- any wait command will execute all queued queries at once, but here
        -- we only wait for the blocker to complete.
        -- we also use wait_handle() to implicitly queue the blocker handle.
        local bres = rctx:wait_handle(r, blocker)

        -- another way of doing this is to ask:
        -- local res = rctx:good(blocker)
        -- if a result was returned, the callback had returned WAIT_GOOD
        if was_blocked == false then
            -- our blocker is happy...
            -- wait for the rest of the handles to come in and make a decision
            -- on what to return to the client.
            local done = rctx:wait_for(count, mcp.WAIT_ANY)
            return rctx:any(t[1])
        else
            return "SERVER_ERROR blocked\r\n"
        end
    end
end

-- log on all callbacks, even if waiting for 1
function logall_factory(rctx, arg)
    say("generating logall factory function")
    local t = {}

    local cb = function(res)
        say("received a response, logging...")
        mcp.log("received a response: " .. tostring(res:ok()))
        return mcp.WAIT_ANY
    end

    for _, v in pairs(arg.list) do
        table.insert(t, rctx:queue_assign(v, cb))
    end

    return function(r)
        rctx:queue(r, t)
        return rctx:wait_handle(r, t[1])
    end
end

-- log a summary after all callbacks run
function summary_factory(rctx, arg)
    say("generating summary factory function")
    local t = {}
    local count = 0

    local todo = 0
    local cb = function(res)
        say("responses TODO: " .. todo)
        todo = todo - 1
        if todo == 0 then
            mcp.log("received all responses")
        end
    end

    for _, v in pairs(arg.list) do
        table.insert(t, rctx:queue_assign(v, cb))
        count = count + 1
    end

    return function(r)
        -- re-seed the todo value that the callback uses
        todo = count

        rctx:queue(r, t)
        -- we're just waiting for a single response, but we queue all of the
        -- handles. the callback uses data from the shared environment and a
        -- summary is logged.
        return rctx:wait_handle(r, t[1])
    end
end

-- testing various waitfor conditions.
function waitfor_factory(rctx, arg)
    say("generating background factory function")
    local t = {}
    local count = 0
    for _, v in pairs(arg.list) do
        table.insert(t, rctx:queue_assign(v))
        count = count + 1
    end

    return function(r)
        local key = r:key()
        if key == "/waitfor/a" then
            rctx:queue(r, t)
            rctx:wait_for(0) -- issue the requests in the background
            return "HD t1\r\n" -- return whatever to the client
        elseif key == "/waitfor/b" then
            rctx:queue(r, t)
            rctx:wait_for(0) -- issue requests and resume
            -- now go back into wait mode, but we've already dispatched
            local done = rctx:wait_for(2)
            if done ~= 2 then
                return "SERVER_ERROR invalid wait"
            end
            -- TODO: bonus points, count the goods or check that everyone's t
            -- flag is right.
            for x=1, count do
                local res = rctx:good(x)
                if res ~= nil then
                    return res
                end
                return "SERVER_ERROR no good response"
            end
        elseif key == "/waitfor/c" then
            rctx:queue(r, t[1])
            rctx:wait_for(0) -- issue the first queued request
            -- queue two more
            rctx:queue(r, t[2])
            rctx:queue(r, t[3])
            -- wait explicitly for the first queued one.
            return rctx:wait_handle(r, t[1])
        elseif key == "/waitfor/d" then
            -- queue two then wait on each individually
            rctx:queue(r, t[1])
            rctx:queue(r, t[2])
            rctx:wait_handle(r, t[1])
            return rctx:wait_handle(r, t[2])
        end
    end
end

-- try "primary zone" and then fail over to secondary zones.
-- using simplified code that just treats the first pool as the primary zone.
function failover_factory(rctx, arg)
    say("generating failover factory function")
    local t = {}
    local count = 0
    for _, v in pairs(arg.list) do
        count = count + 1
    end
    local first = rctx:queue_assign(arg.list[1])

    for x=2, count do
        table.insert(t, rctx:queue_assign(arg.list[x]))
    end

    return function(r)
        -- first try local
        local fres = rctx:wait_handle(r, first)

        if fres == nil or fres:hit() == false then
            -- failed to get a local hit, queue all "far" zones.
            rctx:queue(r, t)
            -- wait for one.
            local done = rctx:wait_for(1, mcp.WAIT_GOOD)
            -- find the good from the second set.
            for x=1, count-1 do
                local res = rctx:good(t[x])
                if res ~= nil then
                    say("found a result")
                    return res
                end
            end
            -- got nothing from second set, just return anything.
            return rctx:any(first)
        else
            return fres
        end
    end
end

function suberrors_factory(rctx)
    say("generating suberrors factory function")

    return function(r)
        local key = r:key()
        if key == "/suberrors/error" then
            error("test error")
        elseif key == "/suberrors/nil" then
            return nil
        elseif key == "/suberrors/int" then
            return 5
        elseif key == "/suberrors/none" then
            return
        end

    end
end

-- example of a factory that takes two other factories and copies traffic
-- across them.
-- If an additional API's for hashing to numerics are added, keys can be
-- hashed to allow "1/n" of keys to copy to one of the splits. This allows
-- shadowing traffic to new/experimental pools, slow-warming traffic, etc.
function split_factory(rctx, arg)
    say("generating split factory function")
    local a = rctx:queue_assign(arg.a)
    local b = rctx:queue_assign(arg.b)

    return function(r)
        say("splitting traffic")
        -- b is the split path.
        rctx:queue(r, b)

        -- a is the main path. so we only explicitly wait on and return a.
        return rctx:wait_handle(r, a)
    end
end

-- test handling of failure to generate a function slot
function failgen_factory(rctx)
    if failgen_armed then
        say("throwing failgen error")
        error("failgen")
    end
    say("arming failgen")
    failgen_armed = true

    return function(r)
        return "NF\r\n"
    end
end

function failgenret_factory(rctx)
    if failgenret_armed then
        return nil
    end
    failgenret_armed = true

    return function(r)
        return "NF\r\n"
    end
end

-- TODO: this might be supported only in a later update.
-- new queue after parent return
-- - do an immediate return + cb queue, queue from that callback
-- - should still work but requires worker lua vm
-- requires removing the need of having an active client socket object to
-- queue new requests for processing.
function postreturn_factory(rctx, arg)

end

-- TODO: demonstrate a split call graph
-- ie; an all split into two single

function mcp_config_routes(p)
    local b_pool = p.b
    p = p.p
    local single = mcp.funcgen_new({ func = direct_factory, arg = p[1], max_queues = 1, name = "single" })
    -- use the typically unused backend.
    local singletwo = mcp.funcgen_new({ func = direct_factory, arg = b_pool, max_queues = 1, name = "singletwo" })

    local first = mcp.funcgen_new({ func = first_factory, arg = p, max_queues = 3, name = "first" })
    local partial = mcp.funcgen_new({ func = partial_factory, arg = { list = p, wait = 2 }, max_queues = 3, name = "partial" })
    local all = mcp.funcgen_new({ func = all_factory, arg = { list = p }, max_queues = 3, name = "all"})
    local fastgood = mcp.funcgen_new({ func = fastgood_factory, arg = { list = p, wait = 2 }, max_queues = 3, name = "fastgood"})
    local blocker = mcp.funcgen_new({ func = blocker_factory, arg = { blocker = b_pool, list = p }, max_queues = 4, name = "blocker"})
    local logall = mcp.funcgen_new({ func = logall_factory, arg = { list = p }, max_queues = 3, name = "logall"})
    local summary = mcp.funcgen_new({ func = summary_factory, arg = { list = p }, max_queues = 3, name = "summary"})
    local waitfor = mcp.funcgen_new({ func = waitfor_factory, arg = { list = p }, max_queues = 3, name = "waitfor"})
    local failover = mcp.funcgen_new({ func = failover_factory, arg = { list = p }, max_queues = 3, name = "failover"})
    local suberrors = mcp.funcgen_new({ func = suberrors_factory, max_queues = 3, name = "suberrors"})
    local locality = mcp.funcgen_new({ func = locality_factory, max_queues = 1, name = "locality"})
    local failgen = mcp.funcgen_new({ func = failgen_factory, max_queues = 1, name = "failgen"})
    local failgenret = mcp.funcgen_new({ func = failgenret_factory, max_queues = 1, name = "failgenret"})

    -- for testing traffic splitting.
    local split = mcp.funcgen_new({ func = split_factory, arg = { a = single, b = singletwo }, max_queues = 2, name = "split"})
    local splitfailover = mcp.funcgen_new({ func = split_factory, arg = { a = failover, b = singletwo }, max_queues = 2, name = "splitfailover"})

    local map = {
        ["single"] = single,
        ["first"] = first,
        ["partial"] = partial,
        ["all"] = all,
        ["fastgood"] = fastgood,
        ["blocker"] = blocker,
        ["logall"] = logall,
        ["summary"] = summary,
        ["waitfor"] = waitfor,
        ["failover"] = failover,
        ["suberrors"] = suberrors,
        ["split"] = split,
        ["splitfailover"] = splitfailover,
        ["locality"] = locality,
    }

    local parg = {
        default = single,
        list = map,
        pattern = "^/(%a+)/"
    }

    local mapfail = {
        ["failgen"] = failgen,
        ["failgenret"] = failgenret,
    }
    local farg = {
        default = single,
        list = mapfail,
        pattern = "^/(%a+)/"
    }

    local pfx = mcp.funcgen_new({ func = prefix_factory, arg = parg, max_queues = 24, name = "prefix" })
    local pfxfail = mcp.funcgen_new({ func = prefix_factory, arg = farg, max_queues = 24, name = "prefixfail" })

    mcp.attach(mcp.CMD_ANY_STORAGE, pfx)
    -- TODO: might need to move this fail stuff to another test file.
    mcp.attach(mcp.CMD_MS, pfxfail)
    mcp.attach(mcp.CMD_MD, pfxfail)
end

-- New style request factories and backend request handling.
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
-- The queueing system is now recursive: a fgen can new_handle() another fgen.
-- Meaning configurations can be assembled as call graphs. IE: If you have a
-- route function A and want to "shadow" some of its requests onto route
-- function B, instead of making A more complex you can create a third
-- function C which splits the traffic.
--
-- API docs: https://github.com/memcached/memcached/wiki/Proxy

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

-- many of these factories have the same basic init pattern, so we can save
-- some code.
function new_basic_factory(arg, func)
    local fgen = mcp.funcgen_new()
    local o = { t = {}, c = 0 }

    -- some of them have a wait, some don't.
    -- here would be a good place to do bounds checking on arguments in
    -- similar functions.
    o.wait = arg.wait
    for _, v in pairs(arg.list) do
        table.insert(o.t, fgen:new_handle(v))
        o.c = o.c + 1
    end

    fgen:ready({ f = func, a = o, n = arg.name})
    return fgen
end

function new_prefix_factory(arg)
    local fgen = mcp.funcgen_new()
    local o = {}
    o.pattern = arg.pattern
    o.default = fgen:new_handle(arg.default)

    o.map = {}
    -- get handler ids for each sub-route value
    -- convert the map.
    for k, v in pairs(arg.list) do
        o.map[k] = fgen:new_handle(v)
    end

    fgen:ready({ f = prefix_factory_gen, a = o, n = arg.name })
    return fgen
end

function prefix_factory_gen(rctx, arg)
    local p = arg.pattern
    local map = arg.map
    local d = arg.default

    say("generating a prefix factory function")

    return function(r)
        local key = r:key()

        local handle = map[string.match(key, p)]
        if handle == nil then
            return rctx:enqueue_and_wait(r, d)
        end
        return rctx:enqueue_and_wait(r, handle)
    end
end

function new_direct_factory(arg)
    local fgen = mcp.funcgen_new()
    local h = fgen:new_handle(arg.p)
    fgen:ready({ f = direct_factory_gen, a = h, n = arg.name })
    return fgen
end

function direct_factory_gen(rctx, h)
    say("generating direct factory function")

    return function(r)
        say("waiting on a single pool")
        return rctx:enqueue_and_wait(r, h)
    end
end

function new_locality_factory(arg)
    local fgen = mcp.funcgen_new()
    local h = fgen:new_handle(arg.p)
    fgen:ready({ f = locality_factory_gen, a = h, n = arg.name })
    return fgen
end

-- factory for proving slots have unique environmental memory.
-- we need to wait on a backend to allow the test to pipeline N requests in
-- parallel, to prove that each parallel slot has a unique lua environment.
function locality_factory_gen(rctx, h)
    say("generating locality factory function")
    local x = 0

    return function(r)
        x = x + 1
        say("returning from locality: " .. x)
        local res = rctx:enqueue_and_wait(r, h)
        return "HD t" .. x .. "\r\n"
    end
end

-- waits for only the _first_ queued handle to return.
-- ie; position 1 in the table.
-- we do a numeric for loop in the returned function to avoid allocations done
-- by a call to pairs()
function first_factory_gen(rctx, arg)
    say("generating first factory function")
    local t = arg.t
    local count = arg.c

    return function(r)
        say("waiting on first of " .. count .. " pools")
        for x=1, count do
            rctx:enqueue(r, t[x])
        end

        return rctx:wait_handle(t[1])
    end
end

-- wait on x out of y
function partial_factory_gen(rctx, arg)
    say("generating partial factory function")
    local t = arg.t
    local count = arg.c
    local wait = arg.wait

    return function(r)
        say("waiting on first " .. wait .. " out of " .. count)
        for x=1, count do
            rctx:enqueue(r, t[x])
        end

        local done = rctx:wait_cond(wait)
        for x=1, count do
            -- :good will only return the result object if the handle's
            -- response was considered "good"
            local res = rctx:res_good(t[x])
            if res ~= nil then
                say("found a result")
                return res
            end
            -- TODO: tally up responses and send summary for test.
        end
        say("found nothing")
        -- didn't return anything good, so return one at random.
        for x=1, count do
            local res = rctx:res_any(t[x])
            if res ~= nil then
                return res
            end
        end
    end
end

-- wait on all pool arguments
function all_factory_gen(rctx, arg)
    say("generating all factory function")
    local t = arg.t
    local count = arg.c
    -- should be a minor speedup avoiding the table lookup.
    local mode = mcp.WAIT_ANY

    return function(r)
        say("waiting on " .. count)

        rctx:enqueue(r, t)
        local done = rctx:wait_cond(count, mode)
        -- :any will give us the result object for that handle, regardless
        -- of return code/status.
        local res = rctx:res_any(t[1])

        -- TODO: tally up the responses and return summary for test.
        return res
    end
end

-- wait on the first good or N of total
function fastgood_factory_gen(rctx, arg)
    say("generating fastgood factory function")
    local t = arg.t
    local count = arg.c
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

    for _, v in pairs(t) do
        rctx:handle_set_cb(v, cb)
    end

    return function(r)
        say("first good or wait for N")

        rctx:enqueue(r, t)
        local done = rctx:wait_cond(wait, mcp.WAIT_GOOD)
        say("fastgood done:", done)

        if done == 1 then
            -- if we just got one "good", we're probably happy.
            for x=1, count do
                -- loop to find the good handle.
                local res = rctx:res_good(t[x])
                if res ~= nil then
                    return res
                end
            end
        else
            -- else we had to wait and now need to decide if it was a miss or
            -- network error.
            -- but for this test we'll just return the first result.
            for x=1, count do
                local res = rctx:res_any(t[x])
                if res ~= nil then
                    return res
                end
            end
        end
    end
end

-- fastgood implemented using internal fastgood state
function fastgoodint_factory_gen(rctx, arg)
    local t = arg.t
    local count = arg.c
    local wait = arg.wait

    return function(r)
        rctx:enqueue(r, t)
        local done = rctx:wait_cond(wait, mcp.WAIT_FASTGOOD)
        say("fastgoodint done:", done)

        local final = nil
        for x=1, count do
            local res, mode = rctx:result(t[x])
            if mode == mcp.WAIT_GOOD then
                return res
            elseif res ~= nil then
                final = res
            end
        end
        -- if no good found, return anything.
        return final
    end
end

function new_blocker_factory(arg)
    local fgen = mcp.funcgen_new()
    local o = { c = 0, t = {} }
    o.b = fgen:new_handle(arg.blocker)

    for _, v in pairs(arg.list) do
        table.insert(o.t, fgen:new_handle(v))
        o.c = o.c + 1
    end

    fgen:ready({ f = blocker_factory_gen, a = o, n = arg.name })
    return fgen
end

-- queue a bunch, but shortcut if a special auxiliary handle fails
function blocker_factory_gen(rctx, arg)
    say("generating blocker factory function")
    local t = arg.t
    local count = arg.c
    local blocker = arg.b
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

    rctx:handle_set_cb(blocker, cb)

    return function(r)
        say("function blocker test")

        -- queue up the real queries we wanted to run.
        rctx:enqueue(r, t)

        -- any wait command will execute all queued queries at once, but here
        -- we only wait for the blocker to complete.
        local bres = rctx:enqueue_and_wait(r, blocker)

        -- another way of doing this is to ask:
        -- local res = rctx:res_good(blocker)
        -- if a result was returned, the callback had returned WAIT_GOOD
        if was_blocked == false then
            -- our blocker is happy...
            -- wait for the rest of the handles to come in and make a decision
            -- on what to return to the client.
            local done = rctx:wait_cond(count, mcp.WAIT_ANY)
            return rctx:res_any(t[1])
        else
            return "SERVER_ERROR blocked\r\n"
        end
    end
end

-- log on all callbacks, even if waiting for 1
function logall_factory_gen(rctx, arg)
    say("generating logall factory function")
    local t = arg.t

    local cb = function(res, req)
        say("received a response, logging...")
        mcp.log("received a response: " .. tostring(res:ok()))
        mcp.log_req(req, res, "even more logs", rctx:cfd())
        return mcp.WAIT_ANY
    end

    for _, v in pairs(t) do
        rctx:handle_set_cb(v, cb)
    end

    return function(r)
        rctx:enqueue(r, t)
        return rctx:wait_handle(t[1])
    end
end

-- log a summary after all callbacks run
function summary_factory_gen(rctx, arg)
    say("generating summary factory function")
    local t = arg.t
    local count = arg.c

    local todo = 0
    local cb = function(res)
        say("responses TODO: " .. todo)
        todo = todo - 1
        if todo == 0 then
            mcp.log("received all responses")
        end
    end

    for _, v in pairs(t) do
        rctx:handle_set_cb(v, cb)
    end

    return function(r)
        -- re-seed the todo value that the callback uses
        todo = count

        rctx:enqueue(r, t)
        -- we're just waiting for a single response, but we queue all of the
        -- handles. the callback uses data from the shared environment and a
        -- summary is logged.
        return rctx:wait_handle(t[1])
    end
end

-- testing various waitfor conditions.
function waitfor_factory_gen(rctx, arg)
    say("generating background factory function")
    local t = arg.t
    local count = arg.c

    return function(r)
        local key = r:key()
        if key == "waitfor/a" then
            rctx:enqueue(r, t)
            rctx:wait_cond(0) -- issue the requests in the background
            return "HD t1\r\n" -- return whatever to the client
        elseif key == "waitfor/b" then
            rctx:enqueue(r, t)
            rctx:wait_cond(0) -- issue requests and resume
            -- now go back into wait mode, but we've already dispatched
            local done = rctx:wait_cond(2)
            if done ~= 2 then
                return "SERVER_ERROR invalid wait"
            end
            -- TODO: bonus points, count the goods or check that everyone's t
            -- flag is right.
            for x=1, count do
                local res = rctx:res_good(x)
                if res ~= nil then
                    return res
                end
                return "SERVER_ERROR no good response"
            end
        elseif key == "waitfor/c" then
            rctx:enqueue(r, t[1])
            rctx:wait_cond(0) -- issue the first queued request
            -- queue two more
            rctx:enqueue(r, t[2])
            rctx:enqueue(r, t[3])
            -- wait explicitly for the first queued one.
            return rctx:wait_handle(t[1])
        elseif key == "waitfor/d" then
            -- queue two then wait on each individually
            rctx:enqueue(r, t[1])
            rctx:enqueue(r, t[2])
            rctx:wait_handle(t[1])
            return rctx:wait_handle(t[2])
        end
    end
end

-- try "primary zone" and then fail over to secondary zones.
-- using simplified code that just treats the first pool as the primary zone.
function failover_factory_gen(rctx, arg)
    say("generating failover factory function")
    local t = {}
    local count = arg.c
    local first = arg.t[1]

    for x=2, count do
        table.insert(t, arg.t[x])
    end

    return function(r)
        -- first try local
        local fres = rctx:enqueue_and_wait(r, first)

        if fres == nil or fres:hit() == false then
            -- failed to get a local hit, queue all "far" zones.
            rctx:enqueue(r, t)
            -- wait for one.
            local done = rctx:wait_cond(1, mcp.WAIT_GOOD)
            -- find the good from the second set.
            for x=1, count-1 do
                local res = rctx:res_good(t[x])
                if res ~= nil then
                    say("found a result")
                    return res
                end
            end
            -- got nothing from second set, just return anything.
            return rctx:res_any(first)
        else
            return fres
        end
    end
end

function new_error_factory(func, name)
    local fgen = mcp.funcgen_new()
    fgen:ready({ f = func, n = name })
    return fgen
end

function errors_factory_gen(rctx)
    say("generating errors factory")

    return function(r)
        local key = r:key()
        -- failure scenarios that require a top-level request context
        if key == "errors/reterror" then
            error("test error")
        elseif key == "errors/retnil" then
            return nil
        elseif key == "errors/retint" then
            return 5
        elseif key == "errors/retnone" then
            return
        end
    end
end

function suberrors_factory_gen(rctx)
    say("generating suberrors factory function")

    return function(r)
        local key = r:key()
        if key == "suberrors/error" then
            error("test error")
        elseif key == "suberrors/nil" then
            return nil
        elseif key == "suberrors/int" then
            return 5
        elseif key == "suberrors/none" then
            return
        end

    end
end

function new_split_factory(arg)
    local fgen = mcp.funcgen_new()
    local o = {}
    o.a = fgen:new_handle(arg.a)
    o.b = fgen:new_handle(arg.b)
    fgen:ready({ f = split_factory_gen, a = o, n = name })
    return fgen
end

-- example of a factory that takes two other factories and copies traffic
-- across them.
-- If an additional API's for hashing to numerics are added, keys can be
-- hashed to allow "1/n" of keys to copy to one of the splits. This allows
-- shadowing traffic to new/experimental pools, slow-warming traffic, etc.
function split_factory_gen(rctx, arg)
    say("generating split factory function")
    local a = arg.a
    local b = arg.b

    return function(r)
        say("splitting traffic")
        -- b is the split path.
        rctx:enqueue(r, b)

        -- a is the main path. so we only explicitly wait on and return a.
        return rctx:enqueue_and_wait(r, a)
    end
end

-- test handling of failure to generate a function slot
function failgen_factory_gen(rctx)
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

function failgenret_factory_gen(rctx)
    if failgenret_armed then
        return nil
    end
    failgenret_armed = true

    return function(r)
        return "NF\r\n"
    end
end

function badreturn_gen(rctx)
    -- returning a userdata that isn't the correct kind of userdata.
    -- shouldn't crash the daemon!
    return function(r)
        return rctx
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
    local single = new_direct_factory({ p = p[1], name = "single" })
    -- use the typically unused backend.
    local singletwo = new_direct_factory({ p = b_pool, name = "singletwo" })

    local first = new_basic_factory({ list = p, name = "first" }, first_factory_gen)
    local partial = new_basic_factory({ list = p, wait = 2, name = "partial" }, partial_factory_gen)
    local all = new_basic_factory({ list = p, name = "all" }, all_factory_gen)
    local fastgood = new_basic_factory({ list = p, wait = 2, name = "fastgood" }, fastgood_factory_gen)
    local fastgoodint = new_basic_factory({ list = p, wait = 2, name = "fastgoodint" }, fastgoodint_factory_gen)
    local blocker = new_blocker_factory({ blocker = b_pool, list = p, name = "blocker" })
    local logall = new_basic_factory({ list = p, name = "logall" }, logall_factory_gen)
    local summary = new_basic_factory({ list = p, name = "summary" }, summary_factory_gen)
    local waitfor = new_basic_factory({ list = p, name = "waitfor" }, waitfor_factory_gen)
    local failover = new_basic_factory({ list = p, name = "failover" }, failover_factory_gen)
    local locality = new_locality_factory({ p = p[1], name = "locality" })

    local errors = new_error_factory(errors_factory_gen, "errors")
    local suberrors = new_error_factory(suberrors_factory_gen, "suberrors")
    local suberr_wrap = new_direct_factory({ p = suberrors, name = "suberrwrap" })
    local badreturn = new_error_factory(badreturn_gen, "badreturn")

    -- for testing traffic splitting.
    local split = new_split_factory({ a = single, b = singletwo, name = "split" })
    local splitfailover = new_split_factory({ a = failover, b = singletwo, name = "splitfailover" })

    local map = {
        ["single"] = single,
        ["first"] = first,
        ["partial"] = partial,
        ["all"] = all,
        ["fastgood"] = fastgood,
        ["fastgoodint"] = fastgoodint,
        ["blocker"] = blocker,
        ["logall"] = logall,
        ["summary"] = summary,
        ["waitfor"] = waitfor,
        ["failover"] = failover,
        ["suberrors"] = suberr_wrap,
        ["errors"] = errors,
        ["split"] = split,
        ["splitfailover"] = splitfailover,
        ["locality"] = locality,
        ["badreturn"] = badreturn,
    }

    local parg = {
        default = single,
        list = map,
        pattern = "^/(%a+)/"
    }

    local failgen = new_error_factory(failgen_factory_gen, "failgen")
    local failgenret = new_error_factory(failgenret_factory_gen, "failgenret")

    local mapfail = {
        ["failgen"] = failgen,
        ["failgenret"] = failgenret,
    }
    local farg = {
        default = single,
        list = mapfail,
        pattern = "^(%a+)/",
        name = "prefixfail"
    }

    local pfx = mcp.router_new({ map = map })
    local pfxfail = new_prefix_factory(farg)

    mcp.attach(mcp.CMD_ANY_STORAGE, pfx)
    -- TODO: might need to move this fail stuff to another test file.
    mcp.attach(mcp.CMD_MS, pfxfail)
    mcp.attach(mcp.CMD_MD, pfxfail)
end

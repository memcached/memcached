-- xTODO: sets of zones behind a prefix.
-- xTODO: zones with local vs other failover.
-- xTODO: failover on get
-- xTODO: all zone sync on set
-- TODO: fallback cache for broken/overloaded zones.

-- local zone could/should be fetched from environment or local file.
-- doing so allows all configuration files to be identical, simplifying consistency checks.
local my_zone = 'z1'

local STAT_EXAMPLE <const> = 1
local STAT_ANOTHER <const> = 2

function mcp_config_pools(oldss)
    mcp.add_stat(STAT_EXAMPLE, "example")
    mcp.add_stat(STAT_ANOTHER, "another")
    mcp.backend_connect_timeout(5) -- 5 second timeout.
    -- alias mcp.backend for convenience.
    -- important to alias global variables in routes where speed is concerned.
    local srv = mcp.backend
    -- local zones = { 'z1', 'z2', 'z3' }

    -- IPs are "127" . "zone" . "pool" . "srv"
    local pfx = 'fooz1'
    local fooz1 = {
        srv(pfx .. 'srv1', '127.1.1.1', 11212, 1),
        srv(pfx .. 'srv2', '127.1.1.2', 11212, 1),
        srv(pfx .. 'srv3', '127.1.1.3', 11212, 1),
    }
    pfx = 'fooz2'
    local fooz2 = {
        srv(pfx .. 'srv1', '127.2.1.1', 11213, 1),
        srv(pfx .. 'srv2', '127.2.1.2', 11213, 1),
        srv(pfx .. 'srv3', '127.2.1.3', 11213, 1),
    }
    pfx = 'fooz3'
    local fooz3 = {
        srv(pfx .. 'srv1', '127.3.1.1', 11214, 1),
        srv(pfx .. 'srv2', '127.3.1.2', 11214, 1),
        srv(pfx .. 'srv3', '127.3.1.3', 11214, 1),
    }

    pfx = 'barz1'
    -- zone "/bar/"-s primary zone should fail; all down.
    local barz1 = {
        srv(pfx .. 'srv1', '127.1.2.1', 11210, 1),
        srv(pfx .. 'srv2', '127.1.2.1', 11210, 1),
        srv(pfx .. 'srv3', '127.1.2.1', 11210, 1),
    }
    pfx = 'barz2'
    local barz2 = {
        srv(pfx .. 'srv1', '127.2.2.2', 11215, 1),
        srv(pfx .. 'srv2', '127.2.2.2', 11215, 1),
        srv(pfx .. 'srv3', '127.2.2.2', 11215, 1),
    }
    pfx = 'barz3'
    local barz3 = {
        srv(pfx .. 'srv1', '127.3.2.3', 11216, 1),
        srv(pfx .. 'srv2', '127.3.2.3', 11216, 1),
        srv(pfx .. 'srv3', '127.3.2.3', 11216, 1),
    }

    -- fallback cache for any zone
    -- NOT USED YET
    pfx = 'fallz1'
    local fallz1 = {
        srv(pfx .. 'srv1', '127.0.2.1', 11212, 1),
    }
    pfx = 'fallz2'
    local fallz2 = {
        srv(pfx .. 'srv1', '127.0.2.2', 11212, 1),
    }
    pfx = 'fallz3'
    local fallz3 = {
        srv(pfx .. 'srv1', '127.0.2.3', 11212, 1),
    }

    local main_zones = {
        foo = { z1 = fooz1, z2 = fooz2, z3 = fooz3 },
        bar = { z1 = barz1, z2 = barz2, z3 = barz3 },
        -- fall = { z1 = fallz1, z2 = fallz2, z3 = fallz3 },
    }

    -- FIXME: should we copy the table to keep the pool tables around?
    -- does the hash selector hold a reference to the pool (but only available in main config?)

    -- uncomment to use the ketama loadable module.
    -- FIXME: passing an argument to the ketama module doesn't work yet.
    -- local ketama = require("ketama")

    -- convert the pools into hash selectors.
    -- TODO: is this a good place to add prefixing/hash editing?
    for _, subs in pairs(main_zones) do
        for k, v in pairs(subs) do
            -- use next line instead for a third party ketama hash
            -- subs[k] = mcp.pool(v, { dist = ketama })
            -- this line overrides the default bucket size for ketama
            -- subs[k] = mcp.pool(v, { dist = ketama, obucket = 80 })
            -- this line uses the default murmur3 straight hash.
            subs[k] = mcp.pool(v)

            -- use this next line instead for jump hash.
            -- the order of servers in the pool argument _must_ not change!
            -- adding the seed string will give a different key distribution
            -- for each zone.
            -- NOTE: 'k' may not be the right seed here:
            -- instead stitch main_zone's key + the sub key?
            -- subs[k] = mcp.pool(v, { dist = mcp.hash_jump, seed = k })
        end
    end

    return main_zones
end

-- WORKER CODE:

-- need to redefine main_zones using fetched selectors?

-- TODO: Fallback zone here?
function failover_factory(zones, local_zone)
    local near_zone = zones[local_zone]
    local far_zones = {}
    -- NOTE: could shuffle/sort to re-order zone retry order
    -- or use 'next(far_zones, idx)' via a stored upvalue here
    for k, v in pairs(zones) do
        if k ~= local_zone then
            far_zones[k] = v
        end
    end
    return function(r)
        local res = near_zone(r)
        if res:hit() == false then
            for _, zone in pairs(far_zones) do
                res = zone(r)
                if res:hit() then
                    break
                end
            end
        end
        return res -- send result back to client
    end
end

-- SET's to main zone, issues deletes to far zones.
function setinvalidate_factory(zones, local_zone)
    local near_zone = zones[local_zone]
    local far_zones = {}
    -- NOTE: could shuffle/sort to re-order zone retry order
    -- or use 'next(far_zones, idx)' via a stored upvalue here
    for k, v in pairs(zones) do
        if k ~= local_zone then
            far_zones[k] = v
        end
    end
    local new_req = mcp.request
    return function(r)
        local res = near_zone(r)
        if res:ok() == true then
            -- create a new delete request
            local dr = new_req("delete /testing/" .. r:key() .. "\r\n")
            for _, zone in pairs(far_zones) do
                -- NOTE: can check/do things on the specific response here.
                zone(dr)
            end
        end
        -- use original response for client, not DELETE's response.
        -- else client won't understand.
        return res -- send result back to client
    end
end

-- NOTE: this function is culling key prefixes. it is an error to use it
-- without a left anchored (^) pattern.
function prefixtrim_factory(pattern, list, default)
    local p = pattern
    local l = list
    local d = default
    local s = mcp.stat
    return function(r)
        local i, j, match = string.find(r:key(), p)
        local route
        if match ~= nil then
            -- remove the key prefix so we don't waste storage.
            r:ltrimkey(j)
            route = l[match]
            if route == nil then
                -- example counter: tick when default route hit.
                s(STAT_EXAMPLE, 1)
                return d(r)
            end
        end
        return route(r)
    end
end

function prefix_factory(pattern, list, default)
    local p = pattern
    local l = list
    local d = default
    local s = mcp.stat
    return function(r)
        local route = l[string.match(r:key(), p)]
        if route == nil then
            -- example counter: tick when default route hit.
            s(STAT_EXAMPLE, 1)
            return d(r)
        end
        return route(r)
    end
end

-- TODO: Check tail call requirements?
function command_factory(map, default)
    local m = map
    local d = default
    return function(r)
        local f = map[r:command()]
        if f == nil then
            -- print("default command")
            return d(r)
        end
        -- testing options replacement...
        if r:command() == mcp.CMD_SET then
            r:token(4, "100") -- set exptime.
        end
        -- print("override command")
        return f(r)
    end
end

-- TODO: is the return value the average? anything special?
-- walks a list of selectors and repeats the request.
function walkall_factory(pool)
    local p = {}
    -- TODO: a shuffle could be useful here.
    for _, v in pairs(pool) do
        table.insert(p, v)
    end
    local x = #p
    return function(r)
        local restable = mcp.await(r, p)
        -- walk results and return "best" result
        -- print("length of await result table", #restable)
        for _, res in pairs(restable) do
            if res:ok() then
                return res
            end
        end
        -- else we return the first result.
        return restable[1]
    end
end

function mcp_config_routes(main_zones)
    -- generate the prefix routes from zones.
    local prefixes = {}
    for pfx, z in pairs(main_zones) do
        local failover = failover_factory(z, my_zone)
        local all = walkall_factory(main_zones[pfx])
        local setdel = setinvalidate_factory(z, my_zone)
        local map = {}
        map[mcp.CMD_SET] = all
        -- NOTE: in t/proxy.t all the backends point to the same place
        -- which makes replicating delete return NOT_FOUND
        map[mcp.CMD_DELETE] = all
        -- similar with ADD. will get an NOT_STORED back.
        -- need better routes designed for the test suite (edit the key
        -- prefix or something)
        map[mcp.CMD_ADD] = failover_factory(z, my_zone)
        prefixes[pfx] = command_factory(map, failover)
    end

    local routetop = prefix_factory("^/(%a+)/", prefixes, function(r) return "SERVER_ERROR no route\r\n" end)

    -- internally run parser at top of tree
    -- also wrap the request string with a convenience object until the C bits
    -- are attached to the internal parser.
    --mcp.attach(mcp.CMD_ANY, function (r) return routetop(r) end)
    mcp.attach(mcp.CMD_ANY_STORAGE, routetop)
end

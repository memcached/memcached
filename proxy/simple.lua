-- NOTE: Still missing a lot! works for basics.
-- If you want something here, please ask, as supporting all of the main
-- features is a goal, but I am adding them in a random order unless otherwise
-- informed.

-- https://stackoverflow.com/questions/9168058/how-to-dump-a-table-to-console
-- should probably get a really nice one of these for the library instead.
function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

-- NOTE: this function is culling key prefixes. it is an error to use it
-- without a left anchored (^) pattern.
function prefixtrim_factory(pattern, list, default)
    -- tag the start anchor so users don't have to remember.
    -- might want to test if it's there first? :)
    local p = "^" .. pattern
    local l = list
    local d = default
    return function(r)
        local i, j, match = string.find(r:key(), p)
        local route = nil
        if match ~= nil then
            -- remove the key prefix so we don't waste storage.
            r:ltrimkey(j)
            route = l[match]
        end
        if route == nil then
            return d(r)
        else
            return route(r)
        end
    end
end

function command_factory(map, default)
    local m = map
    local d = default
    return function(r)
        local f = map[r:command()]
        if f == nil then
            return d(r)
        end
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

-- TODO:
-- v6 formatting
function make_backend(host)
    print("making backend for... " .. host)
    local ip, port, name = string.match(host, "^(.+):(%d+)%s+(%a+)")
    if ip ~= nil then
        return mcp.backend(name, ip, port, 1)
    end
    local ip, port = string.match(host, "^(.+):(%d+)")
    if ip ~= nil then
        return mcp.backend(host, ip, port, 1)
    end
    error(host .. " is an invalid backend string")
end

function mcp_config_pools(old)
    local c = { pools = {} }
	local r = {
        router_type = "keyprefix",
        match_prefix = "/(%a+)/",
    }

    function pool(a) 
    	-- print(dump(a))
		c.pools[a.name] = a
	end
	function router(a)
		-- print(dump(a))
		r = a
	end
	function my_zone(zone)
		-- print(zone)
		c.my_zone = zone
	end
    dofile("./proxy/pooldata.lua")

	--print("read:\n")
    --print(dump(c), dump(r))
	-- convert config into backend and pool objects.
	local o = { pools = {} }

	-- mcp.pool(be)
    -- TODO: figure out inherited defaults to use for the mcp.pool arguments
    -- TODO: string match to mcp.backend() function
    for name, conf in pairs(c.pools) do
        local z = {}
        if c.my_zone == nil then
            local p = {}
            -- no zone configured, build pool from 'backends'
            for _, be in pairs(conf.backends) do
                -- string match for server.
                table.insert(p, make_backend(be))
            end
            -- drop into weird zone?
            z = mcp.pool(p)
        else
            -- TODO: error if a pool lacks a "my_zone" ?
            for zname, backends in pairs(conf.zones) do
                local p = {}
                for _, be in pairs(backends) do
                    -- parse backend
                    table.insert(p, make_backend(be))
                end
                z[zname] = mcp.pool(p)
            end
        end
        o.pools[name] = z
    end

    o.my_zone = c.my_zone

    -- TODO: figure out the router configuration bits
    o.r = r
    return o
end

-- TODO: r.default_pool instead of the SERVER_ERROR bit
function mcp_config_routes(c)
    -- print(dump(c))
    local default = c.r["default_pool"]
    if c.r["default_pool"] == nil then
        default = function(r) return "SERVER_ERROR no route\r\n" end
    end

    -- with a non-zoned configuration we can run with a completely flat config
    if c["my_zone"] == nil then
        print("setting up a zoneless route")
        local top = prefixtrim_factory(c.r.match_prefix, c.pools, default)
        mcp.attach(mcp.CMD_ANY_STORAGE, top)
    else
        -- else we have a more complex setup.
        local myz = c.my_zone
        print("setting up a zoned route. local: " .. myz)

        -- process each pool to have replicated zones.
        local pools = {}
        for name, zones in pairs(c.pools) do
            local failover = failover_factory(zones, myz)
            local all = walkall_factory(zones)
            -- TODO: flesh this out more; append/prepend/replace/etc?
            -- think a bit about good defaults?
            local map = {
                [mcp.CMD_ADD] = all,
                [mcp.CMD_SET] = all,
                [mcp.CMD_DELETE] = all,
            }
            pools[name] = command_factory(map, failover)
        end
        print(dump(pools))

        local top = prefixtrim_factory(c.r.match_prefix, pools, default)
        mcp.attach(mcp.CMD_ANY_STORAGE, top)
    end
end

-- key distributions that match java ketama clients.
-- each key prefix routes to a pool over the same four backends, with a
-- different omode and node identity.

function mcp_config_pools()
    local function backends(label, host, hashkeys)
        local list = {}
        for i = 1, 4 do
            local b = { label = label .. i, host = host, port = 12230 + i }
            if hashkeys then
                b.hashkey = hashkeys[i]
            end
            table.insert(list, mcp.backend(b))
        end
        return list
    end

    local spy = { dist = mcp.dist_ring_hash, omode = "spymemcached", hash = mcp.dist_ring_hash.hash }
    local pools = {
        -- spymemcached, backends configured by hostname: "localhost/127.0.0.1:port"
        sh = mcp.pool(backends("sh", "localhost"), spy),
        -- spymemcached, backends configured by IP: "127.0.0.1:port"
        si = mcp.pool(backends("si", "127.0.0.1"), spy),
    }
    if mcp.dist_ring_hash.hash_elasticache then
        local ec = { dist = mcp.dist_ring_hash, omode = "elasticache", hash = mcp.dist_ring_hash.hash_elasticache }
        -- elasticache-java-cluster-client: always "ip:port"
        pools.ec = mcp.pool(backends("ec", "127.0.0.1"), ec)
        -- node identity given explicitly instead of the backend address.
        pools.eh = mcp.pool(backends("eh", "127.0.0.1",
            { "10.0.0.1:11211", "10.0.0.2:11211", "10.0.0.3:11211", "10.0.0.4:11211" }), ec)
    end
    return pools
end

function mcp_config_routes(pools)
    local map = {}
    for name, pool in pairs(pools) do
        local fg = mcp.funcgen_new()
        local h = fg:new_handle(pool)
        fg:ready({
            n = name,
            f = function(rctx)
                return function(r)
                    return rctx:enqueue_and_wait(r, h)
                end
            end
        })
        map[name] = fg
    end
    mcp.attach(mcp.CMD_MG, mcp.router_new({ map = map }))
end

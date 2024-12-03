-- TODO: separate test file which pokes the mutator config failure modes
-- config arg would make that pretty easy.

function mcp_config_pools()
    local b1 = mcp.backend('b1', '127.0.0.1', 12173)
    return mcp.pool({b1})
end

function mcp_config_routes(p)
    local mgfg = mcp.funcgen_new()
    local mgfgh = mgfg:new_handle(p)
    local msfg = mcp.funcgen_new()
    local msfgh = msfg:new_handle(p)
    -- TODO: basic ascii handlers as well
    -- so we can test rewriting requests between command types

    -- various mutators to test

    -- basic; no flags at all.
    local mut_mgreq = mcp.req_mutator_new(
        { t = "cmdset", cmd = "mg" },
        { t = "keyset", val = "override" }
    )

    local mut_mgreqcopy = mcp.req_mutator_new(
        { t = "cmdcopy", idx = 1 },
        { t = "keycopy", idx = 2 }
    )

    -- set a bunch of flags
    local mut_mgflagreq = mcp.req_mutator_new(
        { t = "cmdset", cmd = "mg" },
        { t = "keyset", val = "override" },
        { t = "flagset", flag = "s" },
        { t = "flagset", flag = "t" },
        { t = "flagset", flag = "O", val = "opaque" },
        { t = "flagset", flag = "N", val = 33 }
    )

    -- basic res: no flags.
    local mut_mgres = mcp.res_mutator_new(
        { t = "rescodeset", val = "HD" }
    )

    -- res with value.
    local mut_mgresval = mcp.res_mutator_new(
        { t = "rescodecopy", idx = 1 },
        { t = "valcopy", idx = 2 }
    )

    -- res with flags.
    local mut_mgresflag = mcp.res_mutator_new(
        { t = "rescodeset", val = "HD" },
        { t = "flagset", flag = "t", val = "37" },
        { t = "flagcopy", flag = "O", idx = 1 }
    )

    -- error res.
    local mut_reserr = mcp.res_mutator_new(
        { t = "reserr", code = "server", msg = "teapot" }
    )

    mgfg:ready({
        n = "mgtest", u = 2, f = function(rctx)
            -- make blank request objects for handing to mutator

            -- these objects must be made per slot (rctx)
            -- they're made via the rctx so it can release memory inbetween
            -- requests.
            local nreq = rctx:request_new()
            local nres = rctx:response_new()

            return function(r)
                local key = r:key()
                -- test tree

                if key == "mgreq" then
                    local ret = mut_mgreq(nreq)
                    return rctx:enqueue_and_wait(nreq, mgfgh)
                elseif key == "mgflagreq" then
                    local ret = mut_mgflagreq(nreq)
                    return rctx:enqueue_and_wait(nreq, mgfgh)
                elseif key == "mgreqcopy" then
                    local ret = mut_mgreqcopy(nreq, "md", "differentkey")
                    return rctx:enqueue_and_wait(nreq, mgfgh)
                elseif key == "mgres" then
                    local ret = mut_mgres(nres)
                    return nres
                elseif key == "mgresval" then
                    local ret = mut_mgresval(nres, "VA", "example value\r\n")
                    return nres
                elseif key == "mgresflag" then
                    local res = rctx:enqueue_and_wait(r, mgfgh)
                    local ret = mut_mgresflag(nres, res)
                    return nres
                elseif key == "mgresflag2" then
                    local res = rctx:enqueue_and_wait(r, mgfgh)
                    local ret = mut_mgresflag(nres, "toast")
                    return nres
                elseif key == "mgresteapot" then
                    local res = mut_reserr(nres)
                    if nres:ok() or nres:hit() then
                        return "SERVER_ERROR NOT a teapot\r\n"
                    end
                    return nres
                end
            end
        end
    })

    msfg:ready({
        n = "mstest", u = 2, f = function(rctx)
            return function(r)
                local key = r:key()
                -- test tree
            end
        end
    })

    mcp.attach(mcp.CMD_MG, mgfg)
    mcp.attach(mcp.CMD_MS, msfg)
end

-- Minimal configuration.
pools{
    main = {
        backends = dofile("./t/proxyroutelibtls_memtier_backends.lua")
    }
}

routes{
    default = route_direct{ child = "main" }
}

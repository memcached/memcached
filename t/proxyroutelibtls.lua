-- Minimal configuration.
pools{
    main = {
        backends = dofile("./t/proxyroutelibtls_backends.lua")
    }
}

routes{
    default = route_direct{ child = "main" }
}

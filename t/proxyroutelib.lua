-- Minimal configuration.
pools{
    main = {
        backends = {
            "127.0.0.1:12181",
        }
    }
}

routes{
    default = route_direct{ child = "main" }
}

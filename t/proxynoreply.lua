pools{
    main = {
        backends = {
            "127.0.0.1:12221",
        }
    }
}

routes{
    default = route_direct{ child = "main" }
}

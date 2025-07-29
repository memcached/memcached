pools {
    mask63 = {
        backends = {
            "127.0.0.1:11811",
            "127.0.0.1:11812",
            "127.0.0.1:11813",
        },
        options = {
            hash = mcp.hash_farmhash,
            dist = mcp.dist_modulo,
            hash_mask = "0x7FFFFFFFFFFFFFFF",
        },
    },
}

routes {
    default = route_direct{ child = "mask63" },
}



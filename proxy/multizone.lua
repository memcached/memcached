local s = require("simple")

-- if my_zone() is commented out, will look for "backends" instead of "zones"
s.my_zone("z1")

-- NOTE: optional to specify this if defaults are okay.
s.router{
    router_type = "keyprefix",
	match_prefix = "/(%a+)/",
	default_pool = nil
}

-- NOTE: a normal config will have backends _or_ zones, not both!
s.pool{
	name = "foo",
	backends = {"127.0.0.1:11212", "127.0.0.1:11213"},
	zones = {
      z1 = {
		"127.0.0.1:11212 foo1",
        "127.0.0.1:11213 foo2",
      },
      z2 = {
		"127.0.0.1:11214",
        "127.0.0.1:11215",
	  },
    }
}

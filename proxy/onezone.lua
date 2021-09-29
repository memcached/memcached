-- by defaults, sends "/foo/*" to "foo" and "/bar/*" to "bar"
pool{
	name = "foo",
	backends = {"127.0.0.1:11212", "127.0.0.1:11213"},
}

pool{
	name = "bar",
	backends = {"127.0.0.1:11214", "127.0.0.1:11215"},
}

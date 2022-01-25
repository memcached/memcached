# Minimal (C) Client for MemCached

WARNING: WORK IN PROGRESS. Missing features or testing!

MCMC is a minimalistic allocation-free modern client for memcached. It uses a
generic response parser, allowing a single code path regardless of the command
sent to memcached. It has no 3rd party dependencies and is designed to
integrate as a building block into full clients.

MCMC does not (yet) include a typical memcached "selector". Meaning the
ability to add many servers to a hash table of some kind and routing keys to
specific servers. The MCMC base client is designed to be an object that
selector objects hold and then issue commands against.

Allocation-free (aside from a call to `getaddrinfo()`) means it does not
_internally_ do any allocations, relying only on the stack. It requires you
malloc a small structure and some buffers, but you are then free to manage
them yourselves. Clients do not hold onto buffers when idle, cutting their
memory overhead to a handful of bytes plus the TCP socket.

MCMC is designed to be a building block for users designing full clients.
For example:

* A client author wants to implement the "get" command
* They write a function in their native language's wrapper which accepts the
  key to fetch and embeds that into a text buffer to look like `get [key]\r\n`
* They then call mcmc's functions to send and read the response, parsing and
  returning it to the client.

This should be the same, if not less, code than wrapping a full C client with
every possible command broken out. It also means 3rd party clients can (and
should!) embed mcmc.c/mcmc.h (and any selector code they want) rather than be
dependent on system distribution of a more complex client.

The allocation-free nature also makes unit testing the client code easier,
hopefully leading to higher quality.

Caveats:

* Care should be taken when handling the buffers mcmc requires to operate.
  Since there are few operators you should only have to pay attention once :)
* It does not support the various maintenance/settings commands (ie; `lru_crawler`).
  It may gain some generic support for this, but those commands were not
designed with consistent response codes and are hard to implement.
* Does not support the binary protocol, which has been deprecated as of 1.6.0.

As of this writing the code is being released _early_ (perhaps too early?). It
may not have proper makefiles, tests, or a fully implemented API. The code has
been posted so client authors and users can give early feedback on the API in
hopes of prodiving something high quality and stable.

Again, looking for feedback! Open an issue or let me know what you think.

Ideally, you want to make a static binary, otherwise the dynamic
linker pollutes your address space with shared libs right in the
middle.  (NOTE: actually, this shouldn't matter so much anymore, now
that we only allocate huge, fixed-size slabs)

Make sure your libevent has epoll (Linux) or kqueue (BSD) support.
Using poll or select only is slow, and works for testing, but
shouldn't be used for high-traffic memcache installations.

To build libevent with epoll on Linux, you need two things. First,
you need /usr/include/sys/epoll.h . To get it, you can install the
userspace epoll library, epoll-lib. The link to the latest version
is buried inside
http://www.xmailserver.org/linux-patches/nio-improve.html ; currently
it's http://www.xmailserver.org/linux-patches/epoll-lib-0.9.tar.gz .
If you're having any trouble building/installing it, you can just copy
epoll.h from that tarball to /usr/include/sys as that's the only thing
from there that libevent really needs.

Secondly, you need to declare syscall numbers of epoll syscalls, so
libevent can use them. Put these declarations somewhere
inside <sys/epoll.h>:

#define __NR_epoll_create               254
#define __NR_epoll_ctl          255
#define __NR_epoll_wait         256

After this you should be able to build libevent with epoll support.
Once you build/install libevent, you don't need <sys/epoll.h> to
compile memcache or link it against libevent. Don't forget that for epoll
support to actually work at runtime you need to use a kernel with epoll
support patch applied, as explained in the README file.

BSD users are luckier, and will get kqueue support by default.




Ideally, you want to make a static binary, otherwise the dynamic
linker pollutes your address space with shared libs right in the
middle.

Make sure your libevent has epoll (Linux) or kqueue (BSD) support.
Using poll or select only is slow, and works for testing, but
shouldn't be used for high-traffice memcache installations.

To build libevent with epoll on Linux, you need:

#define __NR_epoll_create               254
#define __NR_epoll_ctl          255
#define __NR_epoll_wait         256

One okay (but not ideal) place to shove them is /usr/include/asm/unistd.h

BSD users are luckier, and will get kqueue support by default.




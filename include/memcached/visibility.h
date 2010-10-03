/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_VISIBILITY_H
#define MEMCACHED_VISIBILITY_H 1

#if (defined(__SUNPRO_C) && (__SUNPRO_C >= 0x550)) || (defined(__SUNPRO_CC) && (__SUNPRO_CC >= 0x550))
#define MEMCACHED_PUBLIC_API __global
#elif defined __GNUC__
#define MEMCACHED_PUBLIC_API __attribute__ ((visibility("default")))
#else
#define MEMCACHED_PUBLIC_API
#endif

#endif /* MEMCACHED_VISIBILITY_H */

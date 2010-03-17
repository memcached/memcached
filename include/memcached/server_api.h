/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_SERVER_API_H
#define MEMCACHED_SERVER_API_H
#include <inttypes.h>
#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Time relative to server start. Smaller than time_t on 64-bit systems.
     */
    typedef uint32_t rel_time_t;

    typedef enum {
        server_handle_v1 = 1,
        server_extension_api
    } server_api_t;

#ifdef __WIN32__
#undef interface
#endif

    typedef void* (*GET_SERVER_API)(server_api_t interface);

#ifdef __cplusplus
}
#endif

#endif

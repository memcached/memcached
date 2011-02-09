/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef EXAMPLE_PROTOCOL_H
#define EXAMPLE_PROTOCOL_H

#include <memcached/engine.h>

MEMCACHED_PUBLIC_API
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api);

#endif

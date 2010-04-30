/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef ENGINE_LOADER_H
#define ENGINE_LOADER_H

#include <memcached/extension.h>
#include <memcached/engine.h>
#include <memcached/visibility.h>

#ifdef __cplusplus
extern "C" {
#endif
MEMCACHED_PUBLIC_API bool load_engine(const char *soname,
                                      SERVER_HANDLE_V1 *(*get_server_api)(void),
                                      EXTENSION_LOGGER_DESCRIPTOR *logger,
                                      ENGINE_HANDLE **engine_handle);

MEMCACHED_PUBLIC_API bool init_engine(ENGINE_HANDLE * engine,
                                       const char *config_str,
                                       EXTENSION_LOGGER_DESCRIPTOR *logger);

MEMCACHED_PUBLIC_API void log_engine_details(ENGINE_HANDLE * engine,
                                             EXTENSION_LOGGER_DESCRIPTOR *logger);

#ifdef __cplusplus
}
#endif

#endif    /* ENGINE_LOADER_H */

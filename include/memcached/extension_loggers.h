/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_EXTENSION_LOGGERS_H
#define MEMCACHED_EXTENSION_LOGGERS_H
#include <memcached/extension.h>

#ifdef  __cplusplus
extern "C" {
#endif

MEMCACHED_PUBLIC_API EXTENSION_LOGGER_DESCRIPTOR* get_null_logger(void);

MEMCACHED_PUBLIC_API EXTENSION_LOGGER_DESCRIPTOR* get_stderr_logger(void);

MEMCACHED_PUBLIC_API
EXTENSION_ERROR_CODE memcached_initialize_stderr_logger(GET_SERVER_API get_server_api);

#ifdef  __cplusplus
}
#endif

#endif  /* MEMCACHED_EXTENSION_LOGGER_H */

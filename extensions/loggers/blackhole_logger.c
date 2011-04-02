/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"
#include <stdarg.h>
#include <stdio.h>
#include <memcached/extension.h>
#include <memcached/engine.h>
#include "protocol_extension.h"

static const char *get_name(void) {
    return "blackhole";
}

static void logger_log(EXTENSION_LOG_LEVEL severity,
                       const void* client_cookie,
                       const char *fmt, ...)
{
    (void)severity;
    (void)client_cookie;
    (void)fmt;
}

static EXTENSION_LOGGER_DESCRIPTOR descriptor = {
    .get_name = get_name,
    .log = logger_log
};

MEMCACHED_PUBLIC_API
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api) {
    (void)config;

    SERVER_HANDLE_V1 *sapi = get_server_api();
    if (sapi == NULL) {
        return EXTENSION_FATAL;
    }

    if (!sapi->extension->register_extension(EXTENSION_LOGGER, &descriptor)) {
        return EXTENSION_FATAL;
    }

    return EXTENSION_SUCCESS;
}

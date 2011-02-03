/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol_extension.h"

/*
 * This is an example on how you can add your own commands into the
 * ascii protocol. You load the extensions into memcached by using
 * the -X option:
 * ./memcached -X .libs/example_protocol.so -E .libs/default_engine.so
 *
 * @todo add an example that require extra userspace data, and communicates
 *       with the engine by getting the engine descriptor.
 */

static const char *get_name(const void *cmd_cookie);
static bool accept_command(const void *cmd_cookie, void *cookie,
                           int argc, token_t *argv, size_t *ndata,
                           char **ptr);
static ENGINE_ERROR_CODE execute_command(const void *cmd_cookie, const void *cookie,
                                         int argc, token_t *argv,
                                         ENGINE_ERROR_CODE (*response_handler)(const void *cookie,
                                                                               int nbytes,
                                                                               const char *dta));
static void abort_command(const void *cmd_cookie, const void *cookie);

static EXTENSION_ASCII_PROTOCOL_DESCRIPTOR noop_descriptor = {
    .get_name = get_name,
    .accept = accept_command,
    .execute = execute_command,
    .abort = abort_command,
    .cookie = &noop_descriptor
};

static EXTENSION_ASCII_PROTOCOL_DESCRIPTOR echo_descriptor = {
    .get_name = get_name,
    .accept = accept_command,
    .execute = execute_command,
    .abort = abort_command,
    .cookie = &echo_descriptor
};

static const char *get_name(const void *cmd_cookie) {
    if (cmd_cookie == &noop_descriptor) {
        return "noop";
    } else {
        return "echo";
    }
}

static bool accept_command(const void *cmd_cookie, void *cookie,
                           int argc, token_t *argv, size_t *ndata,
                           char **ptr) {
    if (cmd_cookie == &noop_descriptor) {
        return strcmp(argv[0].value, "noop") == 0;
    } else {
        return strcmp(argv[0].value, "echo") == 0;
    }
}

static ENGINE_ERROR_CODE execute_command(const void *cmd_cookie, const void *cookie,
                                         int argc, token_t *argv,
                                         ENGINE_ERROR_CODE (*response_handler)(const void *cookie,
                                                                               int nbytes,
                                                                               const char *dta))
{
    if (cmd_cookie == &noop_descriptor) {
        return response_handler(cookie, 4, "OK\r\n");
    } else {
        if (response_handler(cookie, argv[0].length, argv[0].value) != ENGINE_SUCCESS) {
            return ENGINE_DISCONNECT;
        }

        for (int ii = 1; ii < argc; ++ii) {
            if (response_handler(cookie, 2, " [") != ENGINE_SUCCESS ||
                response_handler(cookie, argv[ii].length, argv[ii].value) != ENGINE_SUCCESS ||
                response_handler(cookie, 1, "]") != ENGINE_SUCCESS) {
                return ENGINE_DISCONNECT;
            }
        }

        return response_handler(cookie, 2, "\r\n");
    }
}

static void abort_command(const void *cmd_cookie, const void *cookie)
{
    /* EMPTY */
}

#if defined (__SUNPRO_C) && (__SUNPRO_C >= 0x550)
__global
#elif defined __GNUC__
__attribute__ ((visibility("default")))
#endif
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api) {
    SERVER_HANDLE_V1 *server = get_server_api();
    if (server == NULL) {
        return EXTENSION_FATAL;
    }
    if (!server->extension->register_extension(EXTENSION_ASCII_PROTOCOL,
                                               &noop_descriptor)) {
        return EXTENSION_FATAL;
    }

    if (!server->extension->register_extension(EXTENSION_ASCII_PROTOCOL,
                                               &echo_descriptor)) {
        return EXTENSION_FATAL;
    }

    return EXTENSION_SUCCESS;
}

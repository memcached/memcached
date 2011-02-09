/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol_extension.h"

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

static EXTENSION_ASCII_PROTOCOL_DESCRIPTOR scrub_descriptor = {
    .get_name = get_name,
    .accept = accept_command,
    .execute = execute_command,
    .abort = abort_command,
    .cookie = &scrub_descriptor
};

GET_SERVER_API server_api;

static const char *get_name(const void *cmd_cookie) {
    return "scrub";
}

static bool accept_command(const void *cmd_cookie, void *cookie,
                           int argc, token_t *argv, size_t *ndata,
                           char **ptr) {
    return strcmp(argv[0].value, "scrub") == 0;
}

static bool my_response_handler(const void *key, uint16_t keylen,
                                const void *ext, uint8_t extlen,
                                const void *body, uint32_t bodylen,
                                uint8_t datatype, uint16_t status,
                                uint64_t cas, const void *cookie)
{
    uint16_t *rval = (uint16_t*)cookie;
    *rval = status;
    return true;
}

static ENGINE_ERROR_CODE execute_command(const void *cmd_cookie, const void *cookie,
                                         int argc, token_t *argv,
                                         ENGINE_ERROR_CODE (*response_handler)(const void *cookie,
                                                                               int nbytes,
                                                                               const char *dta))
{
    protocol_binary_request_header request = {
        .request.magic = (uint8_t)PROTOCOL_BINARY_REQ,
        .request.opcode = PROTOCOL_BINARY_CMD_SCRUB
    };

    uint16_t status = 0;
    SERVER_HANDLE_V1 *server = server_api();
    ENGINE_HANDLE_V1 *v1 = (ENGINE_HANDLE_V1*)server->engine;
    if (v1 == NULL) {
        return response_handler(cookie, 29, "SERVER_ERROR internal error\r\n");
    }

    v1->unknown_command(server->engine, &status, &request, my_response_handler);

    if (status == PROTOCOL_BINARY_RESPONSE_SUCCESS) {
        return response_handler(cookie, 4, "OK\r\n");
    } else if (status == PROTOCOL_BINARY_RESPONSE_EBUSY) {
        return response_handler(cookie, 6, "BUSY\r\n");
    } else {
        return response_handler(cookie, 7, "ERROR\r\n");
    }
}

static void abort_command(const void *cmd_cookie, const void *cookie)
{
    /* EMPTY */
}

MEMCACHED_PUBLIC_API
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api) {
    server_api = get_server_api;
    SERVER_HANDLE_V1 *server = get_server_api();
    if (server == NULL) {
        return EXTENSION_FATAL;
    }
    if (!server->extension->register_extension(EXTENSION_ASCII_PROTOCOL,
                                               &scrub_descriptor)) {
        return EXTENSION_FATAL;
    }

    return EXTENSION_SUCCESS;
}

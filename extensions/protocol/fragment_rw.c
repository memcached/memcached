/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>

#include "protocol_extension.h"
#include <memcached/util.h>
#include "fragment_rw.h"

static uint8_t read_command = PROTOCOL_BINARY_CMD_READ;
static uint8_t write_command = PROTOCOL_BINARY_CMD_WRITE;

GET_SERVER_API server_api;

static const char *get_name(void);
static void setup(void (*add)(EXTENSION_BINARY_PROTOCOL_DESCRIPTOR *descriptor,
                              uint8_t cmd,
                              BINARY_COMMAND_CALLBACK new_handler));

static ENGINE_ERROR_CODE handle_fragment_rw(EXTENSION_BINARY_PROTOCOL_DESCRIPTOR *descriptor,
                                            ENGINE_HANDLE* handle,
                                            const void* cookie,
                                            protocol_binary_request_header *request,
                                            ADD_RESPONSE response);

static EXTENSION_BINARY_PROTOCOL_DESCRIPTOR descriptor = {
    .get_name = get_name,
    .setup = setup
};

static const char *get_name(void) {
    return "fragment read/write";
}

static void setup(void (*add)(EXTENSION_BINARY_PROTOCOL_DESCRIPTOR *descriptor,
                              uint8_t cmd,
                              BINARY_COMMAND_CALLBACK new_handler))
{
    add(&descriptor, read_command, handle_fragment_rw);
    add(&descriptor, write_command, handle_fragment_rw);
}

static ENGINE_ERROR_CODE create_object(ENGINE_HANDLE_V1 *v1,
                                       ENGINE_HANDLE *v,
                                       const void *cookie,
                                       const item_info *org,
                                       uint16_t vbucket,
                                       const void *data,
                                       uint64_t offset,
                                       uint64_t len,
                                       uint64_t *cas)
{
    ENGINE_ERROR_CODE r;
    item *item = NULL;

    r = v1->allocate(v, cookie, &item, org->key, org->nkey, org->nbytes,
                     org->flags, vbucket);
    if (r != ENGINE_SUCCESS) {
        return r;
    }

    item_info i2 = { .nvalue = 1 };
    if (!v1->get_item_info(v, cookie, item, &i2)) {
        v1->release(v, cookie, item);
        return ENGINE_DISCONNECT;
    }

    uint8_t *dest = (void*)i2.value[0].iov_base;
    memcpy(dest, org->value[0].iov_base, org->nbytes);
    memcpy(dest + offset, data, len);

    v1->item_set_cas(v, cookie, item, org->cas);
    r = v1->store(v, cookie, item, cas, OPERATION_CAS, vbucket);
    v1->release(v, cookie, item);
    return r;
}

static ENGINE_ERROR_CODE handle_fragment_rw(EXTENSION_BINARY_PROTOCOL_DESCRIPTOR *descriptor,
                                            ENGINE_HANDLE* handle,
                                            const void* cookie,
                                            protocol_binary_request_header *request,
                                            ADD_RESPONSE response)
{
    if (request->request.extlen != 8 || request->request.keylen == 0) {
        return response(NULL, 0, NULL, 0, NULL, 0, PROTOCOL_BINARY_RAW_BYTES,
                        PROTOCOL_BINARY_RESPONSE_EINVAL, 0, cookie);
    }

    protocol_binary_request_read *req = (void*)request;
    uint8_t *key = req->bytes + sizeof(request->bytes) +
        request->request.extlen;
    uint16_t nkey = ntohs(request->request.keylen);
    uint64_t offset = ntohl(req->message.body.offset);
    uint64_t len = ntohl(req->message.body.length);
    uint16_t vbucket = ntohs(request->request.vbucket);
    uint64_t cas = ntohll(request->request.cas);
    ENGINE_HANDLE_V1 *v1 = (void*)handle;
    item *item = NULL;
    uint8_t *data = key + nkey;

    ENGINE_ERROR_CODE r = v1->get(handle, cookie, &item, key, nkey, vbucket);
    if (r == ENGINE_SUCCESS) {
        item_info item_info = { .nvalue = 1 };

        if (!v1->get_item_info(handle, NULL, item, &item_info)) {
            r = ENGINE_FAILED;
        } else if (cas != 0 && item_info.cas != cas) {
            r = ENGINE_KEY_EEXISTS;
        } else if (offset + len > (uint64_t)item_info.nbytes) {
            r = ENGINE_ERANGE;
        }

        if (r == ENGINE_SUCCESS) {
            if (request->request.opcode == read_command) {
                uint8_t *ptr;
                ptr =  ((uint8_t*)item_info.value[0].iov_base) + offset;
                if (!response(NULL, 0, NULL, 0, ptr,
                              (uint32_t)len, PROTOCOL_BINARY_RAW_BYTES,
                              PROTOCOL_BINARY_RESPONSE_SUCCESS,
                              item_info.cas, cookie)) {
                    return ENGINE_DISCONNECT;
                }
            } else {
                r = create_object(v1, handle, cookie, &item_info,
                                  vbucket, data, offset, len, &cas);
                if (r == ENGINE_SUCCESS) {
                    if (!response(NULL, 0, NULL, 0, NULL, 0,
                                  PROTOCOL_BINARY_RAW_BYTES,
                                  PROTOCOL_BINARY_RESPONSE_SUCCESS,
                                  cas, cookie)) {
                        return ENGINE_DISCONNECT;
                    }
                }
            }
        }

        v1->release(handle, cookie, item);
    }

    return r;
}

MEMCACHED_PUBLIC_API
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api) {

    server_api = get_server_api;
    SERVER_HANDLE_V1 *server = get_server_api();
    if (server == NULL) {
        return EXTENSION_FATAL;
    }

    if (config != NULL) {
        size_t rop, wop;
        struct config_item items[] = {
            { .key = "r",
              .datatype = DT_SIZE,
              .value.dt_size = &rop },
            { .key = "w",
              .datatype = DT_SIZE,
              .value.dt_size = &wop },
            { .key = NULL}
        };

        if (server->core->parse_config(config, items, stderr) != 0) {
            return EXTENSION_FATAL;
        }

        if (items[0].found) {
            read_command = (uint8_t)(rop & 0xff);
        }

        if (items[1].found) {
            write_command = (uint8_t)(wop & 0xff);
        }
    }

    if (!server->extension->register_extension(EXTENSION_BINARY_PROTOCOL,
                                               &descriptor)) {
        return EXTENSION_FATAL;
    }

    return EXTENSION_SUCCESS;
}

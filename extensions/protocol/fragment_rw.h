/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef EXTENSIONS_PROTOCOL_FRAGMENT_RW_H
#define EXTENSIONS_PROTOCOL_FRAGMENT_RW_H

#include <memcached/protocol_binary.h>

/** The default command id for the read operation (override with r=) */
#define PROTOCOL_BINARY_CMD_READ (uint8_t)(0xf1 & 0xff)

/** The default command id for the write operation (override with w=) */
#define PROTOCOL_BINARY_CMD_WRITE (uint8_t)(0xf2 & 0xff)

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Definition of the packet used by read and write
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                uint32_t offset;
                uint32_t length;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 8];
    } protocol_binary_request_read;
    typedef protocol_binary_request_read protocol_binary_request_write;

    /**
     * Definition of the packet returned from read and write
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_read;
    typedef protocol_binary_response_no_extras protocol_binary_response_write;

#ifdef __cplusplus
}
#endif

#endif

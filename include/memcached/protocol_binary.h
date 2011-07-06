/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Copyright (c) <2008>, Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the  nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY SUN MICROSYSTEMS, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL SUN MICROSYSTEMS, INC. BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * Summary: Constants used by to implement the binary protocol.
 *
 * Copy: See Copyright for the status of this software.
 *
 * Author: Trond Norbye <trond.norbye@sun.com>
 */

#ifndef PROTOCOL_BINARY_H
#define PROTOCOL_BINARY_H

#include <stdint.h>
#include <memcached/vbucket.h>

/**
 * \addtogroup Protocol
 * @{
 */

/**
 * This file contains definitions of the constants and packet formats
 * defined in the binary specification. Please note that you _MUST_ remember
 * to convert each multibyte field to / from network byte order to / from
 * host order.
 */
#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * Definition of the legal "magic" values used in a packet.
     * See section 3.1 Magic byte
     */
    typedef enum {
        PROTOCOL_BINARY_REQ = 0x80,
        PROTOCOL_BINARY_RES = 0x81
    } protocol_binary_magic;

    /**
     * Definition of the valid response status numbers.
     * See section 3.2 Response Status
     */
    typedef enum {
        PROTOCOL_BINARY_RESPONSE_SUCCESS = 0x00,
        PROTOCOL_BINARY_RESPONSE_KEY_ENOENT = 0x01,
        PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS = 0x02,
        PROTOCOL_BINARY_RESPONSE_E2BIG = 0x03,
        PROTOCOL_BINARY_RESPONSE_EINVAL = 0x04,
        PROTOCOL_BINARY_RESPONSE_NOT_STORED = 0x05,
        PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL = 0x06,
        PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET = 0x07,
        PROTOCOL_BINARY_RESPONSE_AUTH_ERROR = 0x20,
        PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE = 0x21,
        PROTOCOL_BINARY_RESPONSE_ERANGE = 0x22,
        PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND = 0x81,
        PROTOCOL_BINARY_RESPONSE_ENOMEM = 0x82,
        PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED = 0x83,
        PROTOCOL_BINARY_RESPONSE_EINTERNAL = 0x84,
        PROTOCOL_BINARY_RESPONSE_EBUSY = 0x85,
        PROTOCOL_BINARY_RESPONSE_ETMPFAIL = 0x86
    } protocol_binary_response_status;

    /**
     * Defintion of the different command opcodes.
     * See section 3.3 Command Opcodes
     */
    typedef enum {
        PROTOCOL_BINARY_CMD_GET = 0x00,
        PROTOCOL_BINARY_CMD_SET = 0x01,
        PROTOCOL_BINARY_CMD_ADD = 0x02,
        PROTOCOL_BINARY_CMD_REPLACE = 0x03,
        PROTOCOL_BINARY_CMD_DELETE = 0x04,
        PROTOCOL_BINARY_CMD_INCREMENT = 0x05,
        PROTOCOL_BINARY_CMD_DECREMENT = 0x06,
        PROTOCOL_BINARY_CMD_QUIT = 0x07,
        PROTOCOL_BINARY_CMD_FLUSH = 0x08,
        PROTOCOL_BINARY_CMD_GETQ = 0x09,
        PROTOCOL_BINARY_CMD_NOOP = 0x0a,
        PROTOCOL_BINARY_CMD_VERSION = 0x0b,
        PROTOCOL_BINARY_CMD_GETK = 0x0c,
        PROTOCOL_BINARY_CMD_GETKQ = 0x0d,
        PROTOCOL_BINARY_CMD_APPEND = 0x0e,
        PROTOCOL_BINARY_CMD_PREPEND = 0x0f,
        PROTOCOL_BINARY_CMD_STAT = 0x10,
        PROTOCOL_BINARY_CMD_SETQ = 0x11,
        PROTOCOL_BINARY_CMD_ADDQ = 0x12,
        PROTOCOL_BINARY_CMD_REPLACEQ = 0x13,
        PROTOCOL_BINARY_CMD_DELETEQ = 0x14,
        PROTOCOL_BINARY_CMD_INCREMENTQ = 0x15,
        PROTOCOL_BINARY_CMD_DECREMENTQ = 0x16,
        PROTOCOL_BINARY_CMD_QUITQ = 0x17,
        PROTOCOL_BINARY_CMD_FLUSHQ = 0x18,
        PROTOCOL_BINARY_CMD_APPENDQ = 0x19,
        PROTOCOL_BINARY_CMD_PREPENDQ = 0x1a,
        PROTOCOL_BINARY_CMD_VERBOSITY = 0x1b,
        PROTOCOL_BINARY_CMD_TOUCH = 0x1c,
        PROTOCOL_BINARY_CMD_GAT = 0x1d,
        PROTOCOL_BINARY_CMD_GATQ = 0x1e,

        PROTOCOL_BINARY_CMD_SASL_LIST_MECHS = 0x20,
        PROTOCOL_BINARY_CMD_SASL_AUTH = 0x21,
        PROTOCOL_BINARY_CMD_SASL_STEP = 0x22,

        /* These commands are used for range operations and exist within
         * this header for use in other projects.  Range operations are
         * not expected to be implemented in the memcached server itself.
         */
        PROTOCOL_BINARY_CMD_RGET      = 0x30,
        PROTOCOL_BINARY_CMD_RSET      = 0x31,
        PROTOCOL_BINARY_CMD_RSETQ     = 0x32,
        PROTOCOL_BINARY_CMD_RAPPEND   = 0x33,
        PROTOCOL_BINARY_CMD_RAPPENDQ  = 0x34,
        PROTOCOL_BINARY_CMD_RPREPEND  = 0x35,
        PROTOCOL_BINARY_CMD_RPREPENDQ = 0x36,
        PROTOCOL_BINARY_CMD_RDELETE   = 0x37,
        PROTOCOL_BINARY_CMD_RDELETEQ  = 0x38,
        PROTOCOL_BINARY_CMD_RINCR     = 0x39,
        PROTOCOL_BINARY_CMD_RINCRQ    = 0x3a,
        PROTOCOL_BINARY_CMD_RDECR     = 0x3b,
        PROTOCOL_BINARY_CMD_RDECRQ    = 0x3c,
        /* End Range operations */

        /* VBucket commands */
        PROTOCOL_BINARY_CMD_SET_VBUCKET = 0x3d,
        PROTOCOL_BINARY_CMD_GET_VBUCKET = 0x3e,
        PROTOCOL_BINARY_CMD_DEL_VBUCKET = 0x3f,
        /* End VBucket commands */

        /* TAP commands */
        PROTOCOL_BINARY_CMD_TAP_CONNECT = 0x40,
        PROTOCOL_BINARY_CMD_TAP_MUTATION = 0x41,
        PROTOCOL_BINARY_CMD_TAP_DELETE = 0x42,
        PROTOCOL_BINARY_CMD_TAP_FLUSH = 0x43,
        PROTOCOL_BINARY_CMD_TAP_OPAQUE = 0x44,
        PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET = 0x45,
        PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_START = 0x46,
        PROTOCOL_BINARY_CMD_TAP_CHECKPOINT_END = 0x47,
        /* End TAP */

        PROTOCOL_BINARY_CMD_LAST_RESERVED = 0x8f,

        /* Scrub the data */
        PROTOCOL_BINARY_CMD_SCRUB = 0xf0
    } protocol_binary_command;

    /**
     * Definition of the data types in the packet
     * See section 3.4 Data Types
     */
    typedef enum {
        PROTOCOL_BINARY_RAW_BYTES = 0x00
    } protocol_binary_datatypes;

    /**
     * Definition of the header structure for a request packet.
     * See section 2
     */
    typedef union {
        struct {
            uint8_t magic;
            uint8_t opcode;
            uint16_t keylen;
            uint8_t extlen;
            uint8_t datatype;
            uint16_t vbucket;
            uint32_t bodylen;
            uint32_t opaque;
            uint64_t cas;
        } request;
        uint8_t bytes[24];
    } protocol_binary_request_header;

    /**
     * Definition of the header structure for a response packet.
     * See section 2
     */
    typedef union {
        struct {
            uint8_t magic;
            uint8_t opcode;
            uint16_t keylen;
            uint8_t extlen;
            uint8_t datatype;
            uint16_t status;
            uint32_t bodylen;
            uint32_t opaque;
            uint64_t cas;
        } response;
        uint8_t bytes[24];
    } protocol_binary_response_header;

    /**
     * Definition of a request-packet containing no extras
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header)];
    } protocol_binary_request_no_extras;

    /**
     * Definition of a response-packet containing no extras
     */
    typedef union {
        struct {
            protocol_binary_response_header header;
        } message;
        uint8_t bytes[sizeof(protocol_binary_response_header)];
    } protocol_binary_response_no_extras;

    /**
     * Definition of the packet used by the get, getq, getk and getkq command.
     * See section 4
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_get;
    typedef protocol_binary_request_no_extras protocol_binary_request_getq;
    typedef protocol_binary_request_no_extras protocol_binary_request_getk;
    typedef protocol_binary_request_no_extras protocol_binary_request_getkq;

    /**
     * Definition of the packet returned from a successful get, getq, getk and
     * getkq.
     * See section 4
     */
    typedef union {
        struct {
            protocol_binary_response_header header;
            struct {
                uint32_t flags;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_response_header) + 4];
    } protocol_binary_response_get;

    typedef protocol_binary_response_get protocol_binary_response_getq;
    typedef protocol_binary_response_get protocol_binary_response_getk;
    typedef protocol_binary_response_get protocol_binary_response_getkq;

    /**
     * Definition of the packet used by the delete command
     * See section 4
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_delete;

    /**
     * Definition of the packet returned by the delete command
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_delete;

    /**
     * Definition of the packet used by the flush command
     * See section 4
     * Please note that the expiration field is optional, so remember to see
     * check the header.bodysize to see if it is present.
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                uint32_t expiration;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 4];
    } protocol_binary_request_flush;

    /**
     * Definition of the packet returned by the flush command
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_flush;

    /**
     * Definition of the packet used by set, add and replace
     * See section 4
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                uint32_t flags;
                uint32_t expiration;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 8];
    } protocol_binary_request_set;
    typedef protocol_binary_request_set protocol_binary_request_add;
    typedef protocol_binary_request_set protocol_binary_request_replace;

    /**
     * Definition of the packet returned by set, add and replace
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_set;
    typedef protocol_binary_response_no_extras protocol_binary_response_add;
    typedef protocol_binary_response_no_extras protocol_binary_response_replace;

    /**
     * Definition of the noop packet
     * See section 4
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_noop;

    /**
     * Definition of the packet returned by the noop command
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_noop;

    /**
     * Definition of the structure used by the increment and decrement
     * command.
     * See section 4
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                uint64_t delta;
                uint64_t initial;
                uint32_t expiration;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 20];
    } protocol_binary_request_incr;
    typedef protocol_binary_request_incr protocol_binary_request_decr;

    /**
     * Definition of the response from an incr or decr command
     * command.
     * See section 4
     */
    typedef union {
        struct {
            protocol_binary_response_header header;
            struct {
                uint64_t value;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_response_header) + 8];
    } protocol_binary_response_incr;
    typedef protocol_binary_response_incr protocol_binary_response_decr;

    /**
     * Definition of the quit
     * See section 4
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_quit;

    /**
     * Definition of the packet returned by the quit command
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_quit;

    /**
     * Definition of the packet used by append and prepend command
     * See section 4
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_append;
    typedef protocol_binary_request_no_extras protocol_binary_request_prepend;

    /**
     * Definition of the packet returned from a successful append or prepend
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_append;
    typedef protocol_binary_response_no_extras protocol_binary_response_prepend;

    /**
     * Definition of the packet used by the version command
     * See section 4
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_version;

    /**
     * Definition of the packet returned from a successful version command
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_version;


    /**
     * Definition of the packet used by the stats command.
     * See section 4
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_stats;

    /**
     * Definition of the packet returned from a successful stats command
     * See section 4
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_stats;

    /**
     * Definition of the packet used by the verbosity command
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                uint32_t level;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 4];
    } protocol_binary_request_verbosity;

    /**
     * Definition of the packet returned from the verbosity command
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_verbosity;

    /**
     * Definition of the packet used by the touch command.
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                uint32_t expiration;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 4];
    } protocol_binary_request_touch;

    /**
     * Definition of the packet returned from the touch command
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_touch;

    /**
     * Definition of the packet used by the GAT(Q) command.
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                uint32_t expiration;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 4];
    } protocol_binary_request_gat;

    typedef protocol_binary_request_gat protocol_binary_request_gatq;

    /**
     * Definition of the packet returned from the GAT(Q)
     */
    typedef protocol_binary_response_get protocol_binary_response_gat;
    typedef protocol_binary_response_get protocol_binary_response_gatq;


    /**
     * Definition of a request for a range operation.
     * See http://code.google.com/p/memcached/wiki/RangeOps
     *
     * These types are used for range operations and exist within
     * this header for use in other projects.  Range operations are
     * not expected to be implemented in the memcached server itself.
     */
    typedef union {
        struct {
            protocol_binary_response_header header;
            struct {
                uint16_t size;
                uint8_t  reserved;
                uint8_t  flags;
                uint32_t max_results;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 4];
    } protocol_binary_request_rangeop;

    typedef protocol_binary_request_rangeop protocol_binary_request_rget;
    typedef protocol_binary_request_rangeop protocol_binary_request_rset;
    typedef protocol_binary_request_rangeop protocol_binary_request_rsetq;
    typedef protocol_binary_request_rangeop protocol_binary_request_rappend;
    typedef protocol_binary_request_rangeop protocol_binary_request_rappendq;
    typedef protocol_binary_request_rangeop protocol_binary_request_rprepend;
    typedef protocol_binary_request_rangeop protocol_binary_request_rprependq;
    typedef protocol_binary_request_rangeop protocol_binary_request_rdelete;
    typedef protocol_binary_request_rangeop protocol_binary_request_rdeleteq;
    typedef protocol_binary_request_rangeop protocol_binary_request_rincr;
    typedef protocol_binary_request_rangeop protocol_binary_request_rincrq;
    typedef protocol_binary_request_rangeop protocol_binary_request_rdecr;
    typedef protocol_binary_request_rangeop protocol_binary_request_rdecrq;


    /**
     * Definition of tap commands
     * See To be written
     *
     */

    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                /**
                 * flags is a bitmask used to set properties for the
                 * the connection. Please In order to be forward compatible
                 * you should set all undefined bits to 0.
                 *
                 * If the bit require extra userdata, it will be stored
                 * in the user-data field of the body (passed to the engine
                 * as enginespeciffic). That means that when you parse the
                 * flags and the engine-specific data, you have to work your
                 * way from bit 0 and upwards to find the correct offset for
                 * the data.
                 *
                 */
                uint32_t flags;

                /**
                 * Backfill age
                 *
                 * By using this flag you can limit the amount of data being
                 * transmitted. If you don't specify a backfill age, the
                 * server will transmit everything it contains.
                 *
                 * The first 8 bytes in the engine specific data contains
                 * the oldest entry (from epoc) you're interested in.
                 * Specifying a time in the future (for the server you are
                 * connecting to), will cause it to start streaming current
                 * changes.
                 */
#define TAP_CONNECT_FLAG_BACKFILL 0x01
                /**
                 * Dump will cause the server to send the data stored on the
                 * server, but disconnect when the keys stored in the server
                 * are transmitted.
                 */
#define TAP_CONNECT_FLAG_DUMP 0x02
                /**
                 * The body contains a list of 16 bits words in network byte
                 * order specifying the vbucket ids to monitor. The first 16
                 * bit word contains the number of buckets. The number of 0
                 * means "all buckets"
                 */
#define TAP_CONNECT_FLAG_LIST_VBUCKETS 0x04
                /**
                 * The responsibility of the vbuckets is to be transferred
                 * over to the caller when all items are transferred.
                 */
#define TAP_CONNECT_FLAG_TAKEOVER_VBUCKETS 0x08
                /**
                 * The tap consumer supports ack'ing of tap messages
                 */
#define TAP_CONNECT_SUPPORT_ACK 0x10
                /**
                 * The tap consumer would prefer to just get the keys
                 * back. If the engine supports this it will set
                 * the TAP_FLAG_NO_VALUE flag in each of the
                 * tap packets returned.
                 */
#define TAP_CONNECT_REQUEST_KEYS_ONLY 0x20
                /**
                 * The body contains a list of (vbucket_id, last_checkpoint_id)
                 * pairs. This provides the checkpoint support in TAP streams.
                 * The last checkpoint id represents the last checkpoint that
                 * was successfully persisted.
                 */
#define TAP_CONNECT_CHECKPOINT 0x40
                /**
                 * The tap consumer is a registered tap client, which means that
                 * the tap server will maintain its checkpoint cursor permanently.
                 */
#define TAP_CONNECT_REGISTERED_CLIENT 0x80
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 4];
    } protocol_binary_request_tap_connect;

    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                struct {
                    uint16_t enginespecific_length;
                    /*
                     * The flag section support the following flags
                     */
                    /**
                     * Request that the consumer send a response packet
                     * for this packet. The opaque field must be preserved
                     * in the response.
                     */
#define TAP_FLAG_ACK 0x01
                    /**
                     * The value for the key is not included in the packet
                     */
#define TAP_FLAG_NO_VALUE 0x02
                    uint16_t flags;
                    uint8_t  ttl;
                    uint8_t  res1;
                    uint8_t  res2;
                    uint8_t  res3;
                } tap;
                struct {
                    uint32_t flags;
                    uint32_t expiration;
                } item;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 16];
    } protocol_binary_request_tap_mutation;

    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                struct {
                    uint16_t enginespecific_length;
                    /**
                     * See the definition of the flags for
                     * protocol_binary_request_tap_mutation for a description
                     * of the available flags.
                     */
                    uint16_t flags;
                    uint8_t  ttl;
                    uint8_t  res1;
                    uint8_t  res2;
                    uint8_t  res3;
                } tap;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + 8];
    } protocol_binary_request_tap_no_extras;

    typedef protocol_binary_request_tap_no_extras protocol_binary_request_tap_delete;
    typedef protocol_binary_request_tap_no_extras protocol_binary_request_tap_flush;
    typedef protocol_binary_request_tap_no_extras protocol_binary_request_tap_opaque;
    typedef protocol_binary_request_tap_no_extras protocol_binary_request_tap_vbucket_set;


    /**
     * Definition of the packet used by the scrub.
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_scrub;

    /**
     * Definition of the packet returned from scrub.
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_scrub;


    /**
     * Definition of the packet used by set vbucket
     */
    typedef union {
        struct {
            protocol_binary_request_header header;
            struct {
                vbucket_state_t state;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_request_header) + sizeof(vbucket_state_t)];
    } protocol_binary_request_set_vbucket;
    /**
     * Definition of the packet returned from set vbucket
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_set_vbucket;
    /**
     * Definition of the packet used by del vbucket
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_del_vbucket;
    /**
     * Definition of the packet returned from del vbucket
     */
    typedef protocol_binary_response_no_extras protocol_binary_response_del_vbucket;

    /**
     * Definition of the packet used by get vbucket
     */
    typedef protocol_binary_request_no_extras protocol_binary_request_get_vbucket;

    /**
     * Definition of the packet returned from get vbucket
     */
    typedef union {
        struct {
            protocol_binary_response_header header;
            struct {
                vbucket_state_t state;
            } body;
        } message;
        uint8_t bytes[sizeof(protocol_binary_response_header) + sizeof(vbucket_state_t)];
    } protocol_binary_response_get_vbucket;


    /**
     * @}
     */

#ifdef __cplusplus
}
#endif
#endif /* PROTOCOL_BINARY_H */

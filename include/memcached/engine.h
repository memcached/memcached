/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_ENGINE_H
#define MEMCACHED_ENGINE_H

#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>

#include "memcached/protocol_binary.h"

#ifdef __cplusplus
extern "C" {
#endif

/*! \mainpage memcached public API
 *
 * \section intro_sec Introduction
 *
 * The memcached project provides an API for providing engines as well
 * as data definitions for those implementing the protocol in C.  This
 * documentation will explain both to you.
 *
 * \section docs_sec API Documentation
 *
 * Jump right into <a href="modules.html">the modules docs</a> to get started.
 *
 * \example default_engine.c
 */

/**
 * \defgroup Engine Storage Engine API
 * \defgroup Protex Protocol Extension API
 * \defgroup Protocol Binary Protocol Structures
 *
 * \addtogroup Engine
 * @{
 *
 * Most interesting here is to implement engine_interface_v1 for your
 * engine.
 */

#define ENGINE_INTERFACE_VERSION 1

    /**
     * Response codes for engine operations.
     */
    typedef enum {
        ENGINE_SUCCESS     = 0x00, /**< The command executed successfully */
        ENGINE_KEY_ENOENT  = 0x01, /**< The key does not exists */
        ENGINE_KEY_EEXISTS = 0x02, /**< The key already exists */
        ENGINE_ENOMEM      = 0x03, /**< Could not allocate memory */
        ENGINE_NOT_STORED  = 0x04, /**< The item was not stored */
        ENGINE_EINVAL      = 0x05, /**< Invalid arguments */
        ENGINE_ENOTSUP     = 0x06, /**< The engine does not support this */
        ENGINE_EWOULDBLOCK = 0x07, /**< This would cause the engine to block */
        ENGINE_E2BIG       = 0x08, /**< The data is too big for the engine */
        ENGINE_WANT_MORE   = 0x09, /**< The engine want more data if the frontend
                                    * have more data available. */
        ENGINE_FAILED      = 0xff  /**< Generic failue. */
    } ENGINE_ERROR_CODE;

    /**
     * Engine storage operations.
     */
    typedef enum {
        OPERATION_ADD = 1, /**< Store with add semantics */
        OPERATION_SET,     /**< Store with set semantics */
        OPERATION_REPLACE, /**< Store with replace semantics */
        OPERATION_APPEND,  /**< Store with append semantics */
        OPERATION_PREPEND, /**< Store with prepend semantics */
        OPERATION_CAS      /**< Store with set semantics. */
    } ENGINE_STORE_OPERATION;

    /**
     * Event types for callbacks to the engine indicating state
     * changes in the server.
     */
    typedef enum {
        ON_CONNECT,    /**< A new connection was established. */
        ON_DISCONNECT, /**< A connection was terminated. */
        ON_AUTH        /**< A connection was authenticated */
    } ENGINE_EVENT_TYPE;

    /**
     * Time relative to server start. Smaller than time_t on 64-bit systems.
     */
    typedef uint32_t rel_time_t;

    /**
     * Data common to any item stored in memcached.
     */
    typedef struct {
        rel_time_t exptime; /**< When the item will expire (relative to process
                             * startup) */
        uint32_t   nbytes;  /**< The total size of the data (in bytes) */
        uint32_t   flags;   /**< Flags associated with the item */
        uint16_t   nkey;    /**< The total length of the key (in bytes) */
        uint16_t   iflag;   /**< Intermal flags. lower 8 bit is reserved for the core
                             * server, the upper 8 bits is reserved for engine
                             * implementation. */
    } item;

    /**
     * Callback for any function producing stats.
     *
     * @param key the stat's key
     * @param klen length of the key
     * @param val the stat's value in an ascii form (e.g. text form of a number)
     * @param vlen length of the value
     * @param cookie magic callback cookie
     */
    typedef void (*ADD_STAT)(const char *key, const uint16_t klen,
                             const char *val, const uint32_t vlen,
                             const void *cookie);

    /**
     * Callback for adding a response backet
     * @param key The key to put in the response
     * @param keylen The length of the key
     * @param ext The data to put in the extended field in the response
     * @param extlen The number of bytes in the ext field
     * @param body The data body
     * @param bodylen The number of bytes in the body
     * @param datatype This is currently not used and should be set to 0
     * @param status The status code of the return packet (see in protocol_binary
     *               for the legal values)
     * @param cas The cas to put in the return packet
     * @param cookie The cookie provided by the frontend
     * @return true if return message was successfully created, false if an
     *              error occured that prevented the message from being sent
     */
    typedef bool (*ADD_RESPONSE)(const void *key, uint16_t keylen,
                                 const void *ext, uint8_t extlen,
                                 const void *body, uint32_t bodylen,
                                 uint8_t datatype, uint16_t status,
                                 uint64_t cas, const void *cookie);

    /**
     * Callback for server events.
     *
     * @param cookie The cookie provided by the frontend
     * @param type the type of event
     * @param event_data additional event-specific data.
     */
    typedef void (*EVENT_CALLBACK)(const void *cookie,
                                   ENGINE_EVENT_TYPE type,
                                   const void *event_data);

    /**
     * Abstract interface to an engine.
     */
    typedef struct engine_interface {
        uint64_t interface; /**< The version number on the engine structure */
    } ENGINE_HANDLE;

    /**
     * Interface to the server.
     */
    typedef struct server_interface_v1 {

        /**
         * Register an event callback.
         *
         * @param type the type of event to register
         * @param cb the callback to fire when the event occurs
         */
        void (*register_callback)(ENGINE_EVENT_TYPE type,
                                  EVENT_CALLBACK cb);

        /**
         * Get the auth data for the connection associated with the
         * given cookie.
         *
         * @param cookie The cookie provided by the frontend
         *
         * @return a principal name, or NULL if the connection is not
         *         authenticated
         */
        const char* (*get_auth_data)(const void *cookie);

        /**
         * Get the server's version number.
         *
         * @return the server's version number
         */
        const char* (*server_version)();

        /**
         * Generate a simple hash value of a piece of data.
         *
         * @param data pointer to data to hash
         * @param size size of the data to generate the hash value of
         * @param seed an extra seed value for the hash function
         * @return hash value of the data.
         */
        uint32_t (*hash)(const void *data, size_t size, uint32_t seed);

        /**
         * Get the relative time for the given time_t value.
         */
        rel_time_t (*realtime)(const time_t exptime);


        /**
         * Let a connection know that IO has completed.
         * @param cookie cookie representing the connection
         * @param status the status for the io operation
         */
        void (*notify_io_complete)(const void *cookie,
                                   ENGINE_ERROR_CODE status);

        /**
         * The current time.
         */
        rel_time_t (*get_current_time)(void);
    } SERVER_HANDLE_V1;

    typedef void* (*GET_SERVER_API)(int interface);

    /**
     * The signature for the "create_instance" function exported from the module.
     *
     * This function should fill out an engine inteface structure according to
     * the interface parameter (Note: it is possible to return a lower version
     * number).
     *
     * @param interface The highest interface level the server supports
     * @param get_server_api function to get the server API from
     * @param Where to store the interface handle
     * @return See description of ENGINE_ERROR_CODE
     */
    typedef ENGINE_ERROR_CODE (*CREATE_INSTANCE)(uint64_t interface,
                                                 GET_SERVER_API get_server_api,
                                                 ENGINE_HANDLE** handle);


    /**
     * Definition of the first version of the engine interface
     */
    typedef struct engine_interface_v1 {
        /**
         * Engine info.
         */
        struct engine_interface interface;

        /**
         * Get a description of this engine.
         *
         * @param handle the engine handle
         * @return a stringz description of this engine
         */
        const char* (*get_info)(ENGINE_HANDLE* handle);

        /**
         * Initialize an engine instance.
         * This is called *after* creation, but before the engine may be used.
         *
         * @param handle the engine handle
         * @param config_str configuration this engine needs to initialize itself.
         */
        ENGINE_ERROR_CODE (*initialize)(ENGINE_HANDLE* handle,
                                        const char* config_str);

        /**
         * Tear down this engine.
         *
         * @param handle the engine handle
         */
        void (*destroy)(ENGINE_HANDLE* handle);

        /*
         * Item operations.
         */

        /**
         * Allocate an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param output variable that will receive the item
         * @param key the item's key
         * @param nkey the length of the key
         * @param nbytes the number of bytes that will make up the
         *        value of this item.
         * @param flags the item's flags
         * @param exptime the maximum lifetime of this item
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*allocate)(ENGINE_HANDLE* handle,
                                      const void* cookie,
                                      item **item,
                                      const void* key,
                                      const size_t nkey,
                                      const size_t nbytes,
                                      const int flags,
                                      const rel_time_t exptime);

        /**
         * Remove an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param item the item to be removed
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*remove)(ENGINE_HANDLE* handle,
                                    const void* cookie,
                                    item* item);

        /**
         * Indicate that a caller who received an item no longer needs
         * it.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param item the item to be released
         */
        void (*release)(ENGINE_HANDLE* handle, const
                        void *cookie,
                        item* item);

        /**
         * Retrieve an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param item output variable that will receive the located item
         * @param key the key to look up
         * @param nkey the length of the key
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*get)(ENGINE_HANDLE* handle,
                                 const void* cookie,
                                 item** item,
                                 const void* key,
                                 const int nkey);

        /**
         * Store an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param item the item to store
         * @param cas the CAS value for conditional sets
         * @param operation the type of store operation to perform.
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*store)(ENGINE_HANDLE* handle,
                                   const void *cookie,
                                   item* item,
                                   uint64_t *cas,
                                   ENGINE_STORE_OPERATION operation);

        /**
         * Perform an increment or decrement operation on an item.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param key the key to look up
         * @param nkey the length of the key
         * @param increment if true, increment the value, else decrement
         * @param create if true, create the item if it's missing
         * @param delta the amount to increment or decrement.
         * @param initial when creating, specifies the initial value
         * @param exptime when creating, specifies the expiration time
         * @param cas output CAS value
         * @param result output arithmetic value
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*arithmetic)(ENGINE_HANDLE* handle,
                                        const void* cookie,
                                        const void* key,
                                        const int nkey,
                                        const bool increment,
                                        const bool create,
                                        const uint64_t delta,
                                        const uint64_t initial,
                                        const rel_time_t exptime,
                                        uint64_t *cas,
                                        uint64_t *result);

        /**
         * Flush the cache.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param when time at which the flush should take effect
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*flush)(ENGINE_HANDLE* handle,
                                   const void* cookie, time_t when);

        /*
         * Statistics
         */

        /**
         * Get statistics from the engine.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param stat_key optional argument to stats
         * @param nkey the length of the stat_key
         * @param add_stat callback to feed results to the output
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*get_stats)(ENGINE_HANDLE* handle,
                                       const void* cookie,
                                       const char* stat_key,
                                       int nkey,
                                       ADD_STAT add_stat);

        /**
         * Reset the stats.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         */
        void (*reset_stats)(ENGINE_HANDLE* handle, const void *cookie);

        /**
         * Any unknown command will be considered engine specific.
         *
         * @param handle the engine handle
         * @param cookie The cookie provided by the frontend
         * @param request pointer to request header to be filled in
         * @param response function to transmit data
         *
         * @return ENGINE_SUCCESS if all goes well
         */
        ENGINE_ERROR_CODE (*unknown_command)(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             protocol_binary_request_header *request,
                                             ADD_RESPONSE response);

        /*
         * It is up to the engine writers how to store the data in the engine
         */

        /**
         * Get the CAS ID from an item.
         */
        uint64_t (*item_get_cas)(const item *item);

        /**
         * Set the CAS id on an item.
         */
        void (*item_set_cas)(item *item, uint64_t cas);

        /**
         * Get the key from an item.
         */
        const char* (*item_get_key)(const item *item);

        /**
         * Get the data from an item.
         */
        char* (*item_get_data)(const item *item);

        /**
         * Get an item's class ID.
         */
        uint8_t (*item_get_clsid)(const item* item);
    } ENGINE_HANDLE_V1;

    /**
     * @}
     */

#ifdef __cplusplus
}
#endif

#endif

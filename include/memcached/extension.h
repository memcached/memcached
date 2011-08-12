/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_EXTENSION_H
#define MEMCACHED_EXTENSION_H

#ifndef __cplusplus
#include <stdbool.h>
#endif

#include <stdint.h>
#include <memcached/engine_common.h>
#include <memcached/protocol_binary.h>
#include <memcached/types.h>
#include <memcached/server_api.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \defgroup Extension Generic Extensions API
     * \addtogroup Extension
     * @{
     *
     * Definition of the generic extension API to memcached.
     */

    /**
     * Response codes for extension operations.
     */
    typedef enum {
        /** The command executed successfully */
        EXTENSION_SUCCESS     = 0x00,
        /** A fatal error occurred, and the server should shut down as soon
         * as possible */
        EXTENSION_FATAL       = 0xfe,
        /** Generic failure. */
        EXTENSION_FAILED      = 0xff
    } EXTENSION_ERROR_CODE;

    typedef enum {
        /**
         * A generic extention that don't provide a functionality to the
         * memcached core, but lives in the memcached address space.
         */
        EXTENSION_DAEMON = 0x00,
        /**
         * A log consumer
         */
        EXTENSION_LOGGER,
        /**
         * Command extension for the ASCII protocol
         */
        EXTENSION_ASCII_PROTOCOL,
        /**
         * Command extension for the binary protocol
         */
        EXTENSION_BINARY_PROTOCOL
    } extension_type_t;

    /**
     * Deamon extensions should provide the following descriptor when
     * they register themselves.
     */
    typedef struct extension_daemon_descriptor {
        /**
         * Get the name of the descriptor. The memory area returned by this
         * function has to be valid until the descriptor is unregistered.
         */
        const char* (*get_name)(void);

        /**
         * Deamon descriptors are stored in a linked list in the memcached
         * core by using this pointer. Please do not modify this pointer
         * by yourself until you have unregistered the descriptor.
         * The <b>only</b> time it is safe for an extension to walk this
         * list is during initialization of the modules.
         */
        struct extension_daemon_descriptor *next;
    } EXTENSION_DAEMON_DESCRIPTOR;

    typedef enum {
        EXTENSION_LOG_DETAIL,
        EXTENSION_LOG_DEBUG,
        EXTENSION_LOG_INFO,
        EXTENSION_LOG_WARNING
    } EXTENSION_LOG_LEVEL;

    /**
     * Log extensions should provide the following rescriptor when
     * they register themselves. Please note that if you register a log
     * extension it will <u>replace</u> old one. If you want to be nice to
     * the user you should allow your logger to be chained.
     *
     * Please note that the memcached server will <b>not</b> call the log
     * function if the verbosity level is too low. This is a perfomance
     * optimization from the core to avoid potential formatting of output
     * that may be thrown away.
     */
    typedef struct {
        /**
         * Get the name of the descriptor. The memory area returned by this
         * function has to be valid until the descriptor is unregistered.
         */
        const char* (*get_name)(void);

        /**
         * Add an entry to the log.
         * @param severity the severity for this log entry
         * @param client_cookie the client we're serving (may be NULL if not
         *                      known)
         * @param fmt format string to add to the log
         */
        void (*log)(EXTENSION_LOG_LEVEL severity,
                    const void* client_cookie,
                    const char *fmt, ...);
    } EXTENSION_LOGGER_DESCRIPTOR;

    typedef struct {
        EXTENSION_LOGGER_DESCRIPTOR* (*get_logger)(void);
        EXTENSION_LOG_LEVEL (*get_level)(void);
        void (*set_level)(EXTENSION_LOG_LEVEL severity);
    } SERVER_LOG_API;

    typedef struct {
        char *value;
        size_t length;
    } token_t;

    /**
     * ASCII protocol extensions must provide the following descriptor to
     * extend the capabilities of the ascii protocol. The memcached core
     * will probe each command in the order they are registered, so you should
     * register the most likely command to be used first (or you could register
     * only one descriptor and do a better dispatch routine inside your own
     * implementation of accept / execute).
     */
    typedef struct extension_ascii_protocol_descriptor {
        /**
         * Get the name of the descriptor. The memory area returned by this
         * function has to be valid until the descriptor is unregistered.
         *
         * @param cmd_cookie cookie registered with the command
         */
        const char* (*get_name)(const void *cmd_cookie);

        /**
         * Called by the server to determine if the command in argc, argv should
         * be process by this handler.
         *
         * If the command accepts out-of-band data (like add / append / prepend
         * / replace / set), the command must set the datapointer and ndata
         * to the number of bytes it want to read (remember to account for
         * the trailing "\r\n" ;-))
         *
         * If you need extra data, you should copy all of the argc/argv info
         * you may need to execute the command, because those parameters will
         * be 0 and NULL when execute is invoked...
         *
         * @param cmd_cookie cookie registered with the command
         * @param cookie identifying the client connection
         * @param argc the number of arguments
         * @param argv the argument vector
         * @param ndata the number of bytes in out-of-band data (OUT)
         * @param ptr where the core shall write the data (OUT)
         * @param noreply is this a noreply command or not...
         * @return true if the command should be handled by this command handler
         */
        bool (*accept)(const void *cmd_cookie,
                       void *cookie,
                       int argc,
                       token_t *argv,
                       size_t *ndata,
                       char **ptr);

        /**
         * execute the command.
         *
         * @param cmd_cookie cookie registered with the command
         * @param cookie identifying the client connection
         * @param argc the number of arguments
         * @param argv the argument vector
         * @param response_handler callback to add data to the return buffer
         * @return Error code for the operation
         */
        ENGINE_ERROR_CODE (*execute)(const void *cmd_cookie,
                                     const void *cookie,
                                     int argc, token_t *argv,
                                     ENGINE_ERROR_CODE (*response_handler)(const void *cookie,
                                                                           int nbytes,
                                                                           const char *dta));

        /**
         * abort the command.
         *
         * @param cmd_cookie cookie registered with the command
         * @param cookie identifying the client connection
         */
        void (*abort)(const void *cmd_cookie, const void *cookie);

        /**
         * cookie for the command. This is the cookie passed to accept and
         * execute, so that you can register the same functions for multiple
         * commands (but tell them apart during invokations).
         */
        const void *cookie;

        /**
         * Deamon descriptors are stored in a linked list in the memcached
         * core by using this pointer. Please do not modify this pointer
         * by yourself until you have unregistered the descriptor.
         * The <b>only</b> time it is safe for an extension to walk this
         * list is during initialization of the modules.
         */
        struct extension_ascii_protocol_descriptor *next;
    } EXTENSION_ASCII_PROTOCOL_DESCRIPTOR;


    typedef struct extension_binary_protocol_descriptor EXTENSION_BINARY_PROTOCOL_DESCRIPTOR;

    typedef ENGINE_ERROR_CODE (*BINARY_COMMAND_CALLBACK)(EXTENSION_BINARY_PROTOCOL_DESCRIPTOR *descriptor,
                                                         ENGINE_HANDLE* handle,
                                                         const void* cookie,
                                                         protocol_binary_request_header *request,
                                                         ADD_RESPONSE response);

    /**
     * ASCII protocol extensions must provide the following descriptor to
     * extend the capabilities of the ascii protocol. The memcached core
     * will probe each command in the order they are registered, so you should
     * register the most likely command to be used first (or you could register
     * only one descriptor and do a better dispatch routine inside your own
     * implementation of accept / execute).
     */
    struct extension_binary_protocol_descriptor {
        /**
         * Get the name of the descriptor. The memory area returned by this
         * function has to be valid until the descriptor is unregistered.
         */
        const char* (*get_name)(void);

        void (*setup)(void (*add)(EXTENSION_BINARY_PROTOCOL_DESCRIPTOR *descriptor,
                                  uint8_t cmd,
                                  BINARY_COMMAND_CALLBACK new_handler));

        /**
         * Deamon descriptors are stored in a linked list in the memcached
         * core by using this pointer. Please do not modify this pointer
         * by yourself until you have unregistered the descriptor.
         * The <b>only</b> time it is safe for an extension to walk this
         * list is during initialization of the modules.
         */
        struct extension_binary_protocol_descriptor *next;
    };

    /**
     * The signature for the "memcached_extensions_initialize" function
     * exported from the loadable module.
     *
     * @param config configuration for this extension
     * @param GET_SERVER_API pointer to a function to get a specific server
     *                       API from. server_extension_api contains functions
     *                       to register extensions.
     * @return one of the error codes above.
     */
    typedef EXTENSION_ERROR_CODE (*MEMCACHED_EXTENSIONS_INITIALIZE)(const char *config, GET_SERVER_API get_server_api);


    /**
     * The API provided by the server to manipulate the list of server
     * server extensions.
     */
    typedef struct {
        /**
         * Register an extension
         *
         * @param type The type of extension to register (ex: daemon, logger etc)
         * @param extension The extension to register
         * @return true if success, false otherwise
         */
        bool (*register_extension)(extension_type_t type, void *extension);

        /**
         * Unregister an extension
         *
         * @param type The type of extension to unregister
         * @param extension The extension to unregister
         */
        void (*unregister_extension)(extension_type_t type, void *extension);

        /**
         * Get the registered extension for a certain type. This is useful
         * if you would like to replace one of the handlers with your own
         * extension to proxy functionality.
         *
         * @param type The type of extension to get
         * @param extension Pointer to the registered event. Please note that
         *        if the extension allows for multiple instances of the
         *        extension there will be a "next" pointer inside the element
         *        that can be used for object traversal.
         */
        void *(*get_extension)(extension_type_t type);
    } SERVER_EXTENSION_API;

    /**
     * @}
     */

#ifdef __cplusplus
}
#endif

#endif

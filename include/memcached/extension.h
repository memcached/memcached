/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#ifndef MEMCACHED_EXTENSION_H
#define MEMCACHED_EXTENSION_H

#include <stdbool.h>
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

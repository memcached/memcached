/*
 * Protocol plugin defintions.
 */

#ifndef PROTOCOL_PLUGIN_H
#define PROTOCOL_PLUGIN_H 1

/**
 * \addtogroup Protex
 * @{
 */

/**
 * Response transmission function.
 *
 * @param responder_data context data for the responder
 * @param hdr response header
 * @param data response data
 * @param data_len length of the response data
 */
typedef void (*cb_responder)(responder_ctx *responder_data,
                             protocol_binary_response_header *hdr,
                             char *data,
                             size_t data_len);

/**
 * Unique connection identifier.
 */
typedef int connection_id;

/**
 * Plugin callback responses.
 */
enum plugin_cb_result {
    cb_done,    /**< Indicate this command has completed. */
    cb_defer,   /**< Indicate this command requires further processing. */
    cb_hangup,  /**< Disconnect this connection. */
};

/**
 * Callback fired when a message is completely received.
 *
 * @param userdata user data included during registration
 * @param connection_id connection identifier
 * @param responder responder for transmitting a result
 * @param responder_data responder's context data
 * @param hdr the request header
 * @param data the request data
 * @param the length of the request data
 *
 * @return execution status indicator
 */
typedef enum plugin_cb_result (*plugin_cb)(void *userdata,
                                           connection_id conn_id,
                                           cb_responder responder,
                                           responder_ctx *responder_data,
                                           protocol_binary_response_header *hdr,
                                           char *data,
                                           size_t data_len);

/**
 * Type of state change being observed.
 */
enum plugin_cb_state {
    cb_connected,    /**< Indicating a connection has been established. */
    cb_disconnected  /**< Indicating a connection has been lost. */
};

/**
 * Callback fired when a connection changes state.
 *
 * @param userdata private user data
 * @param state the state being observed
 * @param conn_id the ID of the connection that changed the state
 */
typedef void (*plugin_conn_observer)(void *userdata,
                                     enum plugin_cb_state state,
                                     connection_id conn_id);

/**
 * Register a callback for the given command.
 *
 * @param cmd_id the ID of the command to handle
 * @param callback the callback to handle this command
 * @param userdata user data to be supplied to the callback
 */
void plugin_register_callback(uint8_t cmd_id,
                              plugin_cb callback,
                              void *userdata);

/**
 * Retrieve the current callback info for the given command.
 *
 * @param cmd_id the command whose callback info we'd like to retrieve
 * @param current_callback the current callback function (may be NULL)
 * @param current_userdata the current callback's user data (may be NULL)
 */
void plugin_get_callback(int8_t cmd_id,
                         plugin_cb *current_callback,
                         void **current_userdata);

/**
 * Register a connection observer.
 *
 * @param userdata observation parameters
 * @param obs the observer
 */
void plugin_register_conn_observer(void *userdata,
                                   plugin_conn_observer obs);

/**
 * Unregister a connection observer.
 *
 * @param obs the observer
 */
void plugin_unregister_conn_observer(plugin_conn_observer obs);

/**
 * @}
 */

#endif PROTOCOL_PLUGIN_H

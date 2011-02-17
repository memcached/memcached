/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <memcached/extension.h>
#include <memcached/extension_loggers.h>
#include <memcached/engine.h>

static EXTENSION_LOG_LEVEL current_log_level = EXTENSION_LOG_WARNING;
SERVER_HANDLE_V1 *sapi;

static const char *stderror_get_name(void) {
    return "standard error";
}

static void stderror_logger_log(EXTENSION_LOG_LEVEL severity,
                                const void* client_cookie,
                                const char *fmt, ...)
{
    if (severity >= current_log_level) {
        (void)client_cookie;
        int len = strlen(fmt);
        bool needlf = (len > 0 && fmt[len - 1] != '\n');
        va_list ap;
        va_start(ap, fmt);
        vfprintf(stderr, fmt, ap);
        va_end(ap);
        if (needlf) {
            fprintf(stderr, "\n");
        }
        fflush(stderr);
    }
}

static EXTENSION_LOGGER_DESCRIPTOR stderror_logger_descriptor = {
    .get_name = stderror_get_name,
    .log = stderror_logger_log
};

static void on_log_level(const void *cookie,
                         ENGINE_EVENT_TYPE type,
                         const void *event_data,
                         const void *cb_data) {
    if (sapi != NULL) {
        current_log_level = sapi->log->get_level();
    }
}

EXTENSION_ERROR_CODE memcached_initialize_stderr_logger(GET_SERVER_API get_server_api) {
    sapi = get_server_api();
    if (sapi == NULL) {
        return EXTENSION_FATAL;
    }

    current_log_level = sapi->log->get_level();
    sapi->callback->register_callback(NULL, ON_LOG_LEVEL,
                                      on_log_level, NULL);

    return EXTENSION_SUCCESS;
}

static const char *null_get_name(void) {
    return "/dev/null";
}

static void null_logger_log(EXTENSION_LOG_LEVEL severity,
                            const void* client_cookie,
                            const char *fmt, ...)
{
    (void)severity;
    (void)client_cookie;
    (void)fmt;
    /* EMPTY */
}

static EXTENSION_LOGGER_DESCRIPTOR null_logger_descriptor = {
    .get_name = null_get_name,
    .log = null_logger_log
};

EXTENSION_LOGGER_DESCRIPTOR* get_null_logger(void) {
    return &null_logger_descriptor;
}

EXTENSION_LOGGER_DESCRIPTOR* get_stderr_logger(void) {
    return &stderror_logger_descriptor;
}

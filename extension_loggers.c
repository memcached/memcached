/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdarg.h>
#include <stdio.h>
#include <memcached/extension.h>
#include <memcached/extension_loggers.h>

static const char *stderror_get_name(void) {
    return "standard error";
}

static void stderror_logger_log(EXTENSION_LOG_LEVEL severity,
                                 const void* client_cookie,
                                 const char *fmt, ...)
{
    (void)severity;
    (void)client_cookie;

    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

EXTENSION_LOGGER_DESCRIPTOR stderror_logger_descriptor = {
    .get_name = stderror_get_name,
    .log = stderror_logger_log
};

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

EXTENSION_LOGGER_DESCRIPTOR null_logger_descriptor = {
    .get_name = null_get_name,
    .log = null_logger_log
};

EXTENSION_LOGGER_DESCRIPTOR* get_null_logger(void) {
    return &null_logger_descriptor;
}

EXTENSION_LOGGER_DESCRIPTOR* get_stderr_logger(void) {
    return &stderror_logger_descriptor;
}

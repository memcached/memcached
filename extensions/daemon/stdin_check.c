/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "protocol_extension.h"

union c99hack {
    void *pointer;
    void (*exit_function)(void);
};

static void* check_stdin_thread(void* arg)
{
    pthread_detach(pthread_self());

    while (!feof(stdin)) {
        getc(stdin);
    }

    fprintf(stderr, "EOF on stdin.  Exiting\n");
    union c99hack ch = { .pointer = arg };
    ch.exit_function();
    /* NOTREACHED */
    return NULL;
}

static const char *get_name(void) {
    return "stdin_check";
}

static EXTENSION_DAEMON_DESCRIPTOR descriptor = {
    .get_name = get_name
};

MEMCACHED_PUBLIC_API
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api) {

    SERVER_HANDLE_V1 *server = get_server_api();
    if (server == NULL) {
        return EXTENSION_FATAL;
    }

    if (!server->extension->register_extension(EXTENSION_DAEMON, &descriptor)) {
        return EXTENSION_FATAL;
    }

    union c99hack ch = { .exit_function = server->core->shutdown };

    pthread_t t;
    if (pthread_create(&t, NULL, check_stdin_thread, ch.pointer) != 0) {
        perror("couldn't create stdin checking thread.");
        server->extension->unregister_extension(EXTENSION_DAEMON, &descriptor);
        return EXTENSION_FATAL;
    }

    return EXTENSION_SUCCESS;
}

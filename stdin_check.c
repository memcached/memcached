/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include "stdin_check.h"

static void* check_stdin_thread(void* arg)
{
    pthread_detach(pthread_self());

    while (!feof(stdin)) {
        getc(stdin);
    }

    fprintf(stderr, "EOF on stdin.  Exiting\n");
    exit(0);
    /* NOTREACHED */
    return NULL;
}

static const char *get_name(void) {
    return "stdin_check";
}

static EXTENSION_DAEMON_DESCRIPTOR descriptor = {
    .get_name = get_name
};

#if defined (__SUNPRO_C) && (__SUNPRO_C >= 0x550)
__global
#elif defined __GNUC__
__attribute__ ((visibility("default")))
#endif
EXTENSION_ERROR_CODE memcached_extensions_initialize(const char *config,
                                                     GET_SERVER_API get_server_api) {

    SERVER_HANDLE_V1 *server = get_server_api();
    if (server == NULL) {
        return EXTENSION_FATAL;
    }

    if (!server->extension->register_extension(EXTENSION_DAEMON, &descriptor)) {
        return EXTENSION_FATAL;
    }

    pthread_t t;
    if (pthread_create(&t, NULL, check_stdin_thread, NULL) != 0) {
        perror("couldn't create stdin checking thread.");
        server->extension->unregister_extension(EXTENSION_DAEMON, &descriptor);
        return EXTENSION_FATAL;
    }

    return EXTENSION_SUCCESS;
}

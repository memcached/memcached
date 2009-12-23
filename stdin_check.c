#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sysexits.h>
#include <assert.h>

#include <event.h>
#include <pthread.h>

#include "memcached.h"

static void check_stdin_event(int fd, short event, void *arg)
{
    char buf[100];
    int bytesread = read(STDIN_FILENO, buf, sizeof(buf));
    buf[bytesread] = '\0';

    if (settings.verbose > 1) {
        fprintf(stderr, "Received %d bytes from stdin (%s)\n",
                bytesread, buf);
    }

    if (bytesread == 0) {
        if (settings.verbose > 0) {
            fprintf(stderr, "stdin closed, exiting.\n");
        }
        exit(0);
    }
}

static void init_check_stdin_event(struct event_base *base)
{
    static struct event stdin_event;
    if (fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK) != 0) {
        perror("fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK)");
        exit(EX_OSERR);
    }

    event_set(&stdin_event, STDIN_FILENO, EV_READ | EV_PERSIST,
              check_stdin_event, NULL);
    event_base_set(base, &stdin_event);

    if (event_add(&stdin_event, NULL) != 0) {
        perror("Error adding event checking for stdin.\n");
        exit(EX_OSERR);
    }
}

static void* check_stdin_thread(void* arg)
{
    while (!feof(stdin)) {
        getc(stdin);
    }

    fprintf(stderr, "EOF on stdin.  Exiting\n");
    exit(0);
    /* NOTREACHED */
    return NULL;
}

static void init_check_stdin_thread(void)
{
    static pthread_t t;
    if(pthread_create(&t, NULL, check_stdin_thread, NULL) != 0) {
        perror("couldn't create stdin checking thread.");
        exit(EX_OSERR);
    }
}

void init_check_stdin(struct event_base *base)
{
    char *type = getenv("MEMCACHED_CHECK_STDIN");
    if (!type) {
        return;
    }

    if (strcmp(type, "event") == 0) {
        init_check_stdin_event(base);
    } else if (strcmp(type, "thread") == 0) {
        init_check_stdin_thread();
    } else {
        fprintf(stderr, "Unknown stdin check type:  %s "
                "(supported types: event, thread)\n", type);
        exit(EX_USAGE);
    }
}

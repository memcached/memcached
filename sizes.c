#include "config.h"
#include <stdio.h>

#include "memcached.h"

static void display(const char *name, size_t size) {
    printf("%s\t%d\n", name, (int)size);
}

int main(int argc, char **argv) {

    display("Slab Stats", sizeof(struct slab_stats));
    display("Thread stats",
            sizeof(struct thread_stats)
            - (200 * sizeof(struct slab_stats)));
    display("Global stats", sizeof(struct stats));
    display("Settings", sizeof(struct settings));
    display("Libevent thread",
            sizeof(LIBEVENT_THREAD));
    display("Connection", sizeof(conn));

    printf("----------------------------------------\n");

    display("libevent thread cumulative", sizeof(LIBEVENT_THREAD));
    display("Thread stats cumulative\t", sizeof(struct thread_stats));

    return 0;
}

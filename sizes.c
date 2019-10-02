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
    display("Item (no cas)", sizeof(item));
    display("Item (cas)", sizeof(item) + sizeof(uint64_t));
    display("Libevent thread",
            sizeof(LIBEVENT_THREAD) - sizeof(struct thread_stats));
    display("Connection", sizeof(conn));

    printf("----------------------------------------\n");

    display("libevent thread cumulative", sizeof(LIBEVENT_THREAD));
    display("Thread stats cumulative\t", sizeof(struct thread_stats));

    return 0;
}

#include <stdio.h>

#include "memcached.h"

static void display(const char *name, size_t size) {
    printf("%s\t%d\n", name, (int)size);
}

int main(int argc, char **argv) {

    display("Slab Stats", sizeof(struct slab_stats));
    display("Thread stats",
            sizeof(struct thread_stats)
            - (MAX_NUMBER_OF_SLAB_CLASSES * sizeof(struct slab_stats)));
    display("Global stats", sizeof(struct stats));
    display("Settings", sizeof(struct settings));
    display("Item (no cas)", sizeof(item));
    display("Item (cas)", sizeof(item) + sizeof(uint64_t));
#ifdef EXTSTORE
    display("extstore header", sizeof(item_hdr));
#endif
    display("Libevent thread",
            sizeof(LIBEVENT_THREAD) - sizeof(struct thread_stats));
    display("Connection", sizeof(conn));
    display("Response object", sizeof(mc_resp));
    display("Response bundle", sizeof(mc_resp_bundle));
    display("Response objects per bundle", MAX_RESP_PER_BUNDLE);

    printf("----------------------------------------\n");

    display("libevent thread cumulative", sizeof(LIBEVENT_THREAD));
    display("Thread stats cumulative\t", sizeof(struct thread_stats));

    return 0;
}

#include "memcached.h"
#include <stdio.h>
#include <stdlib.h>

static sasl_callback_t sasl_callbacks[] = {
    {
        SASL_CB_LIST_END, NULL, NULL
    }
};

void init_sasl(void) {
    if (sasl_server_init(sasl_callbacks, "memcached") != SASL_OK) {
        fprintf(stderr, "Error initializing sasl.\n");
        exit(EXIT_FAILURE);
    } else {
        if (settings.verbose) {
            fprintf(stderr, "Initialized SASL.\n");
        }
    }
}

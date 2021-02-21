#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sandbox.h>
#include "memcached.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
/*
 * the sandbox api is marked deprecated, however still used
 * by couple of major softwares/libraries like openssh
 */
void drop_privileges() {
    extern char *__progname;
    char *error = NULL;

    if (sandbox_init(kSBXProfileNoInternet, SANDBOX_NAMED, &error) < 0) {
        fprintf(stderr, "%s: sandbox_init: %s\n", __progname, error);
        sandbox_free_error(error);
        exit(EXIT_FAILURE);
    }
}

#pragma clang diagnostic pop

void setup_privilege_violations_handler(void) {
   // not needed
}

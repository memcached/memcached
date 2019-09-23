#include <sys/capsicum.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "memcached.h"

/*
 * dropping privileges is entering in capability mode
 * in FreeBSD vocabulary.
 */
void drop_privileges() {
    if (cap_enter() != 0) {
        fprintf(stderr, "cap_enter failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void setup_privilege_violations_handler(void) {
   // not needed
}

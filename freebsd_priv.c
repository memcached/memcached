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
    cap_rights_t wd, rd;

    if (cap_rights_init(&wd, CAP_WRITE, CAP_READ) == NULL) {
        fprintf(stderr, "cap_rights_init write protection failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (cap_rights_init(&rd, CAP_FCNTL, CAP_READ, CAP_EVENT) == NULL) {
        fprintf(stderr, "cap_rights_init read protection failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (cap_rights_limit(STDIN_FILENO, &rd) != 0) {
        fprintf(stderr, "cap_rights_limit stdin failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (cap_rights_limit(STDOUT_FILENO, &wd) != 0) {
        fprintf(stderr, "cap_rights_limit stdout failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (cap_rights_limit(STDERR_FILENO, &wd) != 0) {
        fprintf(stderr, "cap_rights_limit stderr failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (cap_enter() != 0) {
        fprintf(stderr, "cap_enter failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

void setup_privilege_violations_handler(void) {
   // not needed
}

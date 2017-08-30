#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "memcached.h"

/*
 * this section of code will drop all (OpenBSD) privileges including
 * those normally granted to all userland process (basic privileges). The
 * effect of this is that after running this code, the process will not able
 * to fork(), exec(), etc.  See pledge(2) for more information.
 */
void drop_privileges() {
    extern char *__progname;

    if (settings.socketpath != NULL) {
       if (pledge("stdio unix", NULL) == -1) {
          fprintf(stderr, "%s: pledge: %s\n", __progname, strerror(errno));
          exit(EXIT_FAILURE);
       }
    } else {
       if (pledge("stdio inet", NULL) == -1) {
          fprintf(stderr, "%s: pledge: %s\n", __progname, strerror(errno));
          exit(EXIT_FAILURE);
       }
     }
}

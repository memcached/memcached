#include <stdlib.h>
#include <priv.h>
#include <stdio.h>
#include "memcached.h"

/*
 * this section of code will drop all (Solaris) privileges including
 * those normally granted to all userland process (basic privileges). The
 * effect of this is that after running this code, the process will not able
 * to fork(), exec(), etc.  See privileges(5) for more information.
 */
void drop_privileges(void) {
   priv_set_t *privs = priv_str_to_set("basic", ",", NULL);

   if (privs == NULL) {
      perror("priv_str_to_set");
      exit(EXIT_FAILURE);
   }

   (void)priv_delset(privs, PRIV_FILE_LINK_ANY);
   (void)priv_delset(privs, PRIV_PROC_EXEC);
   (void)priv_delset(privs, PRIV_PROC_FORK);
   (void)priv_delset(privs, PRIV_PROC_INFO);
   (void)priv_delset(privs, PRIV_PROC_SESSION);

   if (setppriv(PRIV_SET, PRIV_PERMITTED, privs) != 0) {
      perror("setppriv(PRIV_SET, PRIV_PERMITTED)");
      exit(EXIT_FAILURE);
   }

   priv_emptyset(privs);

   if (setppriv(PRIV_SET, PRIV_INHERITABLE, privs) != 0) {
      perror("setppriv(PRIV_SET, PRIV_INHERITABLE)");
      exit(EXIT_FAILURE);
   }

   if (setppriv(PRIV_SET, PRIV_LIMIT, privs) != 0) {
      perror("setppriv(PRIV_SET, PRIV_LIMIT)");
      exit(EXIT_FAILURE);
   }

   priv_freeset(privs);
}

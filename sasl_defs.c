/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "memcached.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sasl/saslplug.h>

char my_sasl_hostname[1025];

#if defined(HAVE_SASL_CB_GETCONF) || defined(HAVE_SASL_CB_GETCONFPATH)
/* The locations we may search for a SASL config file if the user didn't
 * specify one in the environment variable SASL_CONF_PATH
 */
const char * const locations[] = {
    "/etc/sasl/memcached.conf",
    "/etc/sasl2/memcached.conf",
    NULL
};
#endif

#ifndef HAVE_SASL_CALLBACK_FT
typedef int (*sasl_callback_ft)(void);
#endif

#ifdef ENABLE_SASL_PWDB
#define MAX_ENTRY_LEN 256

static const char *memcached_sasl_pwdb;

static int sasl_server_userdb_checkpass(sasl_conn_t *conn,
                                        void *context,
                                        const char *user,
                                        const char *pass,
                                        unsigned passlen,
                                        struct propctx *propctx)
{
    size_t unmlen = strlen(user);
    if ((passlen + unmlen) > (MAX_ENTRY_LEN - 4)) {
        fprintf(stderr,
                "WARNING: Failed to authenticate <%s> due to too long password (%d)\n",
                user, passlen);
        return SASL_NOAUTHZ;
    }

    FILE *pwfile = fopen(memcached_sasl_pwdb, "r");
    if (pwfile == NULL) {
        if (settings.verbose) {
            vperror("WARNING: Failed to open sasl database <%s>",
                    memcached_sasl_pwdb);
        }
        return SASL_NOAUTHZ;
    }

    char buffer[MAX_ENTRY_LEN];
    bool ok = false;

    while ((fgets(buffer, sizeof(buffer), pwfile)) != NULL) {
        if (memcmp(user, buffer, unmlen) == 0 && buffer[unmlen] == ':') {
            /* This is the correct user */
            ++unmlen;
            if (memcmp(pass, buffer + unmlen, passlen) == 0 &&
                (buffer[unmlen + passlen] == ':' || /* Additional tokens */
                 buffer[unmlen + passlen] == '\n' || /* end of line */
                 buffer[unmlen + passlen] == '\r'|| /* dos format? */
                 buffer[unmlen + passlen] == '\0')) { /* line truncated */
                ok = true;
            }

            break;
        }
    }
    (void)fclose(pwfile);
    if (ok) {
        return SASL_OK;
    }

    if (settings.verbose) {
        fprintf(stderr, "INFO: User <%s> failed to authenticate\n", user);
    }

    return SASL_NOAUTHZ;
}
#endif

#if defined(HAVE_SASL_CB_GETCONF) || defined(HAVE_SASL_CB_GETCONFPATH)
static int sasl_getconf(void *context, const char **path)
{
    *path = getenv("SASL_CONF_PATH");

    if (*path == NULL) {
        for (int i = 0; locations[i] != NULL; ++i) {
            if (access(locations[i], F_OK) == 0) {
                *path = locations[i];
                break;
            }
        }
    }

    if (settings.verbose) {
        if (*path != NULL) {
            fprintf(stderr, "Reading configuration from: <%s>\n", *path);
        } else {
            fprintf(stderr, "Failed to locate a config path\n");
        }

    }

    return (*path != NULL) ? SASL_OK : SASL_FAIL;
}
#endif

static int sasl_log(void *context, int level, const char *message)
{
    bool log = true;

    switch (level) {
    case SASL_LOG_NONE:
        log = false;
        break;
    case SASL_LOG_PASS:
    case SASL_LOG_TRACE:
    case SASL_LOG_DEBUG:
    case SASL_LOG_NOTE:
        if (settings.verbose < 2) {
            log = false;
        }
        break;
    case SASL_LOG_WARN:
    case SASL_LOG_FAIL:
        if (settings.verbose < 1) {
            log = false;
        }
        break;
    default:
        /* This is an error */
        ;
    }

    if (log) {
        fprintf(stderr, "SASL (severity %d): %s\n", level, message);
    }

    return SASL_OK;
}

static sasl_callback_t sasl_callbacks[] = {
#ifdef ENABLE_SASL_PWDB
   { SASL_CB_SERVER_USERDB_CHECKPASS, (sasl_callback_ft)sasl_server_userdb_checkpass, NULL },
#endif

   { SASL_CB_LOG, (sasl_callback_ft)sasl_log, NULL },

#ifdef HAVE_SASL_CB_GETCONF
   { SASL_CB_GETCONF, sasl_getconf, NULL },
#else
#ifdef HAVE_SASL_CB_GETCONFPATH
   { SASL_CB_GETCONFPATH, (sasl_callback_ft)sasl_getconf, NULL },
#endif
#endif

   { SASL_CB_LIST_END, NULL, NULL }
};

void init_sasl(void) {
#ifdef ENABLE_SASL_PWDB
    memcached_sasl_pwdb = getenv("MEMCACHED_SASL_PWDB");
    if (memcached_sasl_pwdb == NULL) {
       if (settings.verbose) {
          fprintf(stderr,
                  "INFO: MEMCACHED_SASL_PWDB not specified. "
                  "Internal passwd database disabled\n");
       }
       sasl_callbacks[0].id = SASL_CB_LIST_END;
       sasl_callbacks[0].proc = NULL;
    }
#endif

    memset(my_sasl_hostname, 0, sizeof(my_sasl_hostname));
    if (gethostname(my_sasl_hostname, sizeof(my_sasl_hostname)-1) == -1) {
        if (settings.verbose) {
            fprintf(stderr, "Error discovering hostname for SASL\n");
        }
        my_sasl_hostname[0] = '\0';
    }

    if (sasl_server_init(sasl_callbacks, "memcached") != SASL_OK) {
        fprintf(stderr, "Error initializing sasl.\n");
        exit(EXIT_FAILURE);
    } else {
        if (settings.verbose) {
            fprintf(stderr, "Initialized SASL.\n");
        }
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>
#include <stdint.h>
#include <pthread.h>
#include <stdbool.h>

#include "hash.h"
#include "isasl.h"

static pthread_mutex_t uhash_lock = PTHREAD_MUTEX_INITIALIZER;

static user_db_entry_t **user_ht;
static const int n_uht_buckets = 12289;

static void kill_whitey(char *s) {
    for(int i = strlen(s) - 1; i > 0 && isspace(s[i]); i--) {
        s[i] = '\0';
    }
}

static int u_hash_key(const char *u)
{
    uint32_t h = hash(u, strlen(u), 0) % n_uht_buckets;
    assert(h < n_uht_buckets);
    return h;
}

static char *find_pw(const char *u)
{
    assert(u);
    assert(user_ht);

    int h = u_hash_key(u);

    user_db_entry_t *e = user_ht[h];
    while (e && strcmp(e->username, u) != 0) {
        e = e->next;
    }

    return e ? e->password : NULL;
}

static void store_pw(user_db_entry_t **ht, const char *u, const char *p)
{
    assert(ht);
    assert(u);
    assert(p);
    user_db_entry_t *e = calloc(1, sizeof(user_db_entry_t));
    assert(e);
    e->username = strdup(u);
    assert(e->username);
    e->password = strdup(p);
    assert(e->password);

    int h = u_hash_key(u);

    e->next = ht[h];
    ht[h] = e;
}

static void free_user_ht(void)
{
    if (user_ht) {
        for (int i = 0; i < n_uht_buckets; i++) {
            while (user_ht[i]) {
                user_db_entry_t *e = user_ht[i];
                user_db_entry_t *n = e->next;
                free(e->username);
                free(e->password);
                free(e);
                user_ht[i] = n;
            }
        }
        free(user_ht);
        user_ht = NULL;
    }
}

static int load_user_db(void)
{
    const char *filename = getenv("ISASL_PWFILE");
    if (!filename) {
        fprintf(stderr, "No ISASL_PWFILE defined.\n");
        return SASL_FAIL;
    }

    FILE *sfile = fopen(filename, "r");
    if (!sfile) {
        perror(filename);
        return SASL_FAIL;
    }

    user_db_entry_t **new_ut = calloc(n_uht_buckets,
                                      sizeof(user_db_entry_t*));
    if (!new_ut) {
        fclose(sfile);
        return SASL_NOMEM;
    }

    char up[128];
    while (fgets(up, sizeof(up), sfile)) {
        if (up[0] != '#') {
            char *uname = up, *p = up;
            kill_whitey(up);
            while (*p && !isspace(p[0])) {
                p++;
            }
            p[0] = '\0';
            p++;
            while (isspace(*p)) {
                p++;
            }
            if (p[0] != '\0') {
                store_pw(new_ut, uname, p);
            }
        }
    }

    fclose(sfile);

    pthread_mutex_lock(&uhash_lock);
    free_user_ht();
    user_ht = new_ut;
    pthread_mutex_unlock(&uhash_lock);

    return SASL_OK;
}

void sasl_dispose(sasl_conn_t **pconn)
{
    free(*pconn);
    *pconn = NULL;
}

int sasl_server_init(const sasl_callback_t *callbacks,
                     const char *appname)
{
    return load_user_db();
}

int sasl_server_new(const char *service,
                    const char *serverFQDN,
                    const char *user_realm,
                    const char *iplocalport,
                    const char *ipremoteport,
                    const sasl_callback_t *callbacks,
                    unsigned flags,
                    sasl_conn_t **pconn)
{
    *pconn = calloc(1, sizeof(sasl_conn_t));
    return *pconn ? SASL_OK : SASL_NOMEM;
}

int sasl_listmech(sasl_conn_t *conn,
                  const char *user,
                  const char *prefix,
                  const char *sep,
                  const char *suffix,
                  const char **result,
                  unsigned *plen,
                  int *pcount)
{
    // We use this in a very specific way in the codebase.  If that ever
    // changes, detect it quickly.
    assert(strcmp(prefix, "") == 0);
    assert(strcmp(sep, " ") == 0);
    assert(strcmp(suffix, "") == 0);

    *result = "PLAIN";
    *plen = strlen(*result);
    return SASL_OK;
}

static bool check_up(const char *username, const char *password)
{
    pthread_mutex_lock(&uhash_lock);
    char *pw = find_pw(username);
    bool rv = pw && (strcmp(password, pw) == 0);
    pthread_mutex_unlock(&uhash_lock);
    return rv;
}

int sasl_server_start(sasl_conn_t *conn,
                      const char *mech,
                      const char *clientin,
                      unsigned clientinlen,
                      const char **serverout,
                      unsigned *serveroutlen)
{
    int rv = SASL_FAIL;
    *serverout = "";
    *serveroutlen = 0;

    if(strcmp(mech, "PLAIN") == 0) {
        // 256 is an arbitrary ``large enough'' number.
        if (clientinlen > 2 && clientinlen < 128 && clientin[0] == '\0') {
            const char *username = clientin + 1;
            char password[128];
            int pwlen = clientinlen - 2 - strlen(username);
            if (pwlen > 0) {
                password[pwlen] = '\0';
                memcpy(password, clientin + 2 + strlen(username), pwlen);

                if (check_up(username, password)) {
                    if (conn->username) {
                        free(conn->username);
                        conn->username = NULL;
                    }
                    conn->username = strdup(username);
                    rv = SASL_OK;
                }
            }
        }
    }

    return rv;
}

int sasl_server_step(sasl_conn_t *conn,
                     const char *clientin,
                     unsigned clientinlen,
                     const char **serverout,
                     unsigned *serveroutlen)
{
    // This is only useful when the above returns SASL_CONTINUE.  In this
    // implementation, only PLAIN is supported, so it never will.
    return SASL_FAIL;
}

int sasl_getprop(sasl_conn_t *conn, int propnum,
                 const void **pvalue)
{
    if (propnum != SASL_USERNAME) {
        return SASL_BADPARAM;
    }
    *pvalue = conn->username;
    return SASL_OK;
}

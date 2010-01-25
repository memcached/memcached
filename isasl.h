#ifndef ISASL_H
#define ISASL_H 1

#define SASL_CB_LIST_END   0  /* end of list */

#define SASL_USERNAME     0 /* pointer to NUL terminated user name */
#define ISASL_CONFIG      20 /* Just so we don't have to implement all the auxprop stuff */

typedef struct sasl_callback {
    unsigned long id;
    int (*proc)(void);
    void *context;
} sasl_callback_t;

typedef struct sasl_conn {
    char *username;
    char *config;
} sasl_conn_t;

typedef struct user_db_entry {
    char *username;
    char *password;
    char *config;
    struct user_db_entry *next;
} user_db_entry_t;

void sasl_dispose(sasl_conn_t **pconn);

int sasl_server_init(const sasl_callback_t *callbacks,
                     const char *appname);

int sasl_server_new(const char *service,
                    const char *serverFQDN,
                    const char *user_realm,
                    const char *iplocalport,
                    const char *ipremoteport,
                    const sasl_callback_t *callbacks,
                    unsigned flags,
                    sasl_conn_t **pconn);

int sasl_listmech(sasl_conn_t *conn,
                  const char *user,
                  const char *prefix,
                  const char *sep,
                  const char *suffix,
                  const char **result,
                  unsigned *plen,
                  int *pcount);

int sasl_server_start(sasl_conn_t *conn,
                      const char *mech,
                      const char *clientin,
                      unsigned clientinlen,
                      const char **serverout,
                      unsigned *serveroutlen);

int sasl_server_step(sasl_conn_t *conn,
                     const char *clientin,
                     unsigned clientinlen,
                     const char **serverout,
                     unsigned *serveroutlen);

int sasl_getprop(sasl_conn_t *conn, int propnum,
                 const void **pvalue);

#define SASL_OK       0
#define SASL_CONTINUE 1
#define SASL_FAIL     -1        /* generic failure */
#define SASL_NOMEM    -2        /* memory shortage failure */
#define SASL_BADPARAM -7        /* invalid parameter supplied */
#define SASL_NOUSER   -20       /* user not found */

#endif /* ISASL_H */

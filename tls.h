#ifndef TLS_H
#define TLS_H

#ifdef TLS
void *ssl_accept(conn *c, int sfd, bool *fail);
int ssl_init(void);
void ssl_init_settings(void);
void ssl_init_conn(conn *c, void *ssl);
void ssl_conn_close(void *ssl_in);
bool refresh_certs(char **errmsg);
void ssl_help(void);
bool ssl_set_verify_mode(int verify);
bool ssl_set_min_version(int version);
const char *ssl_proto_text(int version);
#else
#define ssl_init(void)
#define ssl_init_conn(c, ssl)
#define ssl_init_settings(void)
#define ssl_conn_close(ssl)
#define ssl_accept(c, sfd, fail) NULL
#define ssl_help()
#endif

#endif

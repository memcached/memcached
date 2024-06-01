#ifndef TLS_H
#define TLS_H

#define MC_SSL_DISABLED 0
#define MC_SSL_ENABLED_DEFAULT 1
#define MC_SSL_ENABLED_NOPEER 2
#define MC_SSL_ENABLED_PEER 3

#ifdef TLS
void *ssl_accept(conn *c, int sfd, bool *fail);
const unsigned char *ssl_get_peer_cn(conn *c, int *len);
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

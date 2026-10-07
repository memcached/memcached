#ifndef TLS_H
#define TLS_H

#define MC_SSL_DISABLED         0   // notls -> only valid when memcached is run with SSL enabled as not ssl connection
#define MC_SSL_ENABLED_DEFAULT  1   // default setting without SSL_set_verify()
#define MC_SSL_ENABLED_NOPEER   2   // btls -> setup SSL_VERIFY_NONE => don't enforce peer certs
#define MC_SSL_ENABLED_PEER     3   // mtls -> setup SSL_VERIFY_PEER + SSL_VERIFY_FAIL_IF_NO_PEER_CERT => force peer validation
#define MC_SSL_VERIFY_PEER      4   // mtls2 -> setup SSL_VERIFY_PEER + SSL_VERIFY_FAIL_IF_NO_PEER_CERT with verification

#ifdef TLS
extern int ssl_data_index;

bool ssl_check_CA_cert(struct tls_settings *tls_settings);
void *ssl_accept(conn *c, int sfd, bool *fail);
const unsigned char *ssl_get_peer_cn(conn *c, int *len);
int ssl_init(bool ssl_enabled, struct tls_settings *tls_settings);
int ssl_verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx);
struct tls_settings ssl_init_settings(void);
void ssl_init_conn(conn *c, void *ssl);
void ssl_conn_close(void *ssl_in);
int ssl_pending(void *ssl_in);
bool refresh_certs(struct tls_settings *tls_settings, char **errmsg);
void ssl_help(void);
bool ssl_set_verify_mode(int verify);
bool ssl_set_min_version(int version);
const char *ssl_proto_text(int version);
bool ssl_is_client(struct tls_settings *tls_settings);
bool ssl_is_server(struct tls_settings *tls_settings);
#else
#define ssl_init(ssl_enabled, tls_settings)
#define ssl_init_conn(c, ssl)
#define ssl_init_settings(void)
#define ssl_conn_close(ssl)
#define ssl_pending(ssl) 0
#define ssl_accept(c, sfd, fail) NULL
#define ssl_help()
#endif

#endif

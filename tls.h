#ifndef TLS_H
#define TLS_H

/* constant session ID context for application-level SSL session scoping.
 * used in server-side SSL session caching, when enabled. */
#define SESSION_ID_CONTEXT "memcached"

void SSL_LOCK(void);
void SSL_UNLOCK(void);
ssize_t ssl_read(conn *c, void *buf, size_t count);
ssize_t ssl_sendmsg(conn *c, struct msghdr *msg, int flags);
ssize_t ssl_write(conn *c, void *buf, size_t count);

int ssl_init(void);
bool refresh_certs(char **errmsg);
void ssl_callback(const SSL *s, int where, int ret);
int ssl_new_session_callback(SSL *s, SSL_SESSION *sess);
const char *ssl_proto_text(int version);

#endif

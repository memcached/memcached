#ifndef TLS_H
#define TLS_H

void SSL_LOCK(void);
void SSL_UNLOCK(void);
ssize_t ssl_read(conn *c, void *buf, size_t count);
ssize_t ssl_sendmsg(conn *c, struct msghdr *msg, int flags);
ssize_t ssl_write(conn *c, void *buf, size_t count);

int ssl_init(void);
void refresh_certs(void* c);
void ssl_callback(const SSL *s, int where, int ret);

#endif

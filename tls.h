#ifndef TLS_H
#define TLS_H

pthread_mutex_t ssl_ctx_lock;

ssize_t ssl_read(void *arg, void *buf, size_t count);
ssize_t ssl_sendmsg(void *arg, struct msghdr *msg, int flags);
ssize_t ssl_write(void *arg, void *buf, size_t count);

unsigned long get_thread_id_cb(void);
void thread_lock_cb(int mode, int which, const char * f, int l);
int ssl_init(void);
void refresh_certificates(void);

#endif

#ifndef PROTO_PROXY_H
#define PROTO_PROXY_H

void proxy_stats(ADD_STAT add_stats, conn *c);
void process_proxy_stats(ADD_STAT add_stats, conn *c);

/* proxy mode handlers */
int try_read_command_proxy(conn *c);
void complete_nread_proxy(conn *c);
void proxy_cleanup_conn(conn *c);
void proxy_thread_init(LIBEVENT_THREAD *thr);
void proxy_init(bool proxy_uring);
// TODO: need better names or a better interface for these. can be confusing
// to reason about the order.
void proxy_start_reload(void *arg);
int proxy_load_config(void *arg);
void proxy_worker_reload(void *arg, LIBEVENT_THREAD *thr);

void proxy_submit_cb(io_queue_t *q);
void proxy_complete_cb(io_queue_t *q);
void proxy_return_cb(io_pending_t *pending);
void proxy_finalize_cb(io_pending_t *pending);

/* lua */
int proxy_register_libs(LIBEVENT_THREAD *t, void *ctx);

#endif

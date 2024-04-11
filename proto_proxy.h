#ifndef PROTO_PROXY_H
#define PROTO_PROXY_H

void proxy_stats(void *arg, ADD_STAT add_stats, void *c);
void process_proxy_stats(void *arg, ADD_STAT add_stats, void *c);
void process_proxy_funcstats(void *arg, ADD_STAT add_stats, void *c);
void process_proxy_bestats(void *arg, ADD_STAT add_stats, void *c);

/* proxy mode handlers */
int try_read_command_proxy(conn *c);
void complete_nread_proxy(conn *c);
void proxy_cleanup_conn(conn *c);
void proxy_thread_init(void *ctx, LIBEVENT_THREAD *thr);
void *proxy_init(bool proxy_uring, bool proxy_memprofile);
// TODO: need better names or a better interface for these. can be confusing
// to reason about the order.
void proxy_start_reload(void *arg);
int proxy_first_confload(void *arg);
int proxy_load_config(void *arg);
void proxy_worker_reload(void *arg, LIBEVENT_THREAD *thr);
void proxy_gc_poke(LIBEVENT_THREAD *t);

void proxy_submit_cb(io_queue_t *q);
void proxy_complete_cb(io_queue_t *q);

/* lua */
int proxy_register_libs(void *ctx, LIBEVENT_THREAD *t, void *state);

#endif

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// Functions related to the backend handler thread.

#include "proxy.h"

enum proxy_be_failures {
    P_BE_FAIL_TIMEOUT = 0,
    P_BE_FAIL_DISCONNECTED,
    P_BE_FAIL_CONNECTING,
    P_BE_FAIL_READVALIDATE,
    P_BE_FAIL_BADVALIDATE,
    P_BE_FAIL_WRITING,
    P_BE_FAIL_READING,
    P_BE_FAIL_PARSING,
    P_BE_FAIL_CLOSED,
    P_BE_FAIL_UNHANDLEDRES,
    P_BE_FAIL_OOM,
    P_BE_FAIL_ENDSYNC,
    P_BE_FAIL_TRAILINGDATA,
};

const char *proxy_be_failure_text[] = {
    [P_BE_FAIL_TIMEOUT] = "timeout",
    [P_BE_FAIL_DISCONNECTED] = "disconnected",
    [P_BE_FAIL_CONNECTING] = "connecting",
    [P_BE_FAIL_READVALIDATE] = "readvalidate",
    [P_BE_FAIL_BADVALIDATE] = "badvalidate",
    [P_BE_FAIL_WRITING] = "writing",
    [P_BE_FAIL_READING] = "reading",
    [P_BE_FAIL_PARSING] = "parsing",
    [P_BE_FAIL_CLOSED] = "closedsock",
    [P_BE_FAIL_UNHANDLEDRES] = "unhandledres",
    [P_BE_FAIL_OOM] = "outofmemory",
    [P_BE_FAIL_ENDSYNC] = "missingend",
    [P_BE_FAIL_TRAILINGDATA] = "trailingdata",
    NULL
};

static void proxy_backend_handler(const int fd, const short which, void *arg);
static void proxy_beconn_handler(const int fd, const short which, void *arg);
static void proxy_event_handler(evutil_socket_t fd, short which, void *arg);
static void proxy_event_beconn(evutil_socket_t fd, short which, void *arg);
static int _prep_pending_write(mcp_backend_t *be);
static void _post_pending_write(mcp_backend_t *be, ssize_t sent);
static int _flush_pending_write(mcp_backend_t *be);
static void _cleanup_backend(mcp_backend_t *be);
static int _reset_bad_backend(mcp_backend_t *be, enum proxy_be_failures err);
static void _backend_failed(mcp_backend_t *be);
static void _set_main_event(mcp_backend_t *be, struct event_base *base, int flags, struct timeval *t, event_callback_fn callback);
static void _stop_main_event(mcp_backend_t *be);
static void _start_write_event(mcp_backend_t *be);
static void _stop_write_event(mcp_backend_t *be);
static void _start_timeout_event(mcp_backend_t *be);
static void _stop_timeout_event(mcp_backend_t *be);
static int proxy_backend_drive_machine(mcp_backend_t *be);

/* Helper routines common to io_uring and libevent modes */

// TODO (v3): doing an inline syscall here, not ideal for uring mode.
// leaving for now since this should be extremely uncommon.
static int _beconn_send_validate(mcp_backend_t *be) {
    const char *str = "version\r\n";
    const ssize_t len = strlen(str);

    ssize_t res = write(mcmc_fd(be->client), str, len);

    if (res == -1) {
        return -1;
    }

    // I'm making an opinionated statement that we should be able to write
    // "version\r\n" into a fresh socket without hitting EAGAIN.
    if (res < len) {
        return -1;
    }

    return 1;
}

// FIXME: make _backend_failed conditionally use _ur() so we can have one call
// in the code and reuse more code like this.
static int _proxy_beconn_checkconnect(mcp_backend_t *be) {
    int err = 0;
    // We were connecting, now ensure we're properly connected.
    if (mcmc_check_nonblock_connect(be->client, &err) != MCMC_OK) {
        P_DEBUG("%s: backend failed to connect (%s:%s)\n", __func__, be->name, be->port);
        // kick the bad backend, clear the queue, retry later.
        // FIXME (v2): if a connect fails, anything currently in the queue
        // should be safe to hold up until their timeout.
        _reset_bad_backend(be, P_BE_FAIL_CONNECTING);
        _backend_failed(be);
        return -1;
    }
    P_DEBUG("%s: backend connected (%s:%s)\n", __func__, be->name, be->port);
    be->connecting = false;
    be->state = mcp_backend_read;
    be->bad = false;
    be->failed_count = 0;

    be->validating = true;
    // TODO: make validation optional.

    if (_beconn_send_validate(be) == -1) {
        _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
        _backend_failed(be);
        return -1;
    } else {
        // buffer should be empty during validation stage.
        assert(be->rbufused == 0);
        return 0;
    }
}

static int _proxy_event_handler_dequeue(proxy_event_thread_t *t) {
    io_head_t head;

    STAILQ_INIT(&head);
    STAILQ_INIT(&t->be_head);

    // Pull the entire stack of inbound into local queue.
    pthread_mutex_lock(&t->mutex);
    STAILQ_CONCAT(&head, &t->io_head_in);
    pthread_mutex_unlock(&t->mutex);

    int io_count = 0;
    int be_count = 0;
    while (!STAILQ_EMPTY(&head)) {
        io_pending_proxy_t *io = STAILQ_FIRST(&head);
        io->flushed = false;

        // _no_ mutex on backends. they are owned by the event thread.
        STAILQ_REMOVE_HEAD(&head, io_next);
        // paranoia about moving items between lists.
        io->io_next.stqe_next = NULL;

        mcp_backend_t *be = io->backend;
        // So the backend can retrieve its event base.
        if (be->bad) {
            P_DEBUG("%s: fast failing request to bad backend\n", __func__);
            io->client_resp->status = MCMC_ERR;
            return_io_pending((io_pending_t *)io);
            continue;
        }
        STAILQ_INSERT_TAIL(&be->io_head, io, io_next);
        be->depth++;
        io_count++;
        if (!be->stacked) {
            be->stacked = true;
            // more paranoia about be_next not being overwritten
            be->be_next.stqe_next = NULL;
            STAILQ_INSERT_TAIL(&t->be_head, be, be_next);
            be_count++;
        }
    }
    //P_DEBUG("%s: io/be counts for syscalls [%d/%d]\n", __func__, io_count, be_count);
    return io_count;
}

#ifdef HAVE_LIBURING
//static void _proxy_evthr_evset_wnotify(proxy_event_thread_t *t, int notify_fd);
static void _proxy_evthr_evset_be_read(mcp_backend_t *be, char *buf, size_t len, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_writev(mcp_backend_t *be, int iovcnt, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_wrpoll(mcp_backend_t *be, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_retry(mcp_backend_t *be);
static void _proxy_evthr_evset_be_conn(mcp_backend_t *be, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_readvalidate(mcp_backend_t *be, char *buf, size_t len, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_notifier(proxy_event_thread_t *t);
static void _proxy_evthr_evset_benotifier(proxy_event_thread_t *t);
static void _backend_failed_ur(mcp_backend_t *be);

static void _flush_pending_write_ur(mcp_backend_t *be) {
    // Allow us to be called with an empty stack to prevent dev errors.
    if (STAILQ_EMPTY(&be->io_head)) {
        return;
    }

    int iovcnt = _prep_pending_write(be);

    // TODO: write timeout.
    _proxy_evthr_evset_be_writev(be, iovcnt, &be->tunables.read_ur);
}

// TODO: we shouldn't handle reads if a write is pending, so postwrite should
// check for pending read data before going into read mode.
// need be->writing flag to toggle?
static void proxy_backend_postwrite_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    P_DEBUG("%s: %d\n", __func__, cqe->res);
    assert(cqe->res != -EINVAL);
    int sent = cqe->res;
    if (sent < 0) {
        // FIXME: sent == 0 is disconnected? I keep forgetting.
        if (sent == -EAGAIN || sent == -EWOULDBLOCK) {
            // didn't do any writing, wait for a writeable socket.
            _proxy_evthr_evset_be_wrpoll(be, &be->tunables.read_ur);
        } else {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
            _backend_failed_ur(be);
        }
    }

    if (_post_pending_write(be, sent)) {
        // commands were flushed, set read handler.
        _proxy_evthr_evset_be_read(be, be->rbuf+be->rbufused, READ_BUFFER_SIZE-be->rbufused, &be->tunables.read_ur);
    }

    if (be->io_next) {
        // still have unflushed commands, re-run write command.
        // writev can't "block if EAGAIN" in io_uring so far as I can tell, so
        // we have to switch to polling mode here.
        _proxy_evthr_evset_be_wrpoll(be, &be->tunables.read_ur);
    }

    // TODO: if rbufused != 0, push through drive machine?
}

// No-op at the moment. when the linked timeout fires uring returns the
// linked request (read/write/poll/etc) with an interrupted/timeout/cancelled
// error. So we don't need to explicitly handle timeouts.
// I'm leaving the structure in to simplify the callback routine.
// Since timeouts rarely get called the extra code here shouldn't matter.
static void proxy_backend_timeout_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    return;
}

static void proxy_backend_retry_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    _proxy_evthr_evset_be_conn(be, &be->tunables.connect_ur);
}

static void _proxy_evthr_evset_be_retry(mcp_backend_t *be) {
    struct io_uring_sqe *sqe;
    if (be->ur_te_ev.set)
        return;

    be->ur_te_ev.cb = proxy_backend_retry_handler_ur;
    be->ur_te_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // TODO (v2): NULL?

    io_uring_prep_timeout(sqe, &be->tunables.retry_ur, 0, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
    be->ur_te_ev.set = true;
}

static void _backend_failed_ur(mcp_backend_t *be) {
    if (++be->failed_count > be->tunables.backend_failure_limit) {
        P_DEBUG("%s: marking backend as bad\n", __func__);
        be->bad = true;
        _proxy_evthr_evset_be_retry(be);
        STAT_INCR(be->event_thread->ctx, backend_marked_bad, 1);
    } else {
        _proxy_evthr_evset_be_conn(be, &be->tunables.connect_ur);
        STAT_INCR(be->event_thread->ctx, backend_failed, 1);
    }
}

// read handler.
static void proxy_backend_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    int bread = cqe->res;
    // Error or disconnection.
    if (bread <= 0) {
        _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
        _backend_failed_ur(be);
        return;
    }

    be->rbufused += bread;
    int res = proxy_backend_drive_machine(be);

    if (res != 0) {
        _reset_bad_backend(be, res);
        _backend_failed_ur(be);
        return;
    }

    // TODO (v2): when exactly do we need to reset the backend handler?
    if (!STAILQ_EMPTY(&be->io_head)) {
        _proxy_evthr_evset_be_read(be, be->rbuf+be->rbufused, READ_BUFFER_SIZE-be->rbufused, &be->tunables.read_ur);
    }
}

static void proxy_backend_wrhandler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;

    be->can_write = true;
    _flush_pending_write_ur(be);

    _proxy_evthr_evset_be_read(be, be->rbuf+be->rbufused, READ_BUFFER_SIZE-be->rbufused, &be->tunables.read_ur);
}

// a backend with an outstanding new connection has become writeable.
// check validity.
// TODO: this gets an error if cancelled right?
static void proxy_backend_beconn_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    int err = 0;
    assert(be->connecting);
/*    if (_proxy_beconn_checkconnect(be) == -1) {
        return;
    } */

    // We were connecting, now ensure we're properly connected.
    if (mcmc_check_nonblock_connect(be->client, &err) != MCMC_OK) {
        P_DEBUG("%s: backend failed to connect (%s:%s)\n", __func__, be->name, be->port);
        // kick the bad backend, clear the queue, retry later.
        // FIXME (v2): if a connect fails, anything currently in the queue
        // should be safe to hold up until their timeout.
        _reset_bad_backend(be, P_BE_FAIL_CONNECTING);
        _backend_failed_ur(be);
        return;
    }
    P_DEBUG("%s: backend connected (%s:%s)\n", __func__, be->name, be->port);
    be->connecting = false;
    be->state = mcp_backend_read;
    be->bad = false;
    be->failed_count = 0;

    be->validating = true;
    // TODO: make validation optional.

    if (_beconn_send_validate(be) == -1) {
        _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
        _backend_failed_ur(be);
        return;
    } else {
        // buffer should be empty during validation stage.
        assert(be->rbufused == 0);
    }

    // TODO: make validation optional.
    // set next handler on recv for validity check.
    _proxy_evthr_evset_be_readvalidate(be, be->rbuf, READ_BUFFER_SIZE, &be->tunables.read_ur);
}

// TODO: share more code with proxy_beconn_handler
static void proxy_backend_beconn_validate_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    mcmc_resp_t r;
    assert(be->validating);
    assert(cqe->res != -EINVAL);
    P_DEBUG("%s: checking validation: %d\n", __func__, cqe->res);

    int bread = cqe->res;
    // Error or disconnection.
    if (bread <= 0) {
        _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
        _backend_failed_ur(be);
        return;
    }

    be->rbufused += bread;

    int status = mcmc_parse_buf(be->client, be->rbuf, be->rbufused, &r);
    if (status == MCMC_ERR) {
        // Needed more data for a version line, somehow. For the uring code
        // we'll treat that as an error, for now.
        // TODO: re-schedule self if r.code == MCMC_WANT_READ.

        _reset_bad_backend(be, P_BE_FAIL_READVALIDATE);
        _backend_failed_ur(be);
        return;
    }

    if (r.code != MCMC_CODE_VERSION) {
        _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
        _backend_failed_ur(be);
        return;
    }

    be->validating = false;
    be->rbufused = 0;

    // Passed validation, don't need to re-read, flush any pending writes.
    _flush_pending_write(be);
}

// TODO (v3): much code shared with proxy_event_beconn, should be able to
// abstract out.
// TODO (v3): further optimization would move the mcmc_connect() socket
// creation to uring.
static void proxy_beconn_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    proxy_event_thread_t *t = udata;
    P_DEBUG("%s: got wakeup: %d\n", __func__, cqe->res);

    // liburing always uses eventfd for the notifier.
    // *cqe has our result.
    assert(cqe->res != -EINVAL);
    if (cqe->res != sizeof(eventfd_t)) {
        P_DEBUG("%s: cqe->res: %d\n", __func__, cqe->res);
        // FIXME (v2): figure out if this is impossible, and how to handle if not.
        assert(1 == 0);
    }

    // need to re-arm the listener every time.
    _proxy_evthr_evset_benotifier(t);

    beconn_head_t head;

    STAILQ_INIT(&head);
    pthread_mutex_lock(&t->mutex);
    STAILQ_CONCAT(&head, &t->beconn_head_in);
    pthread_mutex_unlock(&t->mutex);

    mcp_backend_t *be = NULL;
    // be can be freed by the loop, so can't use STAILQ_FOREACH.
    while (!STAILQ_EMPTY(&head)) {
        be = STAILQ_FIRST(&head);
        STAILQ_REMOVE_HEAD(&head, beconn_next);
        if (be->transferred) {
            // If this object was already transferred here, we're being
            // signalled to clean it up and free.
            _cleanup_backend(be);
        } else {
            be->transferred = true;
            int status = mcmc_connect(be->client, be->name, be->port, be->connect_flags);
            if (status == MCMC_CONNECTING || status == MCMC_CONNECTED) {
                // if we're already connected for some reason, still push it
                // through the connection handler to keep the code unified. It
                // will auto-wake because the socket is writeable.
                be->connecting = true;
                be->can_write = false;
                _proxy_evthr_evset_be_conn(be, &be->tunables.connect_ur);
            } else {
                _reset_bad_backend(be, P_BE_FAIL_CONNECTING);
                _backend_failed_ur(be);
            }
        }
    }

}

static void proxy_event_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    proxy_event_thread_t *t = udata;

    // liburing always uses eventfd for the notifier.
    // *cqe has our result.
    assert(cqe->res != -EINVAL);
    if (cqe->res != sizeof(eventfd_t)) {
        P_DEBUG("%s: cqe->res: %d\n", __func__, cqe->res);
        // FIXME (v2): figure out if this is impossible, and how to handle if not.
        assert(1 == 0);
    }

    // need to re-arm the listener every time.
    _proxy_evthr_evset_notifier(t);

    // TODO (v2): sqe queues for writing to backends
    //  - _ur handler for backend write completion is to set a read event and
    //  re-submit. ugh.
    // Should be possible to have standing reads, but flow is harder and lets
    // optimize that later. (ie; allow matching reads to a request but don't
    // actually dequeue anything until both read and write are confirmed)
    if (_proxy_event_handler_dequeue(t) == 0) {
        //P_DEBUG("%s: no IO's to complete\n", __func__);
        return;
    }

    // Re-walk each backend and check set event as required.
    mcp_backend_t *be = NULL;

    // TODO (v2): for each backend, queue writev's into sqe's
    // move the backend sqe bits into a write complete handler
    STAILQ_FOREACH(be, &t->be_head, be_next) {
        be->stacked = false;

        if (be->connecting || be->validating) {
            P_DEBUG("%s: deferring IO pending connecting\n", __func__);
        } else {
            _flush_pending_write_ur(be);
        }
    }
}

static void _proxy_evthr_evset_be_readvalidate(mcp_backend_t *be, char *buf, size_t len, struct __kernel_timespec *ts) {
    P_DEBUG("%s: setting: %lu\n", __func__, len);
    struct io_uring_sqe *sqe;
    if (be->ur_rd_ev.set) {
        P_DEBUG("%s: already set\n", __func__);
        return;
    }

    be->ur_rd_ev.cb = proxy_backend_beconn_validate_ur;
    be->ur_rd_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // FIXME (v2): NULL?
    assert(be->rbuf != NULL);
    io_uring_prep_recv(sqe, mcmc_fd(be->client), buf, len, 0);
    io_uring_sqe_set_data(sqe, &be->ur_rd_ev);
    be->ur_rd_ev.set = true;

    sqe->flags |= IOSQE_IO_LINK;

    // add a timeout.
    be->ur_te_ev.cb = proxy_backend_timeout_handler_ur;
    be->ur_te_ev.udata = be;
    sqe = io_uring_get_sqe(&be->event_thread->ring);

    io_uring_prep_link_timeout(sqe, ts, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
}

// reuse the write handler event for pending connections.
static void _proxy_evthr_evset_be_conn(mcp_backend_t *be, struct __kernel_timespec *ts) {
    struct io_uring_sqe *sqe;
    P_DEBUG("%s: setting\n", __func__);
    if (be->ur_wr_ev.set)
        return;

    be->ur_wr_ev.cb = proxy_backend_beconn_ur;
    be->ur_wr_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // FIXME (v2): NULL?

    io_uring_prep_poll_add(sqe, mcmc_fd(be->client), POLLOUT);
    io_uring_sqe_set_data(sqe, &be->ur_wr_ev);
    be->ur_wr_ev.set = true;

    sqe->flags |= IOSQE_IO_LINK;

    // add a timeout.
    // FIXME: do I need to change this at all?
    be->ur_te_ev.cb = proxy_backend_timeout_handler_ur;
    be->ur_te_ev.udata = be;
    sqe = io_uring_get_sqe(&be->event_thread->ring);

    io_uring_prep_link_timeout(sqe, ts, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
}

// reusing the ur_wr_ev.
static void _proxy_evthr_evset_be_writev(mcp_backend_t *be, int iovcnt, struct __kernel_timespec *ts) {
    struct io_uring_sqe *sqe;
    if (be->ur_wr_ev.set)
        return;

    be->ur_wr_ev.cb = proxy_backend_postwrite_ur;
    be->ur_wr_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // FIXME (v2): NULL?

    if (iovcnt == 1) {
        io_uring_prep_write(sqe, mcmc_fd(be->client), be->write_iovs[0].iov_base, be->write_iovs[0].iov_len, 0);
    } else {
        io_uring_prep_writev(sqe, mcmc_fd(be->client), be->write_iovs, iovcnt, 0);
    }
    io_uring_sqe_set_data(sqe, &be->ur_wr_ev);
    be->ur_wr_ev.set = true;

    sqe->flags |= IOSQE_IO_LINK;

    // add a timeout.
    be->ur_te_ev.cb = proxy_backend_timeout_handler_ur;
    be->ur_te_ev.udata = be;
    sqe = io_uring_get_sqe(&be->event_thread->ring);

    io_uring_prep_link_timeout(sqe, ts, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
}

static void _proxy_evthr_evset_be_wrpoll(mcp_backend_t *be, struct __kernel_timespec *ts) {
    struct io_uring_sqe *sqe;
    if (be->ur_wr_ev.set)
        return;

    be->ur_wr_ev.cb = proxy_backend_wrhandler_ur;
    be->ur_wr_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // FIXME (v2): NULL?

    io_uring_prep_poll_add(sqe, mcmc_fd(be->client), POLLOUT);
    io_uring_sqe_set_data(sqe, &be->ur_wr_ev);
    be->ur_wr_ev.set = true;

    sqe->flags |= IOSQE_IO_LINK;

    // add a timeout.
    be->ur_te_ev.cb = proxy_backend_timeout_handler_ur;
    be->ur_te_ev.udata = be;
    sqe = io_uring_get_sqe(&be->event_thread->ring);

    io_uring_prep_link_timeout(sqe, ts, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
}

static void _proxy_evthr_evset_be_read(mcp_backend_t *be, char *buf, size_t len, struct __kernel_timespec *ts) {
    P_DEBUG("%s: setting: %lu\n", __func__, len);
    struct io_uring_sqe *sqe;
    if (be->ur_rd_ev.set) {
        P_DEBUG("%s: already set\n", __func__);
        return;
    }

    be->ur_rd_ev.cb = proxy_backend_handler_ur;
    be->ur_rd_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // FIXME (v2): NULL?
    assert(be->rbuf != NULL);
    io_uring_prep_recv(sqe, mcmc_fd(be->client), buf, len, 0);
    io_uring_sqe_set_data(sqe, &be->ur_rd_ev);
    be->ur_rd_ev.set = true;

    sqe->flags |= IOSQE_IO_LINK;

    // add a timeout.
    // TODO (v2): we can pre-set the event data and avoid always re-doing it here.
    be->ur_te_ev.cb = proxy_backend_timeout_handler_ur;
    be->ur_te_ev.udata = be;
    sqe = io_uring_get_sqe(&be->event_thread->ring);

    io_uring_prep_link_timeout(sqe, ts, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);

}

// FIXME: can this be inside the function?
//static eventfd_t dummy_event = 1;
// TODO: in newer versions of uring we can set ignore success?
/*static void _proxy_evthr_evset_wnotify(proxy_event_thread_t *t, int notify_fd) {
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&t->ring);
    // FIXME (v2) NULL?

    io_uring_prep_write(sqe, notify_fd, &dummy_event, sizeof(dummy_event), 0);
    io_uring_sqe_set_data(sqe, NULL);
}*/

static void _proxy_evthr_evset_benotifier(proxy_event_thread_t *t) {
    struct io_uring_sqe *sqe;
    P_DEBUG("%s: setting: %d\n", __func__, t->ur_benotify_event.set);
    if (t->ur_benotify_event.set)
        return;

    t->ur_benotify_event.cb = proxy_beconn_handler_ur;
    t->ur_benotify_event.udata = t;

    sqe = io_uring_get_sqe(&t->ring);
    // FIXME (v2): NULL?
    io_uring_prep_read(sqe, t->be_event_fd, &t->beevent_counter, sizeof(eventfd_t), 0);
    io_uring_sqe_set_data(sqe, &t->ur_benotify_event);
}

static void _proxy_evthr_evset_notifier(proxy_event_thread_t *t) {
    struct io_uring_sqe *sqe;
    P_DEBUG("%s: setting: %d\n", __func__, t->ur_notify_event.set);
    if (t->ur_notify_event.set)
        return;

    t->ur_notify_event.cb = proxy_event_handler_ur;
    t->ur_notify_event.udata = t;

    sqe = io_uring_get_sqe(&t->ring);
    // FIXME (v2): NULL?
    io_uring_prep_read(sqe, t->event_fd, &t->event_counter, sizeof(eventfd_t), 0);
    io_uring_sqe_set_data(sqe, &t->ur_notify_event);
}

// TODO (v2): IOURING_FEAT_NODROP: uring_submit() should return -EBUSY if out of CQ
// events slots. Therefore might starve SQE's if we were low beforehand.
// - when uring events are armed, they should link into an STAILQ
// - after all cqe's are processed from the loop, walk the queued events
// - generate SQE's as necessary, bailing if we run out before running out of
// events.
// - submit the SQE's
// - if it bails on -EBUSY due to too many CQE's, run the CQE loop again
// - submit if there were pending SQE's before resuming walking the event
// chain.
//
// Think this is the best compromise; doesn't use temporary memory for
// processing CQE's, and we already have dedicated memory for the SQE side of
// things so adding a little more for an STAILQ is fine.
// Until then this code will deadlock and die if -EBUSY happens.
void *proxy_event_thread_ur(void *arg) {
    proxy_event_thread_t *t = arg;
    struct io_uring_cqe *cqe;

    P_DEBUG("%s: starting\n", __func__);

    logger_create(); // TODO (v2): add logger to struct
    while (1) {
        P_DEBUG("%s: submit and wait\n", __func__);
        io_uring_submit_and_wait(&t->ring, 1);
        //P_DEBUG("%s: sqe submitted: %d\n", __func__, ret);

        uint32_t head = 0;
        uint32_t count = 0;

        io_uring_for_each_cqe(&t->ring, head, cqe) {
            P_DEBUG("%s: got a CQE [count:%d]\n", __func__, count);

            proxy_event_t *pe = io_uring_cqe_get_data(cqe);
            if (pe != NULL) {
                pe->set = false;
                pe->cb(pe->udata, cqe);
            }

            count++;
        }

        P_DEBUG("%s: advancing [count:%d]\n", __func__, count);
        io_uring_cq_advance(&t->ring, count);
    }

    return NULL;
}
#endif // HAVE_LIBURING

static void _cleanup_backend(mcp_backend_t *be) {
#ifdef HAVE_LIBURING
    if (be->event_thread->use_uring) {
        // TODO: cancel any live uring events.
    } else {
#endif
    // remove any pending events.
    int pending = event_pending(&be->main_event, EV_READ|EV_WRITE|EV_TIMEOUT, NULL);
    if ((pending & (EV_READ|EV_WRITE|EV_TIMEOUT)) != 0) {
        event_del(&be->main_event); // an error to call event_del() without event.
    }
    pending = event_pending(&be->write_event, EV_READ|EV_WRITE|EV_TIMEOUT, NULL);
    if ((pending & (EV_READ|EV_WRITE|EV_TIMEOUT)) != 0) {
        event_del(&be->write_event); // an error to call event_del() without event.
    }
    pending = event_pending(&be->timeout_event, EV_TIMEOUT, NULL);
    if ((pending & (EV_TIMEOUT)) != 0) {
        event_del(&be->timeout_event); // an error to call event_del() without event.
    }
#ifdef HAVE_LIBURING
    }
#endif

    // - assert on empty queue
    assert(STAILQ_EMPTY(&be->io_head));

    mcmc_disconnect(be->client);
    // - free be->client
    free(be->client);
    // - free be->rbuf
    free(be->rbuf);
    // - free *be
    free(be);
}

// event handler for injecting backends for processing
// currently just for initiating connections the first time.
static void proxy_event_beconn(evutil_socket_t fd, short which, void *arg) {
    proxy_event_thread_t *t = arg;

#ifdef USE_EVENTFD
    uint64_t u;
    if (read(fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
        // Temporary error or wasn't actually ready to read somehow.
        return;
    }
#else
    char buf[1];
    if (read(fd, buf, 1) != 1) {
        P_DEBUG("%s: pipe read failed\n", __func__);
        return;
    }
#endif

    beconn_head_t head;

    STAILQ_INIT(&head);
    pthread_mutex_lock(&t->mutex);
    STAILQ_CONCAT(&head, &t->beconn_head_in);
    pthread_mutex_unlock(&t->mutex);

    // Think we should reuse this code path for manually instructing backends
    // to disable/etc but not coding for that generically. We just need to
    // check the state of the backend when it reaches here or some flags at
    // least.
    // FIXME: another ->stacked flag?
    // Either that or remove the STAILQ code and just using an array of
    // ptr's.
    mcp_backend_t *be = NULL;
    // be can be freed by the loop, so can't use STAILQ_FOREACH.
    while (!STAILQ_EMPTY(&head)) {
        be = STAILQ_FIRST(&head);
        STAILQ_REMOVE_HEAD(&head, beconn_next);
        if (be->transferred) {
            // If this object was already transferred here, we're being
            // signalled to clean it up and free.
            _cleanup_backend(be);
        } else {
            be->transferred = true;
            // assign the initial events to the backend, so we don't have to
            // constantly check if they were initialized yet elsewhere.
            // note these events will not fire until event_add() is called.
            int status = mcmc_connect(be->client, be->name, be->port, be->connect_flags);
            event_assign(&be->main_event, be->event_thread->base, mcmc_fd(be->client), EV_WRITE|EV_TIMEOUT, proxy_beconn_handler, be);
            event_assign(&be->write_event, be->event_thread->base, mcmc_fd(be->client), EV_WRITE|EV_TIMEOUT, proxy_backend_handler, be);
            event_assign(&be->timeout_event, be->event_thread->base, -1, EV_TIMEOUT, proxy_backend_handler, be);

            if (status == MCMC_CONNECTING || status == MCMC_CONNECTED) {
                // if we're already connected for some reason, still push it
                // through the connection handler to keep the code unified. It
                // will auto-wake because the socket is writeable.
                be->connecting = true;
                be->can_write = false;
                // kick off the event we intialized above.
                event_add(&be->main_event, &be->tunables.connect);
            } else {
                _reset_bad_backend(be, P_BE_FAIL_CONNECTING);
                _backend_failed(be);
            }
        }
    }
}

void proxy_run_backend_queue(be_head_t *head) {
    mcp_backend_t *be;
    STAILQ_FOREACH(be, head, be_next) {
        be->stacked = false;
        int flags = 0;

        if (be->bad) {
            // flush queue if backend is still bad.
            // TODO: duplicated from _reset_bad_backend()
            io_pending_proxy_t *io = NULL;
            while (!STAILQ_EMPTY(&be->io_head)) {
                io = STAILQ_FIRST(&be->io_head);
                STAILQ_REMOVE_HEAD(&be->io_head, io_next);
                io->client_resp->status = MCMC_ERR;
                be->depth--;
                return_io_pending((io_pending_t *)io);
            }
        } else if (be->connecting || be->validating) {
            P_DEBUG("%s: deferring IO pending connecting (%s:%s)\n", __func__, be->name, be->port);
        } else {
            flags = _flush_pending_write(be);

            if (flags == -1) {
                _reset_bad_backend(be, P_BE_FAIL_WRITING);
                _backend_failed(be);
            } else if (flags & EV_WRITE) {
                // only get here because we need to kick off the write handler
                _start_write_event(be);
            }

            if (be->pending_read) {
                _start_timeout_event(be);
            }

        }
    }
}

// event handler for executing backend requests
static void proxy_event_handler(evutil_socket_t fd, short which, void *arg) {
    proxy_event_thread_t *t = arg;

#ifdef USE_EVENTFD
    uint64_t u;
    if (read(fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
        // Temporary error or wasn't actually ready to read somehow.
        return;
    }
#else
    char buf[1];
    // TODO (v2): This is a lot more fatal than it should be. can it fail? can
    // it blow up the server?
    // TODO (v2): a cross-platform method of speeding this up would be nice. With
    // event fds we can queue N events and wakeup once here.
    // If we're pulling one byte out of the pipe at a time here it'll just
    // wake us up too often.
    // If the pipe is O_NONBLOCK then maybe just a larger read would work?
    if (read(fd, buf, 1) != 1) {
        P_DEBUG("%s: pipe read failed\n", __func__);
        return;
    }
#endif

    if (_proxy_event_handler_dequeue(t) == 0) {
        //P_DEBUG("%s: no IO's to complete\n", __func__);
        return;
    }

    // Re-walk each backend and check set event as required.
    proxy_run_backend_queue(&t->be_head);
}

void *proxy_event_thread(void *arg) {
    proxy_event_thread_t *t = arg;

    logger_create(); // TODO (v2): add logger ptr to structure
    event_base_loop(t->base, 0);
    event_base_free(t->base);

    // TODO (v2): join bt threads, free array.

    return NULL;
}

static void _set_main_event(mcp_backend_t *be, struct event_base *base, int flags, struct timeval *t, event_callback_fn callback) {
    int pending = event_pending(&be->main_event, EV_READ|EV_WRITE, NULL);
    if ((pending & (EV_READ|EV_WRITE)) != 0) {
        event_del(&be->main_event); // replace existing event.
    }

    event_assign(&be->main_event, base, mcmc_fd(be->client),
            flags, callback, be);
    event_add(&be->main_event, t);
}

static void _stop_main_event(mcp_backend_t *be) {
    int pending = event_pending(&be->main_event, EV_READ|EV_WRITE, NULL);
    if ((pending & (EV_READ|EV_WRITE|EV_TIMEOUT)) == 0) {
        return;
    }
    event_del(&be->write_event);
}

static void _start_write_event(mcp_backend_t *be) {
    int pending = event_pending(&be->main_event, EV_WRITE, NULL);
    if ((pending & (EV_WRITE|EV_TIMEOUT)) != 0) {
        return;
    }
    // FIXME: wasn't there a write timeout?
    event_add(&be->write_event, &be->tunables.read);
}

static void _stop_write_event(mcp_backend_t *be) {
    int pending = event_pending(&be->main_event, EV_WRITE, NULL);
    if ((pending & (EV_WRITE|EV_TIMEOUT)) == 0) {
        return;
    }
    event_del(&be->write_event);
}

// handle the read timeouts with a side event, so we can stick with a
// persistent listener (optimization + catch disconnects faster)
static void _start_timeout_event(mcp_backend_t *be) {
    int pending = event_pending(&be->timeout_event, EV_TIMEOUT, NULL);
    if ((pending & (EV_TIMEOUT)) != 0) {
        return;
    }
    event_add(&be->timeout_event, &be->tunables.read);
}

static void _stop_timeout_event(mcp_backend_t *be) {
    int pending = event_pending(&be->timeout_event, EV_TIMEOUT, NULL);
    if ((pending & (EV_TIMEOUT)) == 0) {
        return;
    }
    event_del(&be->timeout_event);
}

// NOTES:
// - mcp_backend_read: grab req_stack_head, do things
// read -> next, want_read -> next | read_end, etc.
// issue: want read back to read_end as necessary. special state?
//   - it's fine: p->client_resp->type.
// - mcp_backend_next: advance, consume, etc.
// TODO (v2): second argument with enum for a specific error.
// - probably just for logging. for app if any of these errors shouldn't
// result in killing the request stack!
static int proxy_backend_drive_machine(mcp_backend_t *be) {
    bool stop = false;
    io_pending_proxy_t *p = NULL;
    struct timeval end;
    int flags = 0;

    p = STAILQ_FIRST(&be->io_head);
    if (p == NULL) {
        // got a read event, but nothing was queued.
        // probably means a disconnect event.
        // TODO (v2): could probably confirm this by attempting to read the
        // socket, getsockopt, or something else simply for logging or
        // statistical purposes.
        // In this case we know it's going to be a close so error.
        flags = P_BE_FAIL_CLOSED;
        P_DEBUG("%s: read event but nothing in IO queue\n", __func__);
        return flags;
    }

    while (!stop) {
        mcp_resp_t *r;

    switch(be->state) {
        case mcp_backend_read:
            assert(p != NULL);
            // FIXME: remove the _read state?
            be->state = mcp_backend_parse;
            break;
        case mcp_backend_parse:
            r = p->client_resp;
            r->status = mcmc_parse_buf(be->client, be->rbuf, be->rbufused, &r->resp);

            if (r->status == MCMC_ERR) {
                P_DEBUG("%s: mcmc_read failed [%d]\n", __func__, r->status);
                if (r->resp.code == MCMC_WANT_READ) {
                    return 0;
                }
                flags = P_BE_FAIL_PARSING;
                stop = true;
                break;
            }

            // we actually don't care about anything but the value length
            // TODO (v2): if vlen != vlen_read, pull an item and copy the data.
            int extra_space = 0;
            switch (r->resp.type) {
                case MCMC_RESP_GET:
                    // We're in GET mode. we only support one key per
                    // GET in the proxy backends, so we need to later check
                    // for an END.
                    extra_space = ENDLEN;
                    break;
                case MCMC_RESP_END:
                    // this is a MISS from a GET request
                    // or final handler from a STAT request.
                    assert(r->resp.vlen == 0);
                    break;
                case MCMC_RESP_META:
                    // we can handle meta responses easily since they're self
                    // contained.
                    break;
                case MCMC_RESP_GENERIC:
                case MCMC_RESP_NUMERIC:
                    break;
                // TODO (v2): No-op response?
                default:
                    P_DEBUG("%s: Unhandled response from backend: %d\n", __func__, r->resp.type);
                    // unhandled :(
                    flags = P_BE_FAIL_UNHANDLEDRES;
                    stop = true;
                    break;
            }

            if (p->ascii_multiget && r->resp.type == MCMC_RESP_END) {
                // Ascii multiget hack mode; consume END's
                be->rbufused -= r->resp.reslen;
                if (be->rbufused > 0) {
                    memmove(be->rbuf, be->rbuf+r->resp.reslen, be->rbufused);
                }

                be->state = mcp_backend_next;
                break;
            }

            // r->resp.reslen + r->resp.vlen is the total length of the response.
            // TODO (v2): need to associate a buffer with this response...
            // for now lets abuse write_and_free on mc_resp and simply malloc the
            // space we need, stuffing it into the resp object.

            r->blen = r->resp.reslen + r->resp.vlen;
            r->buf = malloc(r->blen + extra_space);
            if (r->buf == NULL) {
                flags = P_BE_FAIL_OOM;
                stop = true;
                break;
            }

            P_DEBUG("%s: r->status: %d, r->bread: %d, r->vlen: %lu\n", __func__, r->status, r->bread, r->resp.vlen);
            if (r->resp.vlen != r->resp.vlen_read) {
                // shouldn't be possible to have excess in buffer
                // if we're dealing with a partial value.
                assert(be->rbufused == r->resp.reslen+r->resp.vlen_read);
                P_DEBUG("%s: got a short read, moving to want_read\n", __func__);
                // copy the partial and advance mcmc's buffer digestion.
                memcpy(r->buf, be->rbuf, r->resp.reslen + r->resp.vlen_read);
                r->bread = r->resp.reslen + r->resp.vlen_read;
                be->rbufused = 0;
                be->state = mcp_backend_want_read;
                flags = 0;
                stop = true;
                break;
            } else {
                // mcmc's already counted the value as read if it fit in
                // the original buffer...
                memcpy(r->buf, be->rbuf, r->resp.reslen+r->resp.vlen_read);
            }

            // had a response, advance the buffer.
            be->rbufused -= r->resp.reslen + r->resp.vlen_read;
            if (be->rbufused > 0) {
                memmove(be->rbuf, be->rbuf+r->resp.reslen+r->resp.vlen_read, be->rbufused);
            }

            if (r->resp.type == MCMC_RESP_GET) {
                be->state = mcp_backend_read_end;
            } else {
                be->state = mcp_backend_next;
            }

            break;
        case mcp_backend_read_end:
            r = p->client_resp;
            // we need to ensure the next data in the stream is "END\r\n"
            // if not, the stack is desynced and we lose it.

            if (be->rbufused >= ENDLEN) {
                if (memcmp(be->rbuf, ENDSTR, ENDLEN) != 0) {
                    flags = P_BE_FAIL_ENDSYNC;
                    stop = true;
                    break;
                } else {
                    // response is good.
                    // FIXME (v2): copy what the server actually sent?
                    if (!p->ascii_multiget) {
                        // sigh... if part of a multiget we need to eat the END
                        // markers down here.
                        memcpy(r->buf+r->blen, ENDSTR, ENDLEN);
                        r->blen += 5;
                    }

                    // advance buffer
                    be->rbufused -= ENDLEN;
                    if (be->rbufused > 0) {
                        memmove(be->rbuf, be->rbuf+ENDLEN, be->rbufused);
                    }
                }
            } else {
                flags = 0;
                stop = true;
                break;
            }

            be->state = mcp_backend_next;

            break;
        case mcp_backend_want_read:
            // Continuing a read from earlier
            r = p->client_resp;
            // take bread input and see if we're done reading the value,
            // else advance, set buffers, return next.
            P_DEBUG("%s: [want_read] r->bread: %d vlen: %lu\n", __func__, r->bread, r->resp.vlen);
            assert(be->rbufused != 0);
            size_t tocopy = be->rbufused < r->blen - r->bread ?
                be->rbufused : r->blen - r->bread;
            memcpy(r->buf+r->bread, be->rbuf, tocopy);
            r->bread += tocopy;

            if (r->bread >= r->blen) {
                // all done copying data.
                if (r->resp.type == MCMC_RESP_GET) {
                    be->state = mcp_backend_read_end;
                } else {
                    be->state = mcp_backend_next;
                }

                // shuffle remaining buffer.
                be->rbufused -= tocopy;
                if (be->rbufused > 0) {
                    memmove(be->rbuf, be->rbuf+tocopy, be->rbufused);
                }
            } else {
                assert(tocopy == be->rbufused);
                // signal to caller to issue a read.
                be->rbufused = 0;
                flags = 0;
                stop = true;
            }

            break;
        case mcp_backend_next:
            // set the head here. when we break the head will be correct.
            STAILQ_REMOVE_HEAD(&be->io_head, io_next);
            be->depth--;
            be->pending_read--;

            // stamp the elapsed time into the response object.
            gettimeofday(&end, NULL);
            p->client_resp->elapsed = (end.tv_sec - p->client_resp->start.tv_sec) * 1000000 +
                (end.tv_usec - p->client_resp->start.tv_usec);

            // have to do the q->count-- and == 0 and redispatch_conn()
            // stuff here. The moment we call return_io here we
            // don't own *p anymore.
            return_io_pending((io_pending_t *)p);
            be->state = mcp_backend_read;

            if (STAILQ_EMPTY(&be->io_head)) {
                stop = true;
                // TODO: if there're no pending requests, the read buffer
                // should also be empty.
                // Get a specific return code for errors to surface this.
                if (be->rbufused > 0) {
                    flags = P_BE_FAIL_TRAILINGDATA;
                }
                break;
            } else {
                p = STAILQ_FIRST(&be->io_head);
            }

            // if leftover, keep processing IO's.
            // if no more data in buffer, need to re-set stack head and re-set
            // event.
            P_DEBUG("%s: [next] remain: %lu\n", __func__, be->rbufused);
            if (be->rbufused != 0) {
                // data trailing in the buffer, for a different request.
                be->state = mcp_backend_parse;
            } else {
                // need to read more data, buffer is empty.
                stop = true;
            }

            break;
        default:
            // TODO (v2): at some point (after v1?) this should attempt to recover,
            // though we should only get here from memory corruption and
            // bailing may be the right thing to do.
            fprintf(stderr, "%s: invalid backend state: %d\n", __func__, be->state);
            assert(false);
    } // switch
    } // while

    return flags;
}

static void _backend_reconnect(mcp_backend_t *be) {
    int status = mcmc_connect(be->client, be->name, be->port, be->connect_flags);
    if (status == MCMC_CONNECTED) {
        // TODO (v2): unexpected but lets let it be here.
        be->connecting = false;
        be->can_write = true;
    } else if (status == MCMC_CONNECTING) {
        be->connecting = true;
        be->can_write = false;
    } else {
        // TODO (v2): failed to immediately re-establish the connection.
        // need to put the BE into a bad/retry state.
        // FIXME (v2): until we get an event to specifically handle connecting and
        // bad server handling, attempt to force a reconnect here the next
        // time a request comes through.
        // The event thread will attempt to write to the backend, fail, then
        // end up in this routine again.
        be->connecting = false;
        be->can_write = true;
    }
    // re-create the write handler for the new file descriptor.
    // the main event will be re-assigned after this call.
    event_assign(&be->write_event, be->event_thread->base, mcmc_fd(be->client), EV_WRITE|EV_TIMEOUT, proxy_backend_handler, be);
    // do not need to re-assign the timer event because it's not tied to fd
}

// All we need to do here is schedule the backend to attempt to connect again.
static void proxy_backend_retry_handler(const int fd, const short which, void *arg) {
    mcp_backend_t *be = arg;
    assert(which & EV_TIMEOUT);
    struct timeval tmp_time = be->tunables.retry;
    _backend_reconnect(be);
    _set_main_event(be, be->event_thread->base, EV_WRITE, &tmp_time, proxy_beconn_handler);
}

// must be called after _reset_bad_backend(), so the backend is currently
// clear.
// TODO (v2): extra counter for "backend connect tries" so it's still possible
// to see dead backends exist
static void _backend_failed(mcp_backend_t *be) {
    struct timeval tmp_time = be->tunables.retry;
    if (++be->failed_count > be->tunables.backend_failure_limit) {
        if (!be->bad) {
            P_DEBUG("%s: marking backend as bad\n", __func__);
            STAT_INCR(be->event_thread->ctx, backend_marked_bad, 1);
            LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_BE_ERROR, NULL, "markedbad", be->name, be->port, 0, NULL, 0);
        }
        be->bad = true;
       _set_main_event(be, be->event_thread->base, EV_TIMEOUT, &tmp_time, proxy_backend_retry_handler);
    } else {
        STAT_INCR(be->event_thread->ctx, backend_failed, 1);
        _backend_reconnect(be);
        _set_main_event(be, be->event_thread->base, EV_WRITE, &tmp_time, proxy_beconn_handler);
    }
}

// TODO (v2): add a second argument for assigning a specific error to all pending
// IO's (ie; timeout).
// The backend has gotten into a bad state (timed out, protocol desync, or
// some other supposedly unrecoverable error: purge the queue and
// cycle the socket.
// Note that some types of errors may not require flushing the queue and
// should be fixed as they're figured out.
// _must_ be called from within the event thread.
static int _reset_bad_backend(mcp_backend_t *be, enum proxy_be_failures err) {
    io_pending_proxy_t *io = NULL;
    // Can't use STAILQ_FOREACH() since return_io_pending() free's the current
    // io. STAILQ_FOREACH_SAFE maybe?
    int depth = be->depth;
    while (!STAILQ_EMPTY(&be->io_head)) {
        io = STAILQ_FIRST(&be->io_head);
        STAILQ_REMOVE_HEAD(&be->io_head, io_next);
        // TODO (v2): Unsure if this is the best way of surfacing errors to lua,
        // but will do for V1.
        io->client_resp->status = MCMC_ERR;
        be->depth--;
        return_io_pending((io_pending_t *)io);
    }

    STAILQ_INIT(&be->io_head);
    be->io_next = NULL; // also reset the write offset.

    // Only log if we don't already know it's messed up.
    if (!be->bad) {
        LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_BE_ERROR, NULL, proxy_be_failure_text[err], be->name, be->port, depth, be->rbuf, be->rbufused);
    }

    // reset buffer to blank state.
    be->rbufused = 0;
    be->pending_read = 0;
    // allow the _backend_failed() routine to connect when ready.
    _stop_write_event(be);
    _stop_main_event(be);
    _stop_timeout_event(be);
    mcmc_disconnect(be->client);
    // we leave the main event alone, because be_failed() always overwrites.

    return 0;
}

static int _prep_pending_write(mcp_backend_t *be) {
    struct iovec *iovs = be->write_iovs;
    io_pending_proxy_t *io = NULL;
    int iovused = 0;
    if (be->io_next == NULL) {
        // separate pointer for how far into the list we've flushed.
        io = STAILQ_FIRST(&be->io_head);
    } else {
        io = be->io_next;
    }
    assert(io != NULL);
    for (; io; io = STAILQ_NEXT(io, io_next)) {
        // TODO (v2): paranoia for now, but this check should never fire
        if (io->flushed)
            continue;

        if (io->iovcnt + iovused > BE_IOV_MAX) {
            // We will need to keep writing later.
            break;
        }

        memcpy(&iovs[iovused], io->iov, sizeof(struct iovec)*io->iovcnt);
        iovused += io->iovcnt;
    }
    return iovused;
}

// returns true if any pending writes were fully flushed.
static void _post_pending_write(mcp_backend_t *be, ssize_t sent) {
    io_pending_proxy_t *io = be->io_next;
    if (io == NULL) {
        io = STAILQ_FIRST(&be->io_head);
    }

    for (; io; io = STAILQ_NEXT(io, io_next)) {
        bool flushed = true;
        if (io->flushed)
            continue;
        if (sent >= io->iovbytes) {
            // short circuit for common case.
            sent -= io->iovbytes;
        } else {
            io->iovbytes -= sent;
            for (int x = 0; x < io->iovcnt; x++) {
                struct iovec *iov = &io->iov[x];
                if (sent >= iov->iov_len) {
                    sent -= iov->iov_len;
                    iov->iov_len = 0;
                } else {
                    iov->iov_len -= sent;
                    iov->iov_base = (char *)iov->iov_base + sent;
                    sent = 0;
                    flushed = false;
                    break;
                }
            }
        }
        io->flushed = flushed;
        if (flushed) {
            be->pending_read++;
        }

        if (sent <= 0) {
            // really shouldn't be negative, though.
            assert(sent >= 0);
            break;
        }
    } // for

    // resume the flush from this point.
    if (io != NULL && !io->flushed) {
        be->io_next = io;
    } else {
        be->io_next = NULL;
    }
}

static int _flush_pending_write(mcp_backend_t *be) {
    int flags = 0;
    // Allow us to be called with an empty stack to prevent dev errors.
    if (STAILQ_EMPTY(&be->io_head)) {
        return 0;
    }

    int iovcnt = _prep_pending_write(be);

    ssize_t sent = writev(mcmc_fd(be->client), be->write_iovs, iovcnt);
    if (sent > 0) {
        _post_pending_write(be, sent);
        // still have unflushed pending IO's, check for write and re-loop.
        if (be->io_next) {
            be->can_write = false;
            flags |= EV_WRITE;
        }
    } else if (sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            be->can_write = false;
            flags |= EV_WRITE;
        } else {
            flags = -1;
        }
    }

    return flags;
}

// Libevent handler for backends in a connecting state.
static void proxy_beconn_handler(const int fd, const short which, void *arg) {
    assert(arg != NULL);
    mcp_backend_t *be = arg;
    int flags = EV_TIMEOUT;
    struct timeval tmp_time = be->tunables.read;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: backend timed out while connecting\n", __func__);
        _reset_bad_backend(be, P_BE_FAIL_TIMEOUT);
        _backend_failed(be);
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;

        if (be->connecting) {
            if (_proxy_beconn_checkconnect(be) == -1) {
                return;
            }
            _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_beconn_handler);
        }

        // TODO: currently never taken, until validation is made optional.
        if (!be->validating) {
            int res = _flush_pending_write(be);
            if (res == -1) {
                _reset_bad_backend(be, P_BE_FAIL_WRITING);
                _backend_failed(be);
                return;
            }
            flags |= res;
            // FIXME: set write event?
        }
    }

    if (which & EV_READ) {
        assert(be->validating);

        int read = recv(mcmc_fd(be->client), be->rbuf + be->rbufused, READ_BUFFER_SIZE - be->rbufused, 0);
        if (read > 0) {
            mcmc_resp_t r;
            be->rbufused += read;

            int status = mcmc_parse_buf(be->client, be->rbuf, be->rbufused, &r);
            if (status == MCMC_ERR) {
                // Needed more data for a version line, somehow. I feel like
                // this should set off some alarms, but it is possible.
                if (r.code == MCMC_WANT_READ) {
                    _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_beconn_handler);
                    return;
                }

                _reset_bad_backend(be, P_BE_FAIL_READVALIDATE);
                _backend_failed(be);
                return;
            }

            if (r.code != MCMC_CODE_VERSION) {
                _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
                _backend_failed(be);
                return;
            }

            be->validating = false;
            be->rbufused = 0;
        } else if (read == 0) {
            // not connected or error.
            _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
            _backend_failed(be);
            return;
        } else if (read == -1) {
            // sit on epoll again.
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                _reset_bad_backend(be, P_BE_FAIL_READING);
                _backend_failed(be);
                return;
            }
            _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_beconn_handler);
            return;
        }

        // Passed validation, don't need to re-read, flush any pending writes.
        int res = _flush_pending_write(be);
        if (res == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
            _backend_failed(be);
            return;
        }
        if (flags & EV_WRITE) {
            _start_write_event(be);
        }
        if (be->pending_read) {
            _start_timeout_event(be);
        }
    }

    // switch to the primary persistent read event.
    if (!be->validating) {
        _set_main_event(be, be->event_thread->base, EV_READ|EV_PERSIST, NULL, proxy_backend_handler);
    }
}

// The libevent backend callback handler.
// If we end up resetting a backend, it will get put back into a connecting
// state.
static void proxy_backend_handler(const int fd, const short which, void *arg) {
    mcp_backend_t *be = arg;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: timeout received, killing backend queue\n", __func__);
        _reset_bad_backend(be, P_BE_FAIL_TIMEOUT);
        _backend_failed(be);
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;
        int res = _flush_pending_write(be);
        if (res == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
            _backend_failed(be);
            return;
        }
        if (res & EV_WRITE) {
            _start_write_event(be);
        }
    }

    if (which & EV_READ) {
        // got a read event, always kill the pending read timer.
        _stop_timeout_event(be);
        // We do the syscall here before diving into the state machine to allow a
        // common code path for io_uring/epoll
        int read = recv(mcmc_fd(be->client), be->rbuf + be->rbufused,
                    READ_BUFFER_SIZE - be->rbufused, 0);
        if (read > 0) {
            be->rbufused += read;
            int res = proxy_backend_drive_machine(be);
            if (res != 0) {
                _reset_bad_backend(be, res);
                _backend_failed(be);
                return;
            }
        } else if (read == 0) {
            // not connected or error.
            _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
            _backend_failed(be);
            return;
        } else if (read == -1) {
            // sit on epoll again.
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                _reset_bad_backend(be, P_BE_FAIL_READING);
                _backend_failed(be);
                return;
            }
        }

#ifdef PROXY_DEBUG
        if (!STAILQ_EMPTY(&be->io_head)) {
            P_DEBUG("backend has leftover IOs: %d\n", be->depth);
        }
#endif
    }

    if (be->pending_read) {
        _start_timeout_event(be);
    }
}

// TODO (v2): IORING_SETUP_ATTACH_WQ port from bench_event once we have multiple
// event threads.
// TODO: this either needs a restructure or split into two funcs:
// 1) for the IO thread which creates its own ring/event base
// 2) for the worker thread which reuses the event base.
// io_uring will probably only work for the IO thread which makes further
// exceptions.
void proxy_init_event_thread(proxy_event_thread_t *t, proxy_ctx_t *ctx, struct event_base *base) {
    t->ctx = ctx;
#ifdef USE_EVENTFD
    t->event_fd = eventfd(0, EFD_NONBLOCK);
    if (t->event_fd == -1) {
        perror("failed to create backend notify eventfd");
        exit(1);
    }
    t->be_event_fd = eventfd(0, EFD_NONBLOCK);
    if (t->be_event_fd == -1) {
        perror("failed to create backend notify eventfd");
        exit(1);
    }
#else
    int fds[2];
    if (pipe(fds)) {
        perror("can't create proxy backend notify pipe");
        exit(1);
    }

    t->notify_receive_fd = fds[0];
    t->notify_send_fd = fds[1];

    if (pipe(fds)) {
        perror("can't create proxy backend connection notify pipe");
        exit(1);
    }
    t->be_notify_receive_fd = fds[0];
    t->be_notify_send_fd = fds[1];
#endif

    // incoming request queue.
    STAILQ_INIT(&t->io_head_in);
    STAILQ_INIT(&t->beconn_head_in);
    pthread_mutex_init(&t->mutex, NULL);
    pthread_cond_init(&t->cond, NULL);

    // initialize the event system.

#ifdef HAVE_LIBURING
    fprintf(stderr, "Sorry, io_uring not supported right now\n");
    abort();
    bool use_uring = t->ctx->use_uring;
    struct io_uring_params p = {0};
    assert(t->event_fd); // uring only exists where eventfd also does.

    // Setup the CQSIZE to be much larger than SQ size, since backpressure
    // issues can cause us to block on SQ submissions and as a network server,
    // stuff happens.

    if (use_uring) {
        p.flags = IORING_SETUP_CQSIZE;
        p.cq_entries = PRING_QUEUE_CQ_ENTRIES;
        int ret = io_uring_queue_init_params(PRING_QUEUE_SQ_ENTRIES, &t->ring, &p);
        if (ret) {
            perror("io_uring_queue_init_params");
            exit(1);
        }
        if (!(p.features & IORING_FEAT_NODROP)) {
            fprintf(stderr, "uring: kernel missing IORING_FEAT_NODROP, using libevent\n");
            use_uring = false;
        }
        if (!(p.features & IORING_FEAT_SINGLE_MMAP)) {
            fprintf(stderr, "uring: kernel missing IORING_FEAT_SINGLE_MMAP, using libevent\n");
            use_uring = false;
        }
        if (!(p.features & IORING_FEAT_FAST_POLL)) {
            fprintf(stderr, "uring: kernel missing IORING_FEAT_FAST_POLL, using libevent\n");
            use_uring = false;
        }

        if (use_uring) {
            // FIXME (v2): Sigh. we need a blocking event_fd for io_uring but we've a
            // chicken and egg in here. need a better structure... in meantime
            // re-create the event_fd.

            // set the new request handler.
            close(t->event_fd);
            t->event_fd = eventfd(0, 0);
            // FIXME (v2): hack for event init.
            t->ur_notify_event.set = false;
            _proxy_evthr_evset_notifier(t);

            // set the new backend connection handler.
            close(t->be_event_fd);
            t->be_event_fd = eventfd(0, 0);
            t->ur_benotify_event.set = false;
            _proxy_evthr_evset_benotifier(t);

            t->use_uring = true;
            return;
        } else {
            // Decided to not use io_uring, so don't waste memory.
            t->use_uring = false;
            io_uring_queue_exit(&t->ring);
        }
    } else {
        t->use_uring = false;
    }
#endif

    if (base == NULL) {
        struct event_config *ev_config;
        ev_config = event_config_new();
        event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
        t->base = event_base_new_with_config(ev_config);
        event_config_free(ev_config);
        if (! t->base) {
            fprintf(stderr, "Can't allocate event base\n");
            exit(1);
        }
    } else {
        // reusing an event base from a worker thread.
        t->base = base;
    }

    // listen for notifications.
    // NULL was thread_libevent_process
    // FIXME (v2): use modern format? (event_assign)
#ifdef USE_EVENTFD
    event_set(&t->notify_event, t->event_fd,
          EV_READ | EV_PERSIST, proxy_event_handler, t);
    event_set(&t->beconn_event, t->be_event_fd,
          EV_READ | EV_PERSIST, proxy_event_beconn, t);
#else
    event_set(&t->notify_event, t->notify_receive_fd,
          EV_READ | EV_PERSIST, proxy_event_handler, t);
    event_set(&t->beconn_event, t->be_notify_receive_fd,
          EV_READ | EV_PERSIST, proxy_event_beconn, t);
#endif

    event_base_set(t->base, &t->notify_event);
    if (event_add(&t->notify_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }
    event_base_set(t->base, &t->beconn_event);
    if (event_add(&t->beconn_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }
}



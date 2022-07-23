/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// Functions related to the backend handler thread.

#include "proxy.h"

static void proxy_backend_handler(const int fd, const short which, void *arg);
static void proxy_event_handler(evutil_socket_t fd, short which, void *arg);
static void proxy_event_updater(evutil_socket_t fd, short which, void *arg);
static int _flush_pending_write(mcp_backend_t *be);
static int _reset_bad_backend(mcp_backend_t *be, enum proxy_be_failures err);
static void _set_event(mcp_backend_t *be, struct event_base *base, int flags, struct timeval t, event_callback_fn callback);
static int proxy_backend_drive_machine(mcp_backend_t *be);

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
        mcp_backend_t *be = io->backend;
        // So the backend can retrieve its event base.
        be->event_thread = t;

        // _no_ mutex on backends. they are owned by the event thread.
        STAILQ_REMOVE_HEAD(&head, io_next);
        // paranoia about moving items between lists.
        io->io_next.stqe_next = NULL;

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
static void _proxy_evthr_evset_be_read(mcp_backend_t *be, char *buf, size_t len, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_wrpoll(mcp_backend_t *be, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_retry(mcp_backend_t *be);
static void _proxy_evthr_evset_notifier(proxy_event_thread_t *t);
static void _proxy_evthr_evset_clock(proxy_event_thread_t *t);
static void proxy_event_updater_ur(void *udata, struct io_uring_cqe *cqe);
struct __kernel_timespec updater_ts = {.tv_sec = 3, .tv_nsec = 0};

static void proxy_event_updater_ur(void *udata, struct io_uring_cqe *cqe) {
    proxy_event_thread_t *t = udata;
    proxy_ctx_t *ctx = t->ctx;

    _proxy_evthr_evset_clock(t);

    // we reuse the "global stats" lock since it's hardly ever used.
    STAT_L(ctx);
    memcpy(&t->tunables, &ctx->tunables, sizeof(t->tunables));
    STAT_UL(ctx);
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
    _proxy_evthr_evset_be_wrpoll(be, &be->event_thread->tunables.connect_ur);
}

static void _proxy_evthr_evset_be_retry(mcp_backend_t *be) {
    struct io_uring_sqe *sqe;
    if (be->ur_te_ev.set)
        return;

    be->ur_te_ev.cb = proxy_backend_retry_handler_ur;
    be->ur_te_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // TODO (v2): NULL?

    io_uring_prep_timeout(sqe, &be->event_thread->tunables.retry_ur, 0, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
    be->ur_te_ev.set = true;
}

static void _backend_failed_ur(mcp_backend_t *be) {
    if (++be->failed_count > be->event_thread->tunables.backend_failure_limit) {
        P_DEBUG("%s: marking backend as bad\n", __func__);
        be->bad = true;
        _proxy_evthr_evset_be_retry(be);
    } else {
        _proxy_evthr_evset_be_wrpoll(be, &be->event_thread->tunables.retry_ur);
    }
}

// read handler.
static void proxy_backend_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    int bread = cqe->res;
    // Error or disconnection.
    if (bread <= 0) {
        _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
        // NOTE: Not calling backed_failed here since if the backend is busted
        // it should be caught by the connect routine.
        // This is probably not _always_ true in practice. Leaving this note
        // so I can re-evaluate later.
        return;
    }

    be->rbufused += bread;
    int res = proxy_backend_drive_machine(be);

    if (res > 0) {
        _proxy_evthr_evset_be_read(be, be->rbuf+be->rbufused, READ_BUFFER_SIZE-be->rbufused, &be->event_thread->tunables.read_ur);
        return;
    } else if (res == -1) {
        _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
        return;
    }

    // TODO (v2): when exactly do we need to reset the backend handler?
    if (!STAILQ_EMPTY(&be->io_head)) {
        _proxy_evthr_evset_be_read(be, be->rbuf+be->rbufused, READ_BUFFER_SIZE-be->rbufused, &be->event_thread->tunables.read_ur);
    }
}

static void proxy_backend_wrhandler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    int flags = 0;

    be->can_write = true;
    if (be->connecting) {
        int err = 0;
        // We were connecting, now ensure we're properly connected.
        if (mcmc_check_nonblock_connect(be->client, &err) != MCMC_OK) {
            // kick the bad backend, clear the queue, retry later.
            // TODO (v2): if a connect fails, anything currently in the queue
            // should be safe to hold up until their timeout.
            _reset_bad_backend(be, P_BE_FAIL_CONNECTING);
            _backend_failed_ur(be);
            P_DEBUG("%s: backend failed to connect\n", __func__);
            return;
        }
        P_DEBUG("%s: backend connected\n", __func__);
        be->connecting = false;
        be->state = mcp_backend_read;
        be->bad = false;
        be->failed_count = 0;
    }
    int res = _flush_pending_write(be);
    if (res == -1) {
        _reset_bad_backend(be, P_BE_FAIL_WRITING);
        return;
    }

    if (flags & EV_WRITE) {
        _proxy_evthr_evset_be_wrpoll(be, &be->event_thread->tunables.connect_ur);
    }

    _proxy_evthr_evset_be_read(be, be->rbuf, READ_BUFFER_SIZE, &be->event_thread->tunables.read_ur);
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
        int flags = 0;

        if (be->connecting) {
            P_DEBUG("%s: deferring IO pending connecting\n", __func__);
            flags |= EV_WRITE;
        } else {
            flags = _flush_pending_write(be);
        }

        if (flags == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
        } else {
            // FIXME (v2): needs a re-write to handle sqe starvation.
            // FIXME (v2): can't actually set the read here? need to confirm _some_
            // write first?
            if (flags & EV_WRITE) {
                _proxy_evthr_evset_be_wrpoll(be, &t->tunables.connect_ur);
            }
            if (flags & EV_READ) {
                _proxy_evthr_evset_be_read(be, be->rbuf, READ_BUFFER_SIZE, &t->tunables.read_ur);
            }
        }
    }
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

static void _proxy_evthr_evset_clock(proxy_event_thread_t *t) {
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&t->ring);
    // FIXME (v2): NULL?

    io_uring_prep_timeout(sqe, &updater_ts, 0, 0);
    io_uring_sqe_set_data(sqe, &t->ur_clock_event);
    t->ur_clock_event.set = true;
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

// TODO (v2): CQE's can generate many SQE's, so we might need to occasionally check
// for space free in the sqe queue and submit in the middle of the cqe
// foreach.
// There might be better places to do this, but I think it's cleaner if
// submission and cqe can stay in this function.
// TODO (v2): The problem is io_submit() can deadlock if too many cqe's are
// waiting.
// Need to understand if this means "CQE's ready to be picked up" or "CQE's in
// flight", because the former is much easier to work around (ie; only run the
// backend handler after dequeuing everything else)
// TODO (v2): IOURING_FEAT_NODROP: uring_submit() should return -EBUSY if out of CQ
// events slots. Therefore might starve SQE's if we were low beforehand.
// - switch from for_each_cqe to doing one at a time (for now?)
// - track # of sqe's allocated in the cqe loop.
// - stop and submit if we've >= half the queue.
// - ??? when can a CQE generate > 1 SQE?
//   - wrhandler_ur can set both wrpoll and read
// - if CQE's can gen > 1 SQE at a time, we'll eventually starve.
// - proper flow: CQE's can enqueue backends to be processed.
// - after CQE's are processed, backends are processed (ouch?)
//   - if SQE's starve here, bail but keep the BE queue.
// - then submit SQE's
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
            pe->set = false;
            pe->cb(pe->udata, cqe);

            count++;
        }

        P_DEBUG("%s: advancing [count:%d]\n", __func__, count);
        io_uring_cq_advance(&t->ring, count);
    }

    return NULL;
}
#endif // HAVE_LIBURING

// We need to get timeout/retry/etc updates to the event thread(s)
// occasionally. I'd like to have a better inteface around this where updates
// are shipped directly; but this is good enough to start with.
static void proxy_event_updater(evutil_socket_t fd, short which, void *arg) {
    proxy_event_thread_t *t = arg;
    proxy_ctx_t *ctx = t->ctx;

    // TODO (v2): double check how much of this boilerplate is still necessary?
    // reschedule the clock event.
    evtimer_del(&t->clock_event);

    evtimer_set(&t->clock_event, proxy_event_updater, t);
    event_base_set(t->base, &t->clock_event);
    struct timeval rate = {.tv_sec = 3, .tv_usec = 0};
    evtimer_add(&t->clock_event, &rate);

    // we reuse the "global stats" lock since it's hardly ever used.
    STAT_L(ctx);
    memcpy(&t->tunables, &ctx->tunables, sizeof(t->tunables));
    STAT_UL(ctx);
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
    mcp_backend_t *be = NULL;
    struct timeval tmp_time = t->tunables.read;

    // FIXME (v2): _set_event() is buggy, see notes on function.
    STAILQ_FOREACH(be, &t->be_head, be_next) {
        be->stacked = false;
        int flags = 0;

        if (be->connecting) {
            P_DEBUG("%s: deferring IO pending connecting\n", __func__);
        } else {
            flags = _flush_pending_write(be);
        }

        if (flags == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
        } else {
            flags = be->can_write ? EV_READ|EV_TIMEOUT : EV_READ|EV_WRITE|EV_TIMEOUT;
            _set_event(be, t->base, flags, tmp_time, proxy_backend_handler);
        }
    }

}

void *proxy_event_thread(void *arg) {
    proxy_event_thread_t *t = arg;

    logger_create(); // TODO (v2): add logger ptr to structure
    event_base_loop(t->base, 0);
    event_base_free(t->base);

    // TODO (v2): join bt threads, free array.

    return NULL;
}

// FIXME (v2): if we use the newer API the various pending checks can be adjusted.
static void _set_event(mcp_backend_t *be, struct event_base *base, int flags, struct timeval t, event_callback_fn callback) {
    // FIXME (v2): chicken and egg.
    // can't check if pending if the structure is was calloc'ed (sigh)
    // don't want to double test here. should be able to event_assign but
    // not add anything during initialization, but need the owner thread's
    // event base.
    int pending = 0;
    if (event_initialized(&be->event)) {
        pending = event_pending(&be->event, EV_READ|EV_WRITE|EV_TIMEOUT, NULL);
    }
    if ((pending & (EV_READ|EV_WRITE|EV_TIMEOUT)) != 0) {
            event_del(&be->event); // replace existing event.
    }

    // if we can't write, we could be connecting.
    // TODO (v2): always check for READ in case some commands were sent
    // successfully? The flags could be tracked on *be and reset in the
    // handler, perhaps?
    event_assign(&be->event, base, mcmc_fd(be->client),
            flags, callback, be);
    event_add(&be->event, &t);
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
    int flags = 0;

    p = STAILQ_FIRST(&be->io_head);
    if (p == NULL) {
        // got a read event, but nothing was queued.
        // probably means a disconnect event.
        // TODO (v2): could probably confirm this by attempting to read the
        // socket, getsockopt, or something else simply for logging or
        // statistical purposes.
        // In this case we know it's going to be a close so error.
        flags = -1;
        P_DEBUG("%s: read event but nothing in IO queue\n", __func__);
        return flags;
    }

    while (!stop) {
        mcp_resp_t *r;
        int res = 1;

    switch(be->state) {
        case mcp_backend_read:
            assert(p != NULL);
            // FIXME: remove the _read state?
            be->state = mcp_backend_parse;
            break;
        case mcp_backend_parse:
            r = p->client_resp;
            r->status = mcmc_parse_buf(be->client, be->rbuf, be->rbufused, &r->resp);
            if (r->status != MCMC_OK) {
                P_DEBUG("%s: mcmc_read failed [%d]\n", __func__, r->status);
                if (r->status == MCMC_WANT_READ) {
                    return EV_READ;
                } else {
                    flags = -1;
                    stop = true;
                    break;
                }
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
                    flags = -1;
                    stop = true;
                    break;
            }

            if (res) {
                if (p->ascii_multiget && r->resp.type == MCMC_RESP_END) {
                    // Ascii multiget hack mode; consume END's
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
                    flags = -1; // TODO (v2): specific error.
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
                    flags |= EV_READ;
                    stop = true;
                    break;
                } else {
                    // mcmc's already counted the value as read if it fit in
                    // the original buffer...
                    memcpy(r->buf, be->rbuf, r->resp.reslen+r->resp.vlen_read);
                }
            } else {
                // TODO (v2): no response read?
                // nothing currently sets res to 0. should remove if that
                // never comes up and handle the error entirely above.
                P_DEBUG("%s: no response read from backend\n", __func__);
                flags = -1;
                stop = true;
                break;
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
                    // TODO (v2): specific error.
                    flags = -1;
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
                flags |= EV_READ;
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

            if (r->bread >= r->resp.vlen) {
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
                flags |= EV_READ;
                stop = true;
            }

            break;
        case mcp_backend_next:
            // set the head here. when we break the head will be correct.
            STAILQ_REMOVE_HEAD(&be->io_head, io_next);
            be->depth--;
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
                    flags = -1;
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

// All we need to do here is schedule the backend to attempt to connect again.
static void proxy_backend_retry_handler(const int fd, const short which, void *arg) {
    mcp_backend_t *be = arg;
    assert(which & EV_TIMEOUT);
    struct timeval tmp_time = be->event_thread->tunables.retry;
    _set_event(be, be->event_thread->base, EV_WRITE|EV_TIMEOUT, tmp_time, proxy_backend_handler);
}

// currently just for timeouts, but certain errors should consider a backend
// to be "bad" as well.
// must be called before _reset_bad_backend(), so the backend is currently
// clear.
// TODO (v2): currently only notes for "bad backends" in cases of timeouts or
// connect failures. We need a specific connect() handler that executes a
// "version" call to at least check that the backend isn't speaking garbage.
// In theory backends can fail such that responses are constantly garbage,
// but it's more likely an app is doing something bad and culling the backend
// may prevent any other clients from talking to that backend. In
// that case we need to track if clients are causing errors consistently and
// block them instead. That's more challenging so leaving a note instead
// of doing this now :)
static void _backend_failed(mcp_backend_t *be) {
    struct timeval tmp_time = be->event_thread->tunables.retry;
    if (++be->failed_count > be->event_thread->tunables.backend_failure_limit) {
        P_DEBUG("%s: marking backend as bad\n", __func__);
        be->bad = true;
       _set_event(be, be->event_thread->base, EV_TIMEOUT, tmp_time, proxy_backend_retry_handler);
        STAT_INCR(be->event_thread->ctx, backend_marked_bad, 1);
    } else {
        STAT_INCR(be->event_thread->ctx, backend_failed, 1);
        _set_event(be, be->event_thread->base, EV_WRITE|EV_TIMEOUT, tmp_time, proxy_backend_handler);
    }
}

const char *proxy_be_failure_text[] = {
    [P_BE_FAIL_TIMEOUT] = "timeout",
    [P_BE_FAIL_DISCONNECTED] = "disconnected",
    [P_BE_FAIL_CONNECTING] = "connecting",
    [P_BE_FAIL_WRITING] = "writing",
    [P_BE_FAIL_READING] = "reading",
    [P_BE_FAIL_PARSING] = "parsing",
    NULL
};

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

    // reset buffer to blank state.
    be->rbufused = 0;
    mcmc_disconnect(be->client);
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

    LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_BE_ERROR, NULL, proxy_be_failure_text[err], be->name, be->port);

    return 0;
}

static int _prep_pending_write(mcp_backend_t *be, unsigned int *tosend) {
    struct iovec *iovs = be->write_iovs;
    io_pending_proxy_t *io = NULL;
    int iovused = 0;
    STAILQ_FOREACH(io, &be->io_head, io_next) {
        if (io->flushed)
            continue;

        if (io->iovcnt + iovused > BE_IOV_MAX) {
            // Signal to caller that we need to keep writing, if writeable.
            // FIXME (v2): can certainly refactor this to loop instead of waiting
            // for a writeable event.
            *tosend += 1;
            break;
        }

        memcpy(&iovs[iovused], io->iov, sizeof(struct iovec)*io->iovcnt);
        iovused += io->iovcnt;
        *tosend += io->iovbytes;
    }
    return iovused;
}

static int _flush_pending_write(mcp_backend_t *be) {
    int flags = 0;
    unsigned int tosend = 0;
    int iovcnt = _prep_pending_write(be, &tosend);

    ssize_t sent = writev(mcmc_fd(be->client), be->write_iovs, iovcnt);
    if (sent > 0) {
        io_pending_proxy_t *io = NULL;
        if (sent < tosend) {
            flags |= EV_WRITE;
        }

        STAILQ_FOREACH(io, &be->io_head, io_next) {
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
                        sent = 0;
                        flushed = false;
                        break;
                    }
                }
            }
            io->flushed = flushed;

            if (flushed) {
                flags |= EV_READ;
            }
            if (sent <= 0) {
                // really shouldn't be negative, though.
                assert(sent >= 0);
                break;
            }
        } // STAILQ_FOREACH
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

// The libevent backend callback handler.
// If we end up resetting a backend, it will get put back into a connecting
// state.
static void proxy_backend_handler(const int fd, const short which, void *arg) {
    mcp_backend_t *be = arg;
    int flags = EV_TIMEOUT;
    struct timeval tmp_time = be->event_thread->tunables.read;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: timeout received, killing backend queue\n", __func__);
        _reset_bad_backend(be, P_BE_FAIL_TIMEOUT);
        _backend_failed(be);
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;
        // TODO (v2): move connect routine to its own function?
        // - hard to do right now because we can't (easily?) edit libevent
        // events.
        if (be->connecting) {
            int err = 0;
            // We were connecting, now ensure we're properly connected.
            if (mcmc_check_nonblock_connect(be->client, &err) != MCMC_OK) {
                // kick the bad backend, clear the queue, retry later.
                // FIXME (v2): if a connect fails, anything currently in the queue
                // should be safe to hold up until their timeout.
                _reset_bad_backend(be, P_BE_FAIL_CONNECTING);
                _backend_failed(be);
                P_DEBUG("%s: backend failed to connect\n", __func__);
                return;
            }
            P_DEBUG("%s: backend connected\n", __func__);
            be->connecting = false;
            be->state = mcp_backend_read;
            be->bad = false;
            be->failed_count = 0;
        }
        int res = _flush_pending_write(be);
        if (res == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
            return;
        }
    }

    if (which & EV_READ) {
        // We do the syscall here before diving into the state machine to allow a
        // common code path for io_uring/epoll
        int read = recv(mcmc_fd(be->client), be->rbuf + be->rbufused,
                    READ_BUFFER_SIZE - be->rbufused, 0);
        if (read > 0) {
            be->rbufused += read;
            int res = proxy_backend_drive_machine(be);
            if (res == -1) {
                _reset_bad_backend(be, P_BE_FAIL_PARSING);
                return;
            }
        } else if (read == 0) {
            // not connected or error.
            _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
            return;
        } else if (read == -1) {
            // sit on epoll again.
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                _reset_bad_backend(be, P_BE_FAIL_READING);
                return;
            }
        }

#ifdef PROXY_DEBUG
        if (!STAILQ_EMPTY(&be->io_head)) {
            P_DEBUG("backend has leftover IOs: %d\n", be->depth);
        }
#endif
    }

    // Still pending requests to read or write.
    if (!STAILQ_EMPTY(&be->io_head)) {
        flags |= EV_READ; // FIXME (v2): might not be necessary here, but ensures we get a disconnect event.
        _set_event(be, be->event_thread->base, flags, tmp_time, proxy_backend_handler);
    }
}

// TODO (v2): IORING_SETUP_ATTACH_WQ port from bench_event once we have multiple
// event threads.
void proxy_init_evthread_events(proxy_event_thread_t *t) {
#ifdef HAVE_LIBURING
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
            close(t->event_fd);
            t->event_fd = eventfd(0, 0);
            // FIXME (v2): hack for event init.
            t->ur_notify_event.set = false;
            _proxy_evthr_evset_notifier(t);

            // periodic data updater for event thread
            t->ur_clock_event.cb = proxy_event_updater_ur;
            t->ur_clock_event.udata = t;
            t->ur_clock_event.set = false;
            _proxy_evthr_evset_clock(t);

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

    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    t->base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);
    if (! t->base) {
        fprintf(stderr, "Can't allocate event base\n");
        exit(1);
    }

    // listen for notifications.
    // NULL was thread_libevent_process
    // FIXME (v2): use modern format? (event_assign)
#ifdef USE_EVENTFD
    event_set(&t->notify_event, t->event_fd,
          EV_READ | EV_PERSIST, proxy_event_handler, t);
#else
    event_set(&t->notify_event, t->notify_receive_fd,
          EV_READ | EV_PERSIST, proxy_event_handler, t);
#endif

    evtimer_set(&t->clock_event, proxy_event_updater, t);
    event_base_set(t->base, &t->clock_event);
    struct timeval rate = {.tv_sec = 3, .tv_usec = 0};
    evtimer_add(&t->clock_event, &rate);

    event_base_set(t->base, &t->notify_event);
    if (event_add(&t->notify_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }

}



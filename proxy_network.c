/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
// Functions related to the backend handler thread.

#include "proxy.h"
#include "proxy_tls.h"

enum proxy_be_failures {
    P_BE_FAIL_TIMEOUT = 0,
    P_BE_FAIL_DISCONNECTED,
    P_BE_FAIL_CONNECTING,
    P_BE_FAIL_CONNTIMEOUT,
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
    P_BE_FAIL_INVALIDPROTOCOL,
};

const char *proxy_be_failure_text[] = {
    [P_BE_FAIL_TIMEOUT] = "timeout",
    [P_BE_FAIL_DISCONNECTED] = "disconnected",
    [P_BE_FAIL_CONNECTING] = "connecting",
    [P_BE_FAIL_CONNTIMEOUT] = "conntimeout",
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
    [P_BE_FAIL_INVALIDPROTOCOL] = "invalidprotocol",
    NULL
};

static void proxy_backend_handler(const int fd, const short which, void *arg);
static void proxy_backend_tls_handler(const int fd, const short which, void *arg);
static void proxy_beconn_handler(const int fd, const short which, void *arg);
static void proxy_beconn_tls_handler(const int fd, const short which, void *arg);
static void proxy_event_handler(evutil_socket_t fd, short which, void *arg);
static void proxy_event_beconn(evutil_socket_t fd, short which, void *arg);
static int _prep_pending_write(struct mcp_backendconn_s *be);
static void _post_pending_write(struct mcp_backendconn_s *be, ssize_t sent);
static int _flush_pending_write(struct mcp_backendconn_s *be);
static int _flush_pending_tls_write(struct mcp_backendconn_s *be);
static void _cleanup_backend(mcp_backend_t *be);
static void _reset_bad_backend(struct mcp_backendconn_s *be, enum proxy_be_failures err);
static void _set_main_event(struct mcp_backendconn_s *be, struct event_base *base, int flags, struct timeval *t, event_callback_fn callback);
static void _stop_main_event(struct mcp_backendconn_s *be);
static void _start_write_event(struct mcp_backendconn_s *be);
static void _stop_write_event(struct mcp_backendconn_s *be);
static void _start_timeout_event(struct mcp_backendconn_s *be);
static void _stop_timeout_event(struct mcp_backendconn_s *be);
static int proxy_backend_drive_machine(struct mcp_backendconn_s *be);

/* Helper routines common to io_uring and libevent modes */

// TODO (v3): doing an inline syscall here, not ideal for uring mode.
// leaving for now since this should be extremely uncommon.
static int _beconn_send_validate(struct mcp_backendconn_s *be) {
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

static int _proxy_beconn_checkconnect(struct mcp_backendconn_s *be) {
    int err = 0;
    // We were connecting, now ensure we're properly connected.
    if (mcmc_check_nonblock_connect(be->client, &err) != MCMC_OK) {
        P_DEBUG("%s: backend failed to connect (%s:%s)\n", __func__, be->be_parent->name, be->be_parent->port);
        // kick the bad backend, clear the queue, retry later.
        // FIXME (v2): if a connect fails, anything currently in the queue
        // should be safe to hold up until their timeout.
        _reset_bad_backend(be, P_BE_FAIL_CONNECTING);
        return -1;
    }
    P_DEBUG("%s: backend connected [fd: %d] (%s:%s)\n", __func__, mcmc_fd(be->client), be->be_parent->name, be->be_parent->port);
    be->connecting = false;
    be->state = mcp_backend_read;

    // seed the failure time for the flap check.
    gettimeofday(&be->last_failed, NULL);

    be->validating = true;
    // TODO: make validation optional.

    return 0;
}

// Use a simple heuristic to choose a backend connection socket out of a list
// of sockets.
struct mcp_backendconn_s *proxy_choose_beconn(mcp_backend_t *be) {
    struct mcp_backendconn_s *bec = &be->be[0];
    if (be->conncount != 1) {
        int depth = INT_MAX;
        // TODO: to computationally limit + ensure each connection stays
        // somewhat warm:
        // - remember idx of last conn used.
        // - if next idx has a lower depth, use that one instead
        // - tick idx (and reset if necessary)
        // else under low loads only the first conn will ever get used (which
        // is normally good; but sometimes bad if using stateful firewalls)
        for (int x = 0; x < be->conncount; x++) {
            struct mcp_backendconn_s *bec_i = &be->be[x];
            if (bec_i->bad) {
                continue;
            }
            if (bec_i->depth == 0) {
                bec = bec_i;
                break;
            } else if (bec_i->depth < depth) {
                depth = bec_i->depth;
                bec = bec_i;
            }
        }
    }

    return bec;
}

static void _proxy_event_handler_dequeue(proxy_event_thread_t *t) {
    io_head_t head;

    STAILQ_INIT(&head);
    STAILQ_INIT(&t->be_head);

    // Pull the entire stack of inbound into local queue.
    pthread_mutex_lock(&t->mutex);
    STAILQ_CONCAT(&head, &t->io_head_in);
    pthread_mutex_unlock(&t->mutex);

    while (!STAILQ_EMPTY(&head)) {
        io_pending_proxy_t *io = STAILQ_FIRST(&head);
        io->flushed = false;

        // _no_ mutex on backends. they are owned by the event thread.
        STAILQ_REMOVE_HEAD(&head, io_next);
        // paranoia about moving items between lists.
        io->io_next.stqe_next = NULL;

        mcp_backend_t *be = io->backend;
        STAILQ_INSERT_TAIL(&be->io_head, io, io_next);
        assert(be->depth > -1);
        be->depth++;
        if (!be->stacked) {
            be->stacked = true;
            STAILQ_INSERT_TAIL(&t->be_head, be, be_next);
        }
    }
}

static void _cleanup_backend(mcp_backend_t *be) {
    for (int x = 0; x < be->conncount; x++) {
        struct mcp_backendconn_s *bec = &be->be[x];
        // remove any pending events.
        if (!be->tunables.down) {
            int pending = event_pending(&bec->main_event, EV_READ|EV_WRITE|EV_TIMEOUT, NULL);
            if (pending != 0) {
                event_del(&bec->main_event); // an error to call event_del() without event.
            }
            pending = event_pending(&bec->write_event, EV_READ|EV_WRITE|EV_TIMEOUT, NULL);
            if (pending != 0) {
                event_del(&bec->write_event); // an error to call event_del() without event.
            }
            pending = event_pending(&bec->timeout_event, EV_TIMEOUT, NULL);
            if (pending != 0) {
                event_del(&bec->timeout_event); // an error to call event_del() without event.
            }

            // - assert on empty queue
            assert(STAILQ_EMPTY(&bec->io_head));

            mcp_tls_shutdown(bec);
            mcmc_disconnect(bec->client);

            if (bec->bad) {
                mcp_sharedvm_delta(bec->event_thread->ctx, SHAREDVM_BACKEND_IDX,
                    bec->be_parent->label, -1);
            }
        }
        // - free be->client
        free(bec->client);
        // - free be->rbuf
        free(bec->rbuf);
    }
    // free once parent has had all connections closed off.
    free(be);
}

static void _setup_backend(mcp_backend_t *be) {
    for (int x = 0; x < be->conncount; x++) {
        struct mcp_backendconn_s *bec = &be->be[x];
        if (be->tunables.down) {
            // backend is "forced" into a bad state. never connect or
            // otherwise attempt to use it.
            be->be[x].bad = true;
            continue;
        }
        // assign the initial events to the backend, so we don't have to
        // constantly check if they were initialized yet elsewhere.
        // note these events will not fire until event_add() is called.
        int status = mcmc_connect(bec->client, be->name, be->port, bec->connect_flags);
        event_callback_fn _beconn_handler = &proxy_beconn_handler;
        event_callback_fn _backend_handler = &proxy_backend_handler;
        if (be->tunables.use_tls) {
            _beconn_handler = &proxy_beconn_tls_handler;
            _backend_handler = &proxy_backend_tls_handler;
        }
        event_assign(&bec->main_event, bec->event_thread->base, mcmc_fd(bec->client), EV_WRITE|EV_TIMEOUT, _beconn_handler, bec);
        event_assign(&bec->write_event, bec->event_thread->base, mcmc_fd(bec->client), EV_WRITE|EV_TIMEOUT, _backend_handler, bec);
        event_assign(&bec->timeout_event, bec->event_thread->base, -1, EV_TIMEOUT, _backend_handler, bec);

        if (status == MCMC_CONNECTING || status == MCMC_CONNECTED) {
            // if we're already connected for some reason, still push it
            // through the connection handler to keep the code unified. It
            // will auto-wake because the socket is writeable.
            bec->connecting = true;
            bec->can_write = false;
            // kick off the event we intialized above.
            event_add(&bec->main_event, &bec->tunables.connect);
        } else {
            _reset_bad_backend(bec, P_BE_FAIL_CONNECTING);
        }
    }
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
            _setup_backend(be);
        }
    }
}

static void _proxy_flush_backend_queue(mcp_backend_t *be) {
    io_pending_proxy_t *io = NULL;
    P_DEBUG("%s: fast failing request to bad backend (%s:%s) depth: %d\n", __func__, be->name, be->port, be->depth);

    while (!STAILQ_EMPTY(&be->io_head)) {
        io = STAILQ_FIRST(&be->io_head);
        STAILQ_REMOVE_HEAD(&be->io_head, io_next);
        mcp_resp_set_elapsed(io->client_resp);
        io->client_resp->status = MCMC_ERR;
        io->client_resp->resp.code = MCMC_CODE_SERVER_ERROR;
        be->depth--;
        assert(be->depth > -1);
        return_io_pending((io_pending_t *)io);
    }
}

void proxy_run_backend_queue(be_head_t *head) {
    mcp_backend_t *be;
    STAILQ_FOREACH(be, head, be_next) {
        be->stacked = false;
        int flags = 0;
        struct mcp_backendconn_s *bec = proxy_choose_beconn(be);

        int limit = be->tunables.backend_depth_limit;
        if (bec->bad) {
            // TODO: another counter for fast fails?
            _proxy_flush_backend_queue(be);
            continue;
        } else if (limit && bec->depth > limit) {
            proxy_ctx_t *ctx = bec->event_thread->ctx;
            STAT_INCR(ctx, request_failed_depth, be->depth);
            _proxy_flush_backend_queue(be);
            continue;
        }

        // drop new requests onto end of conn's io-head, reset the backend one.
        STAILQ_CONCAT(&bec->io_head, &be->io_head);
        bec->depth += be->depth;
        be->depth = 0;

        if (bec->connecting || bec->validating) {
            P_DEBUG("%s: deferring IO pending connecting (%s:%s)\n", __func__, be->name, be->port);
        } else {
            if (!bec->ssl) {
                flags = _flush_pending_write(bec);
            } else {
                flags = _flush_pending_tls_write(bec);
            }

            if (flags == -1) {
                _reset_bad_backend(bec, P_BE_FAIL_WRITING);
            } else if (flags & EV_WRITE) {
                // only get here because we need to kick off the write handler
                _start_write_event(bec);
            }

            if (bec->pending_read) {
                _start_timeout_event(bec);
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

    _proxy_event_handler_dequeue(t);

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

static void _set_main_event(struct mcp_backendconn_s *be, struct event_base *base, int flags, struct timeval *t, event_callback_fn callback) {
    int pending = event_pending(&be->main_event, EV_READ|EV_WRITE|EV_TIMEOUT, NULL);
    if (pending != 0) {
        event_del(&be->main_event); // replace existing event.
    }

    int fd = mcmc_fd(be->client);
    if (fd == 0) {
        fd = -1; // need to pass -1 to event assign if we're not operating on
                 // a connection.
    }
    event_assign(&be->main_event, base, fd,
            flags, callback, be);
    event_add(&be->main_event, t);
}

static void _stop_main_event(struct mcp_backendconn_s *be) {
    event_del(&be->main_event);
}

static void _start_write_event(struct mcp_backendconn_s *be) {
    int pending = event_pending(&be->write_event, EV_WRITE|EV_TIMEOUT, NULL);
    if (pending != 0) {
        return;
    }
    // FIXME: wasn't there a write timeout?
    event_add(&be->write_event, &be->tunables.read);
}

static void _stop_write_event(struct mcp_backendconn_s *be) {
    event_del(&be->write_event);
}

// handle the read timeouts with a side event, so we can stick with a
// persistent listener (optimization + catch disconnects faster)
static void _start_timeout_event(struct mcp_backendconn_s *be) {
    int pending = event_pending(&be->timeout_event, EV_TIMEOUT, NULL);
    if (pending != 0) {
        return;
    }
    event_add(&be->timeout_event, &be->tunables.read);
}

static void _stop_timeout_event(struct mcp_backendconn_s *be) {
    int pending = event_pending(&be->timeout_event, EV_TIMEOUT, NULL);
    if (pending == 0) {
        return;
    }
    event_del(&be->timeout_event);
}

static void _drive_machine_next(struct mcp_backendconn_s *be, io_pending_proxy_t *p) {
    // set the head here. when we break the head will be correct.
    STAILQ_REMOVE_HEAD(&be->io_head, io_next);
    be->depth--;
    assert(p != be->io_next); // don't remove what we need to flush.
    assert(be->depth > -1);
    be->pending_read--;
    assert(be->pending_read > -1);

    mcp_resp_set_elapsed(p->client_resp);
    // have to do the q->count-- and == 0 and redispatch_conn()
    // stuff here. The moment we call return_io here we
    // don't own *p anymore.
    return_io_pending((io_pending_t *)p);
    be->state = mcp_backend_read;
}

// NOTES:
// - mcp_backend_read: grab req_stack_head, do things
// read -> next, want_read -> next | read_end, etc.
static int proxy_backend_drive_machine(struct mcp_backendconn_s *be) {
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
            r->status = mcmc_parse_buf(be->rbuf, be->rbufused, &r->resp);

            // Quick check if we need more data.
            if (r->resp.code == MCMC_WANT_READ) {
                return 0;
            }

            // we actually don't care about anything but the value length
            // TODO (v2): if vlen != vlen_read, pull an item and copy the data.
            int extra_space = 0;
            // if all goes well, move to the next request.
            be->state = mcp_backend_next;
            switch (r->resp.type) {
                case MCMC_RESP_GET:
                    // We're in GET mode. we only support one key per
                    // GET in the proxy backends, so we need to later check
                    // for an END.
                    extra_space = ENDLEN;
                    be->state = mcp_backend_read_end;
                    break;
                case MCMC_RESP_END:
                    // this is a MISS from a GET request
                    // or final handler from a STAT request.
                    assert(r->resp.vlen == 0);
                    if (p->ascii_multiget) {
                        // Ascii multiget hack mode; consume END's
                        be->rbufused -= r->resp.reslen;
                        if (be->rbufused > 0) {
                            memmove(be->rbuf, be->rbuf+r->resp.reslen, be->rbufused);
                        }

                        be->state = mcp_backend_next;
                        continue;
                    }
                    break;
                case MCMC_RESP_META:
                    // we can handle meta responses easily since they're self
                    // contained.
                    break;
                case MCMC_RESP_GENERIC:
                case MCMC_RESP_NUMERIC:
                    break;
                case MCMC_RESP_ERRMSG: // received an error message
                    if (r->resp.code != MCMC_CODE_SERVER_ERROR) {
                        // Non server errors are protocol errors; can't trust
                        // the connection anymore.
                        be->state = mcp_backend_next_close;
                    }
                    break;
                case MCMC_RESP_FAIL:
                    P_DEBUG("%s: mcmc_read failed [%d]\n", __func__, r->status);
                    flags = P_BE_FAIL_PARSING;
                    stop = true;
                    break;
                // TODO (v2): No-op response?
                default:
                    P_DEBUG("%s: Unhandled response from backend: %d\n", __func__, r->resp.type);
                    // unhandled :(
                    flags = P_BE_FAIL_UNHANDLEDRES;
                    stop = true;
                    break;
            }

            // r->resp.reslen + r->resp.vlen is the total length of the response.
            // TODO (v2): need to associate a buffer with this response...
            // for now we simply malloc, but reusable buffers should be used

            r->blen = r->resp.reslen + r->resp.vlen;
            {
                bool oom = proxy_bufmem_checkadd(r->thread, r->blen + extra_space);

                if (oom) {
                    flags = P_BE_FAIL_OOM;
                    // need to zero out blen so we don't over-decrement later
                    r->blen = 0;
                    stop = true;
                    break;
                }
            }
            r->buf = malloc(r->blen + extra_space);
            if (r->buf == NULL) {
                // Enforce accounting.
                pthread_mutex_lock(&r->thread->proxy_limit_lock);
                r->thread->proxy_buffer_memory_used -= r->blen + extra_space;
                pthread_mutex_unlock(&r->thread->proxy_limit_lock);

                flags = P_BE_FAIL_OOM;
                r->blen = 0;
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
                    } else {
                        r->extra = 5;
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
            _drive_machine_next(be, p);

            if (STAILQ_EMPTY(&be->io_head)) {
                stop = true;
                // if there're no pending requests, the read buffer
                // should also be empty.
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
        case mcp_backend_next_close:
            // we advance and return the current IO, then kill the conn.
            _drive_machine_next(be, p);
            stop = true;
            flags = P_BE_FAIL_INVALIDPROTOCOL;

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

static void _backend_reconnect(struct mcp_backendconn_s *be) {
    int status = mcmc_connect(be->client, be->be_parent->name, be->be_parent->port, be->connect_flags);
    if (status == MCMC_CONNECTED) {
        // TODO (v2): unexpected but lets let it be here.
        be->connecting = false;
        be->can_write = true;
    } else if (status == MCMC_CONNECTING) {
        be->connecting = true;
        be->can_write = false;
    } else {
        // failed to immediately re-establish the connection.
        // need to put the BE into a bad/retry state.
        be->connecting = false;
        be->can_write = true;
    }
    // re-create the write handler for the new file descriptor.
    // the main event will be re-assigned after this call.
    event_callback_fn _backend_handler = &proxy_backend_handler;
    if (be->be_parent->tunables.use_tls) {
        _backend_handler = &proxy_backend_tls_handler;
    }
    event_assign(&be->write_event, be->event_thread->base, mcmc_fd(be->client), EV_WRITE|EV_TIMEOUT, _backend_handler, be);
    // do not need to re-assign the timer event because it's not tied to fd
}

// All we need to do here is schedule the backend to attempt to connect again.
static void proxy_backend_retry_handler(const int fd, const short which, void *arg) {
    struct mcp_backendconn_s *be = arg;
    assert(which & EV_TIMEOUT);
    struct timeval tmp_time = be->tunables.connect;
    _backend_reconnect(be);
    event_callback_fn _backend_handler = &proxy_beconn_handler;
    if (be->be_parent->tunables.use_tls) {
        _backend_handler = &proxy_beconn_tls_handler;
    }
    _set_main_event(be, be->event_thread->base, EV_WRITE, &tmp_time, _backend_handler);
}

// must be called after _reset_bad_backend(), so the backend is currently
// clear.
// TODO (v2): extra counter for "backend connect tries" so it's still possible
// to see dead backends exist
static void _backend_reschedule(struct mcp_backendconn_s *be) {
    bool failed = false;
    struct timeval tmp_time = {0};
    long int retry_time = be->tunables.retry.tv_sec;
    char *badtext = "markedbad";
    if (be->flap_count > be->tunables.backend_failure_limit) {
        // reduce retry frequency to avoid noise.
        float backoff = retry_time;
        for (int x = 0; x < be->flap_count; x++) {
            backoff *= be->tunables.flap_backoff_ramp;
        }
        retry_time = (uint32_t)backoff;

        if (retry_time > be->tunables.flap_backoff_max) {
            retry_time = be->tunables.flap_backoff_max;
        }
        badtext = "markedbadflap";
        failed = true;
    } else if (be->failed_count > be->tunables.backend_failure_limit) {
        failed = true;
    }
    tmp_time.tv_sec = retry_time;

    if (failed) {
        if (!be->bad) {
            P_DEBUG("%s: marking backend as bad\n", __func__);
            STAT_INCR(be->event_thread->ctx, backend_marked_bad, 1);
            mcp_sharedvm_delta(be->event_thread->ctx, SHAREDVM_BACKEND_IDX,
                    be->be_parent->label, 1);
            LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_BE_ERROR, NULL, badtext, be->be_parent->name, be->be_parent->port, be->be_parent->label, 0, NULL, 0, retry_time);
        }
        be->bad = true;
       _set_main_event(be, be->event_thread->base, EV_TIMEOUT, &tmp_time, proxy_backend_retry_handler);
    } else {
        struct timeval tmp_time = be->tunables.connect;
        STAT_INCR(be->event_thread->ctx, backend_failed, 1);
        _backend_reconnect(be);
        event_callback_fn _backend_handler = &proxy_beconn_handler;
        if (be->be_parent->tunables.use_tls) {
            _backend_handler = &proxy_beconn_tls_handler;
        }
        _set_main_event(be, be->event_thread->base, EV_WRITE, &tmp_time, _backend_handler);
    }
}

static void _backend_flap_check(struct mcp_backendconn_s *be, enum proxy_be_failures err) {
    struct timeval now;
    struct timeval *flap = &be->tunables.flap;

    switch (err) {
        case P_BE_FAIL_TIMEOUT:
        case P_BE_FAIL_DISCONNECTED:
        case P_BE_FAIL_WRITING:
        case P_BE_FAIL_READING:
            if (flap->tv_sec != 0 || flap->tv_usec != 0) {
                struct timeval delta = {0};
                int64_t subsec = 0;
                gettimeofday(&now, NULL);
                delta.tv_sec = now.tv_sec - be->last_failed.tv_sec;
                subsec = now.tv_usec - be->last_failed.tv_usec;
                if (subsec < 0) {
                    // tv_usec is specced as "at least" [-1, 1000000]
                    // so to guarantee lower negatives we need this temp var.
                    delta.tv_sec--;
                    subsec += 1000000;
                    delta.tv_usec = subsec;
                }

                if (flap->tv_sec < delta.tv_sec ||
                    (flap->tv_sec == delta.tv_sec && flap->tv_usec < delta.tv_usec)) {
                    // delta is larger than our flap range. reset the flap counter.
                    be->flap_count = 0;
                } else {
                    // seems like we flapped again.
                    be->flap_count++;
                }
                be->last_failed = now;
            }
            break;
        default:
            // only perform a flap check on network related errors.
            break;
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
static void _reset_bad_backend(struct mcp_backendconn_s *be, enum proxy_be_failures err) {
    io_pending_proxy_t *io = NULL;
    P_DEBUG("%s: resetting bad backend: [fd: %d] %s\n", __func__, mcmc_fd(be->client), proxy_be_failure_text[err]);
    // Can't use STAILQ_FOREACH() since r_io_p() free's the current
    // io. STAILQ_FOREACH_SAFE maybe?
    int depth = be->depth;
    while (!STAILQ_EMPTY(&be->io_head)) {
        io = STAILQ_FIRST(&be->io_head);
        STAILQ_REMOVE_HEAD(&be->io_head, io_next);
        // TODO (v2): Unsure if this is the best way of surfacing errors to lua,
        // but will do for V1.
        mcp_resp_set_elapsed(io->client_resp);
        io->client_resp->status = MCMC_ERR;
        io->client_resp->resp.code = MCMC_CODE_SERVER_ERROR;
        be->depth--;
        assert(be->depth > -1);
        return_io_pending((io_pending_t *)io);
    }

    STAILQ_INIT(&be->io_head);
    be->io_next = NULL; // also reset the write offset.

    // Only log if we don't already know it's messed up.
    if (!be->bad) {
        LOGGER_LOG(NULL, LOG_PROXYEVENTS, LOGGER_PROXY_BE_ERROR, NULL, proxy_be_failure_text[err], be->be_parent->name, be->be_parent->port, be->be_parent->label, depth, be->rbuf, be->rbufused, 0);
    }

    // reset buffer to blank state.
    be->rbufused = 0;
    be->pending_read = 0;
    // clear events so the reconnect handler can re-arm them with a few fd.
    _stop_write_event(be);
    _stop_main_event(be);
    _stop_timeout_event(be);
    mcp_tls_shutdown(be);
    mcmc_disconnect(be->client);
    // we leave the main event alone, because be_failed() always overwrites.

    // check failure counters and schedule a retry.
    be->failed_count++;
    _backend_flap_check(be, err);
    _backend_reschedule(be);
}

static int _prep_pending_write(struct mcp_backendconn_s *be) {
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
static void _post_pending_write(struct mcp_backendconn_s *be, ssize_t sent) {
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
    if (io != NULL) {
        if (!io->flushed) {
            be->io_next = io;
        } else {
            // Check for incomplete list because we hit the iovcnt limit.
            io_pending_proxy_t *nio = STAILQ_NEXT(io, io_next);
            if (nio != NULL && !nio->flushed) {
                be->io_next = nio;
            } else {
                be->io_next = NULL;
            }
        }
    } else {
        be->io_next = NULL;
    }
}

static int _flush_pending_write(struct mcp_backendconn_s *be) {
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

static int _flush_pending_tls_write(struct mcp_backendconn_s *be) {
    int flags = 0;
    // Allow us to be called with an empty stack to prevent dev errors.
    if (STAILQ_EMPTY(&be->io_head)) {
        return 0;
    }

    int iovcnt = _prep_pending_write(be);

    int sent = mcp_tls_writev(be, iovcnt);
    if (sent > 0) {
        _post_pending_write(be, sent);
        // FIXME: can _post_pending_write do this and return EV_WRITE?
        // still have unflushed pending IO's, check for write and re-loop.
        if (be->io_next) {
            be->can_write = false;
            flags |= EV_WRITE;
        }
    } else if (sent == MCP_TLS_NEEDIO) {
        // want io
        be->can_write = false;
        flags |= EV_WRITE;
    } else if (sent == MCP_TLS_ERR) {
        // hard error from tls
        flags = -1;
    }

    return flags;
}


static void proxy_bevalidate_tls_handler(const int fd, const short which, void *arg) {
    assert(arg != NULL);
    struct mcp_backendconn_s *be = arg;
    int flags = EV_TIMEOUT;
    struct timeval tmp_time = be->tunables.read;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: backend timed out while connecting [fd: %d]\n", __func__, mcmc_fd(be->client));
        if (be->connecting) {
            _reset_bad_backend(be, P_BE_FAIL_CONNTIMEOUT);
        } else {
            _reset_bad_backend(be, P_BE_FAIL_READVALIDATE);
        }
        return;
    }

    if (which & EV_READ) {
        int read = mcp_tls_read(be);

        if (read > 0) {
            mcmc_resp_t r;

            int status = mcmc_parse_buf(be->rbuf, be->rbufused, &r);
            if (status == MCMC_ERR) {
                // Needed more data for a version line, somehow. I feel like
                // this should set off some alarms, but it is possible.
                if (r.code == MCMC_WANT_READ) {
                    _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_bevalidate_tls_handler);
                    return;
                }

                _reset_bad_backend(be, P_BE_FAIL_READVALIDATE);
                return;
            }

            if (r.code != MCMC_CODE_VERSION) {
                _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
                return;
            }

            be->validating = false;
            be->rbufused = 0;
        } else if (read == 0) {
            // not connected or error.
            _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
            return;
        } else if (read == MCP_TLS_NEEDIO) {
            // try again failure.
            _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_bevalidate_tls_handler);
            return;
        } else if (read == MCP_TLS_ERR) {
            // hard failure.
            _reset_bad_backend(be, P_BE_FAIL_READING);
            return;
        }

        // Passed validation, don't need to re-read, flush any pending writes.
        int res = _flush_pending_tls_write(be);
        if (res == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
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
        _set_main_event(be, be->event_thread->base, EV_READ|EV_PERSIST, NULL, proxy_backend_tls_handler);

        // we're happily validated and switching to normal processing, so
        // _now_ the backend is no longer "bad".
        // If we reset the failed count earlier we then can fail the
        // validation loop indefinitely without ever being marked bad.
        if (be->bad) {
            // was bad, need to mark as no longer bad in shared space.
            mcp_sharedvm_delta(be->event_thread->ctx, SHAREDVM_BACKEND_IDX,
                    be->be_parent->label, -1);
        }
        be->bad = false;
        be->failed_count = 0;
    }
}

// Libevent handler when we're in TLS mode. Unfortunately the code is
// different enough to warrant its own function.
static void proxy_beconn_tls_handler(const int fd, const short which, void *arg) {
    assert(arg != NULL);
    struct mcp_backendconn_s *be = arg;
    //int flags = EV_TIMEOUT;
    struct timeval tmp_time = be->tunables.read;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: backend timed out while connecting [fd: %d]\n", __func__, mcmc_fd(be->client));
        if (be->connecting) {
            _reset_bad_backend(be, P_BE_FAIL_CONNTIMEOUT);
        } else {
            _reset_bad_backend(be, P_BE_FAIL_READVALIDATE);
        }
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;

        if (be->connecting) {
            if (_proxy_beconn_checkconnect(be) == -1) {
                return;
            }
            // TODO: check return code.
            mcp_tls_connect(be);
            // fall through to handshake attempt.
        }
    }

    assert(be->validating);
    int ret = mcp_tls_handshake(be);
    if (ret == MCP_TLS_NEEDIO) {
        // Need to try again.
        _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_beconn_tls_handler);
        return;
    } else if (ret == 1) {
        // handshake complete.
        if (mcp_tls_send_validate(be) != MCP_TLS_OK) {
            _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
            return;
        }

        // switch to another handler for the final stage.
        _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_bevalidate_tls_handler);
    } else if (ret < 0) {
        // FIXME: FAIL_HANDSHAKE
        _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
        return;
    }
}

// Libevent handler for backends in a connecting state.
static void proxy_beconn_handler(const int fd, const short which, void *arg) {
    assert(arg != NULL);
    struct mcp_backendconn_s *be = arg;
    int flags = EV_TIMEOUT;
    struct timeval tmp_time = be->tunables.read;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: backend timed out while connecting [fd: %d]\n", __func__, mcmc_fd(be->client));
        if (be->connecting) {
            _reset_bad_backend(be, P_BE_FAIL_CONNTIMEOUT);
        } else {
            _reset_bad_backend(be, P_BE_FAIL_READVALIDATE);
        }
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;

        if (be->connecting) {
            if (_proxy_beconn_checkconnect(be) == -1) {
                return;
            }
            if (_beconn_send_validate(be) == -1) {
                _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
                return;
            }
            _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_beconn_handler);
        }

        // TODO: currently never taken, until validation is made optional.
        if (!be->validating) {
            int res = _flush_pending_write(be);
            if (res == -1) {
                _reset_bad_backend(be, P_BE_FAIL_WRITING);
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

            int status = mcmc_parse_buf(be->rbuf, be->rbufused, &r);
            if (status == MCMC_ERR) {
                // Needed more data for a version line, somehow. I feel like
                // this should set off some alarms, but it is possible.
                if (r.code == MCMC_WANT_READ) {
                    _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_beconn_handler);
                    return;
                }

                _reset_bad_backend(be, P_BE_FAIL_READVALIDATE);
                return;
            }

            if (r.code != MCMC_CODE_VERSION) {
                _reset_bad_backend(be, P_BE_FAIL_BADVALIDATE);
                return;
            }

            be->validating = false;
            be->rbufused = 0;
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
            _set_main_event(be, be->event_thread->base, EV_READ, &tmp_time, proxy_beconn_handler);
            return;
        }

        // Passed validation, don't need to re-read, flush any pending writes.
        int res = _flush_pending_write(be);
        if (res == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
            return;
        }
        if (res & EV_WRITE) {
            _start_write_event(be);
        }
        if (be->pending_read) {
            _start_timeout_event(be);
        }
    }

    // switch to the primary persistent read event.
    if (!be->validating) {
        _set_main_event(be, be->event_thread->base, EV_READ|EV_PERSIST, NULL, proxy_backend_handler);

        // we're happily validated and switching to normal processing, so
        // _now_ the backend is no longer "bad".
        // If we reset the failed count earlier we then can fail the
        // validation loop indefinitely without ever being marked bad.
        if (be->bad) {
            // was bad, need to mark as no longer bad in shared space.
            mcp_sharedvm_delta(be->event_thread->ctx, SHAREDVM_BACKEND_IDX,
                    be->be_parent->label, -1);
        }
        be->bad = false;
        be->failed_count = 0;
    }
}

static void proxy_backend_tls_handler(const int fd, const short which, void *arg) {
    struct mcp_backendconn_s *be = arg;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: timeout received, killing backend queue\n", __func__);
        _reset_bad_backend(be, P_BE_FAIL_TIMEOUT);
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;
        int res = _flush_pending_tls_write(be);
        if (res == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
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
        // common code path for io_uring/epoll/tls/etc
        int read = mcp_tls_read(be);
        if (read > 0) {
            int res = proxy_backend_drive_machine(be);
            if (res != 0) {
                _reset_bad_backend(be, res);
                return;
            }
        } else if (read == 0) {
            // not connected or error.
            _reset_bad_backend(be, P_BE_FAIL_DISCONNECTED);
            return;
        } else if (read == MCP_TLS_NEEDIO) {
            // sit on epoll again.
            return;
        } else if (read == MCP_TLS_ERR) {
            _reset_bad_backend(be, P_BE_FAIL_READING);
            return;
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

// The libevent backend callback handler.
// If we end up resetting a backend, it will get put back into a connecting
// state.
static void proxy_backend_handler(const int fd, const short which, void *arg) {
    struct mcp_backendconn_s *be = arg;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: timeout received, killing backend queue\n", __func__);
        _reset_bad_backend(be, P_BE_FAIL_TIMEOUT);
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;
        int res = _flush_pending_write(be);
        if (res == -1) {
            _reset_bad_backend(be, P_BE_FAIL_WRITING);
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

    if (be->pending_read) {
        _start_timeout_event(be);
    }
}

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
    if (t->ctx->use_uring) {
        fprintf(stderr, "Sorry, io_uring not supported right now\n");
        abort();
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



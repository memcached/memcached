/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *  memcached - memory caching daemon
 *
 *       http://www.danga.com/memcached/
 *
 *  Copyright 2003 Danga Interactive, Inc.  All rights reserved.
 *
 *  Use and distribution licensed under the BSD license.  See
 *  the LICENSE file for full text.
 *
 *  Authors:
 *      Anatoly Vorobey <mellon@pobox.com>
 *      Brad Fitzpatrick <brad@danga.com>
 */
#include "memcached.h"
#include "memcached/extension_loggers.h"

#if defined(ENABLE_SASL) || defined(ENABLE_ISASL)
#define SASL_ENABLED
#endif

#ifndef __WIN32__

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* some POSIX systems need the following definition
 * to get mlockall flags out of sys/mman.h.  */
#ifndef _P1003_1B_VISIBLE
#define _P1003_1B_VISIBLE
#endif
/* need this to get IOV_MAX on some platforms. */
#ifndef __need_IOV_MAX
#define __need_IOV_MAX
#endif
#include <pwd.h>
#include <sys/mman.h>
#endif /* !__WIN32__ */

#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <limits.h>
#include <ctype.h>
#include <stdarg.h>

#include <stddef.h>

/* FreeBSD 4.x doesn't have IOV_MAX exposed. */
#ifndef IOV_MAX
#if defined(__FreeBSD__) || defined(__APPLE__)
# define IOV_MAX 1024
#endif
#endif

static inline void item_set_cas(const void *cookie, item *it, uint64_t cas) {
    settings.engine.v1->item_set_cas(settings.engine.v0, cookie, it, cas);
}

/* static inline uint8_t item_get_clsid(const item* it) { */
/*     /\* return settings.engine.v1->item_get_clsid(settings.engine.v0, it); *\/ */
/* } */

/* The item must always be called "it" */
#define SLAB_GUTS(conn, thread_stats, slab_op, thread_op) \
    thread_stats->slab_stats[info.clsid].slab_op++;

#define THREAD_GUTS(conn, thread_stats, slab_op, thread_op) \
    thread_stats->thread_op++;

#define THREAD_GUTS2(conn, thread_stats, slab_op, thread_op) \
    thread_stats->slab_op++; \
    thread_stats->thread_op++;

#define SLAB_THREAD_GUTS(conn, thread_stats, slab_op, thread_op) \
    SLAB_GUTS(conn, thread_stats, slab_op, thread_op) \
    THREAD_GUTS(conn, thread_stats, slab_op, thread_op)

#define STATS_INCR1(GUTS, conn, slab_op, thread_op, key, nkey) { \
    struct independent_stats *independent_stats = get_independent_stats(conn); \
    struct thread_stats *thread_stats = \
        &independent_stats->thread_stats[conn->thread->index]; \
    topkeys_t *topkeys = independent_stats->topkeys; \
    pthread_mutex_lock(&thread_stats->mutex); \
    GUTS(conn, thread_stats, slab_op, thread_op); \
    pthread_mutex_unlock(&thread_stats->mutex); \
    TK(topkeys, slab_op, key, nkey, current_time); \
}

#define STATS_INCR(conn, op, key, nkey) \
    STATS_INCR1(THREAD_GUTS, conn, op, op, key, nkey)

#define SLAB_INCR(conn, op, key, nkey) \
    STATS_INCR1(SLAB_GUTS, conn, op, op, key, nkey)

#define STATS_TWO(conn, slab_op, thread_op, key, nkey) \
    STATS_INCR1(THREAD_GUTS2, conn, slab_op, thread_op, key, nkey)

#define SLAB_TWO(conn, slab_op, thread_op, key, nkey) \
    STATS_INCR1(SLAB_THREAD_GUTS, conn, slab_op, thread_op, key, nkey)

#define STATS_HIT(conn, op, key, nkey) \
    SLAB_TWO(conn, op##_hits, cmd_##op, key, nkey)

#define STATS_MISS(conn, op, key, nkey) \
    STATS_TWO(conn, op##_misses, cmd_##op, key, nkey)

#define STATS_NOKEY(conn, op) { \
    struct thread_stats *thread_stats = \
        get_thread_stats(conn); \
    pthread_mutex_lock(&thread_stats->mutex); \
    thread_stats->op++; \
    pthread_mutex_unlock(&thread_stats->mutex); \
}

#define STATS_NOKEY2(conn, op1, op2) { \
    struct thread_stats *thread_stats = \
        get_thread_stats(conn); \
    pthread_mutex_lock(&thread_stats->mutex); \
    thread_stats->op1++; \
    thread_stats->op2++; \
    pthread_mutex_unlock(&thread_stats->mutex); \
}

#define STATS_ADD(conn, op, amt) { \
    struct thread_stats *thread_stats = \
        get_thread_stats(conn); \
    pthread_mutex_lock(&thread_stats->mutex); \
    thread_stats->op += amt; \
    pthread_mutex_unlock(&thread_stats->mutex); \
}

volatile sig_atomic_t memcached_shutdown;

/*
 * We keep the current time of day in a global variable that's updated by a
 * timer event. This saves us a bunch of time() system calls (we really only
 * need to get the time once a second, whereas there can be tens of thousands
 * of requests a second) and allows us to use server-start-relative timestamps
 * rather than absolute UNIX timestamps, a space savings on systems where
 * sizeof(time_t) > sizeof(unsigned int).
 */
volatile rel_time_t current_time;

/*
 * forward declarations
 */
static int new_socket(struct addrinfo *ai);
static int try_read_command(conn *c);
static inline struct independent_stats *get_independent_stats(conn *c);
static inline struct thread_stats *get_thread_stats(conn *c);
static void register_callback(ENGINE_HANDLE *eh,
                              ENGINE_EVENT_TYPE type,
                              EVENT_CALLBACK cb, const void *cb_data);


enum try_read_result {
    READ_DATA_RECEIVED,
    READ_NO_DATA_RECEIVED,
    READ_ERROR,            /** an error occured (on the socket) (or client closed connection) */
    READ_MEMORY_ERROR      /** failed to allocate more memory */
};

static enum try_read_result try_read_network(conn *c);
static enum try_read_result try_read_udp(conn *c);

/* stats */
static void stats_init(void);
static void server_stats(ADD_STAT add_stats, conn *c, bool aggregate);
static void process_stat_settings(ADD_STAT add_stats, void *c);


/* defaults */
static void settings_init(void);

/* event handling, network IO */
static void event_handler(const int fd, const short which, void *arg);
static bool update_event(conn *c, const int new_flags);
static void complete_nread(conn *c);
static void process_command(conn *c, char *command);
static void write_and_free(conn *c, char *buf, int bytes);
static int ensure_iov_space(conn *c);
static int add_iov(conn *c, const void *buf, int len);
static int add_msghdr(conn *c);


/* time handling */
static void set_current_time(void);  /* update the global variable holding
                              global 32-bit seconds-since-start time
                              (to avoid 64 bit time_t) */

/** exported globals **/
struct stats stats;
struct settings settings;
static time_t process_started;     /* when the process was started */

/** file scope variables **/
static conn *listen_conn = NULL;
static struct event_base *main_base;
static struct independent_stats *default_independent_stats;

static struct engine_event_handler *engine_event_handlers[MAX_ENGINE_EVENT_TYPE + 1];

enum transmit_result {
    TRANSMIT_COMPLETE,   /** All done writing. */
    TRANSMIT_INCOMPLETE, /** More data remaining to write. */
    TRANSMIT_SOFT_ERROR, /** Can't write any more right now. */
    TRANSMIT_HARD_ERROR  /** Can't write (c->state is set to conn_closing) */
};

static enum transmit_result transmit(conn *c);

#define REALTIME_MAXDELTA 60*60*24*30

// Perform all callbacks of a given type for the given connection.
static void perform_callbacks(ENGINE_EVENT_TYPE type,
                              const void *data,
                              const void *c) {
    for (struct engine_event_handler *h = engine_event_handlers[type];
         h; h = h->next) {
        h->cb(c, type, data, h->cb_data);
    }
}

/*
 * given time value that's either unix time or delta from current unix time,
 * return unix time. Use the fact that delta can't exceed one month
 * (and real time value can't be that low).
 */
static rel_time_t realtime(const time_t exptime) {
    /* no. of seconds in 30 days - largest possible delta exptime */

    if (exptime == 0) return 0; /* 0 means never expire */

    if (exptime > REALTIME_MAXDELTA) {
        /* if item expiration is at/before the server started, give it an
           expiration time of 1 second after the server started.
           (because 0 means don't expire).  without this, we'd
           underflow and wrap around to some large value way in the
           future, effectively making items expiring in the past
           really expiring never */
        if (exptime <= process_started)
            return (rel_time_t)1;
        return (rel_time_t)(exptime - process_started);
    } else {
        return (rel_time_t)(exptime + current_time);
    }
}

static void stats_init(void) {
    stats.daemon_conns = 0;
    stats.rejected_conns = 0;
    stats.curr_conns = stats.total_conns = stats.conn_structs = 0;

    /* make the time we started always be 2 seconds before we really
       did, so time(0) - time.started is never zero.  if so, things
       like 'settings.oldest_live' which act as booleans as well as
       values are now false in boolean context... */
    process_started = time(0) - 2;
    stats_prefix_init();
}

static void stats_reset(const void *cookie) {
    struct conn *conn = (struct conn*)cookie;
    STATS_LOCK();
    stats.rejected_conns = 0;
    stats.total_conns = 0;
    stats_prefix_clear();
    STATS_UNLOCK();
    threadlocal_stats_reset(get_independent_stats(conn)->thread_stats);
    settings.engine.v1->reset_stats(settings.engine.v0, cookie);
}

static void settings_init(void) {
    settings.use_cas = true;
    settings.access = 0700;
    settings.port = 11211;
    settings.udpport = 11211;
    /* By default this string should be NULL for getaddrinfo() */
    settings.inter = NULL;
    settings.maxbytes = 64 * 1024 * 1024; /* default is 64MB */
    settings.maxconns = 1024;         /* to limit connections-related memory to about 5MB */
    settings.verbose = 0;
    settings.oldest_live = 0;
    settings.evict_to_free = 1;       /* push old items out of cache when memory runs out */
    settings.socketpath = NULL;       /* by default, not using a unix socket */
    settings.factor = 1.25;
    settings.chunk_size = 48;         /* space for a modest key and value */
    settings.num_threads = 4;         /* N workers */
    settings.prefix_delimiter = ':';
    settings.detail_enabled = 0;
    settings.allow_detailed = true;
    settings.reqs_per_event = DEFAULT_REQS_PER_EVENT;
    settings.backlog = 1024;
    settings.binding_protocol = negotiating_prot;
    settings.item_size_max = 1024 * 1024; /* The famous 1MB upper limit. */
    settings.topkeys = 0;
    settings.require_sasl = false;
    settings.extensions.logger = get_stderr_logger();
}

/*
 * Adds a message header to a connection.
 *
 * Returns 0 on success, -1 on out-of-memory.
 */
static int add_msghdr(conn *c)
{
    struct msghdr *msg;

    assert(c != NULL);

    if (c->msgsize == c->msgused) {
        msg = realloc(c->msglist, c->msgsize * 2 * sizeof(struct msghdr));
        if (! msg)
            return -1;
        c->msglist = msg;
        c->msgsize *= 2;
    }

    msg = c->msglist + c->msgused;

    /* this wipes msg_iovlen, msg_control, msg_controllen, and
       msg_flags, the last 3 of which aren't defined on solaris: */
    memset(msg, 0, sizeof(struct msghdr));

    msg->msg_iov = &c->iov[c->iovused];

    if (c->request_addr_size > 0) {
        msg->msg_name = &c->request_addr;
        msg->msg_namelen = c->request_addr_size;
    }

    c->msgbytes = 0;
    c->msgused++;

    if (IS_UDP(c->transport)) {
        /* Leave room for the UDP header, which we'll fill in later. */
        return add_iov(c, NULL, UDP_HEADER_SIZE);
    }

    return 0;
}

static const char *prot_text(enum protocol prot) {
    char *rv = "unknown";
    switch(prot) {
        case ascii_prot:
            rv = "ascii";
            break;
        case binary_prot:
            rv = "binary";
            break;
        case negotiating_prot:
            rv = "auto-negotiate";
            break;
    }
    return rv;
}

void safe_close(int sfd) {
    if (sfd != -1) {
        int rval;
        while ((rval = close(sfd)) == -1 &&
               (errno == EINTR || errno == EAGAIN)) {
            /* go ahead and retry */
        }

        if (rval == -1) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Failed to close socket %d (%s)!!\n", (int)sfd,
                                            strerror(errno));
        } else {
            STATS_LOCK();
            stats.curr_conns--;
            STATS_UNLOCK();
        }
    }
}

/*
 * Free list management for connections.
 */
cache_t *conn_cache;      /* suffix cache */

/**
 * Reset all of the dynamic buffers used by a connection back to their
 * default sizes. The strategy for resizing the buffers is to allocate a
 * new one of the correct size and free the old one if the allocation succeeds
 * instead of using realloc to change the buffer size (because realloc may
 * not shrink the buffers, and will also copy the memory). If the allocation
 * fails the buffer will be unchanged.
 *
 * @param c the connection to resize the buffers for
 * @return true if all allocations succeeded, false if one or more of the
 *         allocations failed.
 */
static bool conn_reset_buffersize(conn *c) {
    bool ret = true;

    if (c->rsize != DATA_BUFFER_SIZE) {
        void *ptr = malloc(DATA_BUFFER_SIZE);
        if (ptr != NULL) {
            free(c->rbuf);
            c->rbuf = ptr;
            c->rsize = DATA_BUFFER_SIZE;
        } else {
            ret = false;
        }
    }

    if (c->wsize != DATA_BUFFER_SIZE) {
        void *ptr = malloc(DATA_BUFFER_SIZE);
        if (ptr != NULL) {
            free(c->wbuf);
            c->wbuf = ptr;
            c->wsize = DATA_BUFFER_SIZE;
        } else {
            ret = false;
        }
    }

    if (c->isize != ITEM_LIST_INITIAL) {
        void *ptr = malloc(sizeof(item *) * ITEM_LIST_INITIAL);
        if (ptr != NULL) {
            free(c->ilist);
            c->ilist = ptr;
            c->isize = ITEM_LIST_INITIAL;
        } else {
            ret = false;
        }
    }

    if (c->suffixsize != SUFFIX_LIST_INITIAL) {
        void *ptr = malloc(sizeof(char *) * SUFFIX_LIST_INITIAL);
        if (ptr != NULL) {
            free(c->suffixlist);
            c->suffixlist = ptr;
            c->suffixsize = SUFFIX_LIST_INITIAL;
        } else {
            ret = false;
        }
    }

    if (c->iovsize != IOV_LIST_INITIAL) {
        void *ptr = malloc(sizeof(struct iovec) * IOV_LIST_INITIAL);
        if (ptr != NULL) {
            free(c->iov);
            c->iov = ptr;
            c->iovsize = IOV_LIST_INITIAL;
        } else {
            ret = false;
        }
    }

    if (c->msgsize != MSG_LIST_INITIAL) {
        void *ptr = malloc(sizeof(struct msghdr) * MSG_LIST_INITIAL);
        if (ptr != NULL) {
            free(c->msglist);
            c->msglist = ptr;
            c->msgsize = MSG_LIST_INITIAL;
        } else {
            ret = false;
        }
    }

    return ret;
}

/**
 * Constructor for all memory allocations of connection objects. Initialize
 * all members and allocate the transfer buffers.
 *
 * @param buffer The memory allocated by the object cache
 * @param unused1 not used
 * @param unused2 not used
 * @return 0 on success, 1 if we failed to allocate memory
 */
static int conn_constructor(void *buffer, void *unused1, int unused2) {
    (void)unused1; (void)unused2;

    conn *c = buffer;
    memset(c, 0, sizeof(*c));
    MEMCACHED_CONN_CREATE(c);

    if (!conn_reset_buffersize(c)) {
        free(c->rbuf);
        free(c->wbuf);
        free(c->ilist);
        free(c->suffixlist);
        free(c->iov);
        free(c->msglist);
        settings.extensions.logger->log(EXTENSION_LOG_WARNING,
                                        NULL,
                                        "Failed to allocate buffers for connection\n");
        return 1;
    }

    STATS_LOCK();
    stats.conn_structs++;
    STATS_UNLOCK();

    return 0;
}

/**
 * Destructor for all connection objects. Release all allocated resources.
 *
 * @param buffer The memory allocated by the objec cache
 * @param unused not used
 */
static void conn_destructor(void *buffer, void *unused) {
    (void)unused;
    conn *c = buffer;
    free(c->rbuf);
    free(c->wbuf);
    free(c->ilist);
    free(c->suffixlist);
    free(c->iov);
    free(c->msglist);

    STATS_LOCK();
    stats.conn_structs--;
    STATS_UNLOCK();
}

conn *conn_new(const int sfd, STATE_FUNC init_state,
                const int event_flags,
                const int read_buffer_size, enum network_transport transport,
                struct event_base *base, struct timeval *timeout) {
    conn *c = cache_alloc(conn_cache);

    if (c == NULL) {
        return NULL;
    }

    assert(c->thread == NULL);

    if (c->rsize < read_buffer_size) {
        void *mem = malloc(read_buffer_size);
        if (mem) {
            c->rsize = read_buffer_size;
            free(c->rbuf);
            c->rbuf = mem;
        } else {
            assert(c->thread == NULL);
            cache_free(conn_cache, c);
            return NULL;
        }
    }

    c->transport = transport;
    c->protocol = settings.binding_protocol;

    /* unix socket mode doesn't need this, so zeroed out.  but why
     * is this done for every command?  presumably for UDP
     * mode.  */
    if (!settings.socketpath) {
        c->request_addr_size = sizeof(c->request_addr);
    } else {
        c->request_addr_size = 0;
    }

    if (settings.verbose > 1) {
        if (init_state == conn_listening) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "<%d server listening (%s)\n", sfd,
                                            prot_text(c->protocol));
        } else if (IS_UDP(transport)) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "<%d server listening (udp)\n", sfd);
        } else if (c->protocol == negotiating_prot) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "<%d new auto-negotiating client connection\n",
                                            sfd);
        } else if (c->protocol == ascii_prot) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "<%d new ascii client connection.\n", sfd);
        } else if (c->protocol == binary_prot) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "<%d new binary client connection.\n", sfd);
        } else {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "<%d new unknown (%d) client connection\n",
                                            sfd, c->protocol);
            assert(false);
        }
    }

    c->sfd = sfd;
    c->state = init_state;
    c->rlbytes = 0;
    c->cmd = -1;
    c->ascii_cmd = NULL;
    c->rbytes = c->wbytes = 0;
    c->wcurr = c->wbuf;
    c->rcurr = c->rbuf;
    c->ritem = 0;
    c->icurr = c->ilist;
    c->suffixcurr = c->suffixlist;
    c->ileft = 0;
    c->suffixleft = 0;
    c->iovused = 0;
    c->msgcurr = 0;
    c->msgused = 0;
    c->next = NULL;

    c->write_and_go = init_state;
    c->write_and_free = 0;
    c->item = 0;

    c->noreply = false;

    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = event_flags;

    if (event_add(&c->event, timeout) == -1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING,
                                        NULL,
                                        "Failed to add connection to libevent: %s", strerror(errno));
        assert(c->thread == NULL);
        cache_free(conn_cache, c);
        return NULL;
    }

    STATS_LOCK();
    stats.curr_conns++;
    stats.total_conns++;
    STATS_UNLOCK();

    c->aiostat = ENGINE_SUCCESS;
    c->ewouldblock = false;

    MEMCACHED_CONN_ALLOCATE(c->sfd);

    perform_callbacks(ON_CONNECT, NULL, c);

    return c;
}

static void conn_cleanup(conn *c) {
    assert(c != NULL);

    if (c->item) {
        settings.engine.v1->release(settings.engine.v0, c, c->item);
        c->item = 0;
    }

    if (c->ileft != 0) {
        for (; c->ileft > 0; c->ileft--,c->icurr++) {
            settings.engine.v1->release(settings.engine.v0, c, *(c->icurr));
        }
    }

    if (c->suffixleft != 0) {
        for (; c->suffixleft > 0; c->suffixleft--, c->suffixcurr++) {
            cache_free(c->thread->suffix_cache, *(c->suffixcurr));
        }
    }

    if (c->write_and_free) {
        free(c->write_and_free);
        c->write_and_free = 0;
    }

    if (c->sasl_conn) {
        sasl_dispose(&c->sasl_conn);
        c->sasl_conn = NULL;
    }

    c->engine_storage = NULL;
    c->tap_iterator = NULL;
    c->thread = NULL;
    assert(c->next == NULL);
    c->ascii_cmd = NULL;
    c->pending_close.active = false;
    c->sfd = -1;
}

void conn_close(conn *c) {
    assert(c != NULL);

    /* delete the event, the socket and the conn */
    if (c->sfd != -1) {
        MEMCACHED_CONN_RELEASE(c->sfd);
        event_del(&c->event);

        if (settings.verbose > 1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "<%d connection closed.\n", c->sfd);
        }
        safe_close(c->sfd);
        c->sfd = -1;
    }

    if (c->ascii_cmd != NULL) {
        c->ascii_cmd->abort(c->ascii_cmd, c);
    }

    assert(c->thread);
    if (!c->pending_close.active) {
        perform_callbacks(ON_DISCONNECT, NULL, c);
    } else {
        assert(current_time > c->pending_close.timeout);
    }

    LOCK_THREAD(c->thread);
    /* remove from pending-io list */
    if (settings.verbose > 1 && list_contains(c->thread->pending_io, c)) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        "Current connection was in the pending-io list.. Nuking it\n");
    }
    c->thread->pending_io = list_remove(c->thread->pending_io, c);
    c->thread->pending_close = list_remove(c->thread->pending_close, c);
    UNLOCK_THREAD(c->thread);

    conn_cleanup(c);

    /*
     * The contract with the object cache is that we should return the
     * object in a constructed state. Reset the buffers to the default
     * size
     */
    conn_reset_buffersize(c);
    assert(c->thread == NULL);
    cache_free(conn_cache, c);
}

/*
 * Shrinks a connection's buffers if they're too big.  This prevents
 * periodic large "get" requests from permanently chewing lots of server
 * memory.
 *
 * This should only be called in between requests since it can wipe output
 * buffers!
 */
static void conn_shrink(conn *c) {
    assert(c != NULL);

    if (IS_UDP(c->transport))
        return;

    if (c->rsize > READ_BUFFER_HIGHWAT && c->rbytes < DATA_BUFFER_SIZE) {
        char *newbuf;

        if (c->rcurr != c->rbuf)
            memmove(c->rbuf, c->rcurr, (size_t)c->rbytes);

        newbuf = (char *)realloc((void *)c->rbuf, DATA_BUFFER_SIZE);

        if (newbuf) {
            c->rbuf = newbuf;
            c->rsize = DATA_BUFFER_SIZE;
        }
        /* TODO check other branch... */
        c->rcurr = c->rbuf;
    }

    if (c->isize > ITEM_LIST_HIGHWAT) {
        item **newbuf = (item**) realloc((void *)c->ilist, ITEM_LIST_INITIAL * sizeof(c->ilist[0]));
        if (newbuf) {
            c->ilist = newbuf;
            c->isize = ITEM_LIST_INITIAL;
        }
    /* TODO check error condition? */
    }

    if (c->msgsize > MSG_LIST_HIGHWAT) {
        struct msghdr *newbuf = (struct msghdr *) realloc((void *)c->msglist, MSG_LIST_INITIAL * sizeof(c->msglist[0]));
        if (newbuf) {
            c->msglist = newbuf;
            c->msgsize = MSG_LIST_INITIAL;
        }
    /* TODO check error condition? */
    }

    if (c->iovsize > IOV_LIST_HIGHWAT) {
        struct iovec *newbuf = (struct iovec *) realloc((void *)c->iov, IOV_LIST_INITIAL * sizeof(c->iov[0]));
        if (newbuf) {
            c->iov = newbuf;
            c->iovsize = IOV_LIST_INITIAL;
        }
    /* TODO check return value */
    }
}

/**
 * Convert a state name to a human readable form.
 */
const char *state_text(STATE_FUNC state) {
    if (state == conn_listening) {
        return "conn_listening";
    } else if (state == conn_new_cmd) {
        return "conn_new_cmd";
    } else if (state == conn_waiting) {
        return "conn_waiting";
    } else if (state == conn_read) {
        return "conn_read";
    } else if (state == conn_parse_cmd) {
        return "conn_parse_cmd";
    } else if (state == conn_write) {
        return "conn_write";
    } else if (state == conn_nread) {
        return "conn_nread";
    } else if (state == conn_swallow) {
        return "conn_swallow";
    } else if (state == conn_closing) {
        return "conn_closing";
    } else if (state == conn_mwrite) {
        return "conn_mwrite";
    } else if (state == conn_ship_log) {
        return "conn_ship_log";
    } else if (state == conn_add_tap_client) {
        return "conn_add_tap_client";
    } else if (state == conn_setup_tap_stream) {
        return "conn_setup_tap_stream";
    } else if (state == conn_pending_close) {
        return "conn_pending_close";
    } else if (state == conn_immediate_close) {
        return "conn_immediate_close";
    } else {
        return "Unknown";
    }
}

/*
 * Sets a connection's current state in the state machine. Any special
 * processing that needs to happen on certain state transitions can
 * happen here.
 */
void conn_set_state(conn *c, STATE_FUNC state) {
    assert(c != NULL);

    if (state != c->state) {
        /*
         * The connections in the "tap thread" behaves differently than
         * normal connections because they operate in a full duplex mode.
         * New messages may appear from both sides, so we can't block on
         * read from the nework / engine
         */
        if (c->thread == &tap_thread) {
            if (state == conn_waiting) {
                c->which = EV_WRITE;
                state = conn_ship_log;
            }
        }

        if (settings.verbose > 2 || c->state == conn_closing
            || c->state == conn_add_tap_client) {
            settings.extensions.logger->log(EXTENSION_LOG_DETAIL, c,
                                            "%d: going from %s to %s\n",
                                            c->sfd, state_text(c->state),
                                            state_text(state));
        }

        c->state = state;

        if (state == conn_write || state == conn_mwrite) {
            MEMCACHED_PROCESS_COMMAND_END(c->sfd, c->wbuf, c->wbytes);
        }
    }
}

/*
 * Ensures that there is room for another struct iovec in a connection's
 * iov list.
 *
 * Returns 0 on success, -1 on out-of-memory.
 */
static int ensure_iov_space(conn *c) {
    assert(c != NULL);

    if (c->iovused >= c->iovsize) {
        int i, iovnum;
        struct iovec *new_iov = (struct iovec *)realloc(c->iov,
                                (c->iovsize * 2) * sizeof(struct iovec));
        if (! new_iov)
            return -1;
        c->iov = new_iov;
        c->iovsize *= 2;

        /* Point all the msghdr structures at the new list. */
        for (i = 0, iovnum = 0; i < c->msgused; i++) {
            c->msglist[i].msg_iov = &c->iov[iovnum];
            iovnum += c->msglist[i].msg_iovlen;
        }
    }

    return 0;
}


/*
 * Adds data to the list of pending data that will be written out to a
 * connection.
 *
 * Returns 0 on success, -1 on out-of-memory.
 */

static int add_iov(conn *c, const void *buf, int len) {
    struct msghdr *m;
    int leftover;
    bool limit_to_mtu;

    assert(c != NULL);

    do {
        m = &c->msglist[c->msgused - 1];

        /*
         * Limit UDP packets, and the first payloads of TCP replies, to
         * UDP_MAX_PAYLOAD_SIZE bytes.
         */
        limit_to_mtu = IS_UDP(c->transport) || (1 == c->msgused);

        /* We may need to start a new msghdr if this one is full. */
        if (m->msg_iovlen == IOV_MAX ||
            (limit_to_mtu && c->msgbytes >= UDP_MAX_PAYLOAD_SIZE)) {
            add_msghdr(c);
            m = &c->msglist[c->msgused - 1];
        }

        if (ensure_iov_space(c) != 0)
            return -1;

        /* If the fragment is too big to fit in the datagram, split it up */
        if (limit_to_mtu && len + c->msgbytes > UDP_MAX_PAYLOAD_SIZE) {
            leftover = len + c->msgbytes - UDP_MAX_PAYLOAD_SIZE;
            len -= leftover;
        } else {
            leftover = 0;
        }

        m = &c->msglist[c->msgused - 1];
        m->msg_iov[m->msg_iovlen].iov_base = (void *)buf;
        m->msg_iov[m->msg_iovlen].iov_len = len;

        c->msgbytes += len;
        c->iovused++;
        m->msg_iovlen++;

        buf = ((char *)buf) + len;
        len = leftover;
    } while (leftover > 0);

    return 0;
}


/*
 * Constructs a set of UDP headers and attaches them to the outgoing messages.
 */
static int build_udp_headers(conn *c) {
    int i;
    unsigned char *hdr;

    assert(c != NULL);

    if (c->msgused > c->hdrsize) {
        void *new_hdrbuf;
        if (c->hdrbuf)
            new_hdrbuf = realloc(c->hdrbuf, c->msgused * 2 * UDP_HEADER_SIZE);
        else
            new_hdrbuf = malloc(c->msgused * 2 * UDP_HEADER_SIZE);
        if (! new_hdrbuf)
            return -1;
        c->hdrbuf = (unsigned char *)new_hdrbuf;
        c->hdrsize = c->msgused * 2;
    }

    hdr = c->hdrbuf;
    for (i = 0; i < c->msgused; i++) {
        c->msglist[i].msg_iov[0].iov_base = (void*)hdr;
        c->msglist[i].msg_iov[0].iov_len = UDP_HEADER_SIZE;
        *hdr++ = c->request_id / 256;
        *hdr++ = c->request_id % 256;
        *hdr++ = i / 256;
        *hdr++ = i % 256;
        *hdr++ = c->msgused / 256;
        *hdr++ = c->msgused % 256;
        *hdr++ = 0;
        *hdr++ = 0;
        assert((void *) hdr == (caddr_t)c->msglist[i].msg_iov[0].iov_base + UDP_HEADER_SIZE);
    }

    return 0;
}


static void out_string(conn *c, const char *str) {
    size_t len;

    assert(c != NULL);

    if (c->noreply) {
        if (settings.verbose > 1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            ">%d NOREPLY %s\n", c->sfd, str);
        }
        c->noreply = false;
        conn_set_state(c, conn_new_cmd);
        return;
    }

    if (settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        ">%d %s\n", c->sfd, str);
    }

    len = strlen(str);
    if ((len + 2) > c->wsize) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    memcpy(c->wbuf, str, len);
    memcpy(c->wbuf + len, "\r\n", 2);
    c->wbytes = len + 2;
    c->wcurr = c->wbuf;

    conn_set_state(c, conn_write);
    c->write_and_go = conn_new_cmd;
    return;
}

/*
 * we get here after reading the value in set/add/replace commands. The command
 * has been stored in c->cmd, and the item is ready in c->item.
 */
static void complete_update_ascii(conn *c) {
    assert(c != NULL);

    item *it = c->item;
    item_info info = { .nvalue = 1 };
    if (!settings.engine.v1->get_item_info(settings.engine.v0, c, it, &info)) {
        settings.engine.v1->release(settings.engine.v0, c, it);
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                        "%d: Failed to get item info\n",
                                        c->sfd);
        out_string(c, "SERVER_ERROR failed to get item details");
        return;
    }

    if (memcmp((char*)info.value[0].iov_base + info.nbytes - 2, "\r\n", 2) != 0) {
        out_string(c, "CLIENT_ERROR bad data chunk");
    } else {
        ENGINE_ERROR_CODE ret = settings.engine.v1->store(settings.engine.v0, c,
                                                          it, &c->cas,
                                                          c->store_op, 0);
#ifdef ENABLE_DTRACE
        switch (c->store_op) {
        case OPERATION_ADD:
            MEMCACHED_COMMAND_ADD(c->sfd, info.key, info.nkey,
                                  (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
            break;
        case OPERATION_REPLACE:
            MEMCACHED_COMMAND_REPLACE(c->sfd, info.key, info.nkey,
                                      (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
            break;
        case OPERATION_APPEND:
            MEMCACHED_COMMAND_APPEND(c->sfd, info.key, info.nkey,
                                     (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
            break;
        case OPERATION_PREPEND:
            MEMCACHED_COMMAND_PREPEND(c->sfd, info.key, info.nkey,
                                      (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
            break;
        case OPERATION_SET:
            MEMCACHED_COMMAND_SET(c->sfd, info.key, info.nkey,
                                  (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
            break;
        case OPERATION_CAS:
            MEMCACHED_COMMAND_CAS(c->sfd, info.key, info.nkey, info.nbytes, c->cas);
            break;
        }
#endif

        switch (ret) {
        case ENGINE_SUCCESS:
            out_string(c, "STORED");
            break;
        case ENGINE_KEY_EEXISTS:
            out_string(c, "EXISTS");
            break;
        case ENGINE_KEY_ENOENT:
            out_string(c, "NOT_FOUND");
            break;
        case ENGINE_NOT_STORED:
            out_string(c, "NOT_STORED");
            break;
        case ENGINE_DISCONNECT:
            c->state = conn_closing;
            break;
        case ENGINE_ENOTSUP:
            out_string(c, "SERVER_ERROR not supported.");
            break;
        default:
            out_string(c, "SERVER_ERROR unhandled storage type.");
        }
    }

    SLAB_INCR(c, cmd_set, info.key, info.nkey);
    /* release the c->item reference */
    settings.engine.v1->release(settings.engine.v0, c, c->item);
    c->item = 0;
}

/**
 * get a pointer to the start of the request struct for the current command
 */
static void* binary_get_request(conn *c) {
    char *ret = c->rcurr;
    ret -= (sizeof(c->binary_header) + c->binary_header.request.keylen +
            c->binary_header.request.extlen);

    assert(ret >= c->rbuf);
    return ret;
}

/**
 * get a pointer to the key in this request
 */
static char* binary_get_key(conn *c) {
    return c->rcurr - (c->binary_header.request.keylen);
}

/**
 * Insert a key into a buffer, but replace all non-printable characters
 * with a '.'.
 *
 * @param dest where to store the output
 * @param destsz size of destination buffer
 * @param prefix string to insert before the data
 * @param client the client we are serving
 * @param from_client set to true if this data is from the client
 * @param key the key to add to the buffer
 * @param nkey the number of bytes in the key
 * @return number of bytes in dest if success, -1 otherwise
 */
static ssize_t key_to_printable_buffer(char *dest, size_t destsz,
                                       int client, bool from_client,
                                       const char *prefix,
                                       const char *key,
                                       size_t nkey)
{
    ssize_t nw = snprintf(dest, destsz, "%c%d %s ", from_client ? '>' : '<',
                          client, prefix);
    if (nw == -1) {
        return -1;
    }

    char *ptr = dest + nw;
    destsz -= nw;
    if (nkey > destsz) {
        nkey = destsz;
    }

    for (ssize_t ii = 0; ii < nkey; ++ii, ++key, ++ptr) {
        if (isgraph(*key)) {
            *ptr = *key;
        } else {
            *ptr = '.';
        }
    }

    *ptr = '\0';
    return ptr - dest;
}

/**
 * Convert a byte array to a text string
 *
 * @param dest where to store the output
 * @param destsz size of destination buffer
 * @param prefix string to insert before the data
 * @param client the client we are serving
 * @param from_client set to true if this data is from the client
 * @param data the data to add to the buffer
 * @param size the number of bytes in data to print
 * @return number of bytes in dest if success, -1 otherwise
 */
static ssize_t bytes_to_output_string(char *dest, size_t destsz,
                                      int client, bool from_client,
                                      const char *prefix,
                                      const char *data,
                                      size_t size)
{
    ssize_t nw = snprintf(dest, destsz, "%c%d %s", from_client ? '>' : '<',
                          client, prefix);
    if (nw == -1) {
        return -1;
    }
    ssize_t offset = nw;

    for (ssize_t ii = 0; ii < size; ++ii) {
        if (ii % 4 == 0) {
            if ((nw = snprintf(dest + offset, destsz - offset, "\n%c%d  ",
                               from_client ? '>' : '<', client)) == -1) {
                return  -1;
            }
            offset += nw;
        }
        if ((nw = snprintf(dest + offset, destsz - offset,
                           " 0x%02x", (unsigned char)data[ii])) == -1) {
            return -1;
        }
        offset += nw;
    }

    if ((nw = snprintf(dest + offset, destsz - offset, "\n")) == -1) {
        return -1;
    }

    return offset + nw;
}

static void add_bin_header(conn *c, uint16_t err, uint8_t hdr_len, uint16_t key_len, uint32_t body_len) {
    protocol_binary_response_header* header;

    assert(c);

    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        /* XXX:  out_string is inappropriate here */
        out_string(c, "SERVER_ERROR out of memory");
        return;
    }

    header = (protocol_binary_response_header *)c->wbuf;

    header->response.magic = (uint8_t)PROTOCOL_BINARY_RES;
    header->response.opcode = c->binary_header.request.opcode;
    header->response.keylen = (uint16_t)htons(key_len);

    header->response.extlen = (uint8_t)hdr_len;
    header->response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES;
    header->response.status = (uint16_t)htons(err);

    header->response.bodylen = htonl(body_len);
    header->response.opaque = c->opaque;
    header->response.cas = htonll(c->cas);

    if (settings.verbose > 1) {
        char buffer[1024];
        if (bytes_to_output_string(buffer, sizeof(buffer), c->sfd, false,
                                   "Writing bin response:",
                                   (const char*)header->bytes,
                                   sizeof(header->bytes)) != -1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                            "%s", buffer);
        }
    }

    add_iov(c, c->wbuf, sizeof(header->response));
}

/**
 * Convert an error code generated from the storage engine to the corresponding
 * error code used by the protocol layer.
 * @param e the error code as used in the engine
 * @return the error code as used by the protocol layer
 */
static protocol_binary_response_status engine_error_2_protocol_error(ENGINE_ERROR_CODE e) {
    protocol_binary_response_status ret;

    switch (e) {
    case ENGINE_SUCCESS:
        return PROTOCOL_BINARY_RESPONSE_SUCCESS;
    case ENGINE_KEY_ENOENT:
        return PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
    case ENGINE_KEY_EEXISTS:
        return PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
    case ENGINE_ENOMEM:
        return PROTOCOL_BINARY_RESPONSE_ENOMEM;
    case ENGINE_NOT_STORED:
        return PROTOCOL_BINARY_RESPONSE_NOT_STORED;
    case ENGINE_EINVAL:
        return PROTOCOL_BINARY_RESPONSE_EINVAL;
    case ENGINE_ENOTSUP:
        return PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED;
    case ENGINE_E2BIG:
        return PROTOCOL_BINARY_RESPONSE_E2BIG;
    case ENGINE_NOT_MY_VBUCKET:
        return PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET;
    default:
        ret = PROTOCOL_BINARY_RESPONSE_EINTERNAL;
    }

    return ret;
}

static void write_bin_packet(conn *c, protocol_binary_response_status err, int swallow) {
    ssize_t len;
    char buffer[1024] = { [sizeof(buffer) - 1] = '\0' };

    switch (err) {
    case PROTOCOL_BINARY_RESPONSE_SUCCESS:
        len = 0;
        break;
    case PROTOCOL_BINARY_RESPONSE_ENOMEM:
        len = snprintf(buffer, sizeof(buffer), "Out of memory");
        break;
    case PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND:
        len = snprintf(buffer, sizeof(buffer), "Unknown command");
        break;
    case PROTOCOL_BINARY_RESPONSE_KEY_ENOENT:
        len = snprintf(buffer, sizeof(buffer), "Not found");
        break;
    case PROTOCOL_BINARY_RESPONSE_EINVAL:
        len = snprintf(buffer, sizeof(buffer), "Invalid arguments");
        break;
    case PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS:
        len = snprintf(buffer, sizeof(buffer), "Data exists for key");
        break;
    case PROTOCOL_BINARY_RESPONSE_E2BIG:
        len = snprintf(buffer, sizeof(buffer), "Too large");
        break;
    case PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL:
        len = snprintf(buffer, sizeof(buffer),
                       "Non-numeric server-side value for incr or decr");
        break;
    case PROTOCOL_BINARY_RESPONSE_NOT_STORED:
        len = snprintf(buffer, sizeof(buffer), "Not stored");
        break;
    case PROTOCOL_BINARY_RESPONSE_AUTH_ERROR:
        len = snprintf(buffer, sizeof(buffer), "Auth failure");
        break;
    case PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED:
        len = snprintf(buffer, sizeof(buffer), "Not supported");
        break;
    case PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET:
        len = snprintf(buffer, sizeof(buffer),
                       "I'm not responsible for this vbucket");
        break;

    default:
        len = snprintf(buffer, sizeof(buffer), "UNHANDLED ERROR (%d)", err);
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                        ">%d UNHANDLED ERROR: %d\n", c->sfd, err);
    }

    /* Allow the engine to pass extra error information */
    if (settings.engine.v1->errinfo != NULL) {
        size_t elen = settings.engine.v1->errinfo(settings.engine.v0, c, buffer + len + 2,
                                                  sizeof(buffer) - len - 3);

        if (elen > 0) {
            memcpy(buffer + len, ": ", 2);
            len += elen + 2;
        }
    }

    if (err != PROTOCOL_BINARY_RESPONSE_SUCCESS && settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        ">%d Writing an error: %s\n", c->sfd,
                                        buffer);
    }

    add_bin_header(c, err, 0, 0, len);
    if (len > 0) {
        add_iov(c, buffer, len);
    }
    conn_set_state(c, conn_mwrite);
    if (swallow > 0) {
        c->sbytes = swallow;
        c->write_and_go = conn_swallow;
    } else {
        c->write_and_go = conn_new_cmd;
    }
}

/* Form and send a response to a command over the binary protocol */
static void write_bin_response(conn *c, void *d, int hlen, int keylen, int dlen) {
    if (!c->noreply || c->cmd == PROTOCOL_BINARY_CMD_GET ||
        c->cmd == PROTOCOL_BINARY_CMD_GETK) {
        add_bin_header(c, 0, hlen, keylen, dlen);
        if(dlen > 0) {
            add_iov(c, d, dlen);
        }
        conn_set_state(c, conn_mwrite);
        c->write_and_go = conn_new_cmd;
    } else {
        conn_set_state(c, conn_new_cmd);
    }
}


static void complete_incr_bin(conn *c) {
    protocol_binary_response_incr* rsp = (protocol_binary_response_incr*)c->wbuf;
    protocol_binary_request_incr* req = binary_get_request(c);

    assert(c != NULL);
    assert(c->wsize >= sizeof(*rsp));

    /* fix byteorder in the request */
    req->message.body.delta = ntohll(req->message.body.delta);
    req->message.body.initial = ntohll(req->message.body.initial);
    req->message.body.expiration = ntohl(req->message.body.expiration);
    char *key = binary_get_key(c);
    size_t nkey = c->binary_header.request.keylen;
    bool incr = (c->cmd == PROTOCOL_BINARY_CMD_INCREMENT ||
                 c->cmd == PROTOCOL_BINARY_CMD_INCREMENTQ);

    if (settings.verbose > 1) {
        char buffer[1024];
        ssize_t nw;
        nw = key_to_printable_buffer(buffer, sizeof(buffer), c->sfd, true,
                                     incr ? "INCR" : "DECR", key, nkey);
        if (nw != -1) {
            if (snprintf(buffer + nw, sizeof(buffer) - nw,
                         " %" PRIu64 ", %" PRIu64 ", %" PRIu64 "\n",
                         (uint64_t)req->message.body.delta,
                         (uint64_t)req->message.body.initial,
                         (uint64_t)req->message.body.expiration) != -1) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c, "%s",
                                                buffer);
            }
        }
    }

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    if (ret == ENGINE_SUCCESS) {
        ret = settings.engine.v1->arithmetic(settings.engine.v0,
                                             c, key, nkey, incr,
                                             req->message.body.expiration != 0xffffffff,
                                             req->message.body.delta,
                                             req->message.body.initial,
                                             req->message.body.expiration,
                                             &c->cas,
                                             &rsp->message.body.value,
                                             c->binary_header.request.vbucket);
    }

    switch (ret) {
    case ENGINE_SUCCESS:
        rsp->message.body.value = htonll(rsp->message.body.value);
        write_bin_response(c, &rsp->message.body, 0, 0,
                           sizeof (rsp->message.body.value));
        if (incr) {
            STATS_INCR(c, incr_hits, key, nkey);
        } else {
            STATS_INCR(c, decr_hits, key, nkey);
        }
        break;
    case ENGINE_KEY_EEXISTS:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, 0);
        break;
    case ENGINE_KEY_ENOENT:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
        if (c->cmd == PROTOCOL_BINARY_CMD_INCREMENT) {
            STATS_INCR(c, incr_misses, key, nkey);
        } else {
            STATS_INCR(c, decr_misses, key, nkey);
        }
        break;
    case ENGINE_ENOMEM:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
        break;
    case ENGINE_EINVAL:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_DELTA_BADVAL, 0);
        break;
    case ENGINE_NOT_STORED:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_STORED, 0);
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    case ENGINE_ENOTSUP:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, 0);
        break;
    case ENGINE_NOT_MY_VBUCKET:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET, 0);
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    default:
        abort();
    }
}

static void complete_update_bin(conn *c) {
    protocol_binary_response_status eno = PROTOCOL_BINARY_RESPONSE_EINVAL;
    assert(c != NULL);

    item *it = c->item;
    item_info info = { .nvalue = 1 };
    if (!settings.engine.v1->get_item_info(settings.engine.v0, c, it, &info)) {
        settings.engine.v1->release(settings.engine.v0, c, it);
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                        "%d: Failed to get item info\n",
                                        c->sfd);
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINTERNAL, 0);
        return;
    }
    /* We don't actually receive the trailing two characters in the bin
     * protocol, so we're going to just set them here */
    memcpy((char*)info.value[0].iov_base + info.value[0].iov_len - 2, "\r\n", 2);
    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    if (ret == ENGINE_SUCCESS) {
        ret = settings.engine.v1->store(settings.engine.v0, c,
                                        it, &c->cas, c->store_op,
                                        c->binary_header.request.vbucket);
    }

#ifdef ENABLE_DTRACE
    switch (c->cmd) {
    case OPERATION_ADD:
        MEMCACHED_COMMAND_ADD(c->sfd, info.key, info.nkey,
                              (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
        break;
    case OPERATION_REPLACE:
        MEMCACHED_COMMAND_REPLACE(c->sfd, info.key, info.nkey,
                                  (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
        break;
    case OPERATION_APPEND:
        MEMCACHED_COMMAND_APPEND(c->sfd, info.key, info.nkey,
                                 (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
        break;
    case OPERATION_PREPEND:
        MEMCACHED_COMMAND_PREPEND(c->sfd, info.key, info.nkey,
                                  (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
        break;
    case OPERATION_SET:
        MEMCACHED_COMMAND_SET(c->sfd, info.key, info.nkey,
                              (ret == ENGINE_SUCCESS) ? info.nbytes : -1, c->cas);
        break;
    }
#endif

    switch (ret) {
    case ENGINE_SUCCESS:
        /* Stored */
        write_bin_response(c, NULL, 0, 0, 0);
        break;
    case ENGINE_KEY_EEXISTS:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, 0);
        break;
    case ENGINE_KEY_ENOENT:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
        break;
    case ENGINE_ENOMEM:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    case ENGINE_ENOTSUP:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, 0);
        break;
    case ENGINE_NOT_MY_VBUCKET:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET, 0);
        break;
    default:
        if (c->store_op == OPERATION_ADD) {
            eno = PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS;
        } else if(c->store_op == OPERATION_REPLACE) {
            eno = PROTOCOL_BINARY_RESPONSE_KEY_ENOENT;
        } else {
            eno = PROTOCOL_BINARY_RESPONSE_NOT_STORED;
        }
        write_bin_packet(c, eno, 0);
    }

    SLAB_INCR(c, cmd_set, info.key, info.nkey);

    if (!c->ewouldblock) {
        /* release the c->item reference */
        settings.engine.v1->release(settings.engine.v0, c, c->item);
        c->item = 0;
    }
}

static void process_bin_get(conn *c) {
    item *it;

    protocol_binary_response_get* rsp = (protocol_binary_response_get*)c->wbuf;
    char* key = binary_get_key(c);
    size_t nkey = c->binary_header.request.keylen;

    if (settings.verbose > 1) {
        char buffer[1024];
        if (key_to_printable_buffer(buffer, sizeof(buffer), c->sfd, true,
                                    "GET", key, nkey) != -1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c, "%s\n",
                                            buffer);
        }
    }

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    if (ret == ENGINE_SUCCESS) {
        ret = settings.engine.v1->get(settings.engine.v0, c, &it, key, nkey,
                                      c->binary_header.request.vbucket);
    }

    uint16_t keylen;
    uint32_t bodylen;
    item_info info = { .nvalue = 1 };

    switch (ret) {
    case ENGINE_SUCCESS:
        if (!settings.engine.v1->get_item_info(settings.engine.v0, c, it, &info)) {
            settings.engine.v1->release(settings.engine.v0, c, it);
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                            "%d: Failed to get item info\n",
                                            c->sfd);
            write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINTERNAL, 0);
            break;
        }

        /* the length has two unnecessary bytes ("\r\n") */
        keylen = 0;
        bodylen = sizeof(rsp->message.body) + (info.nbytes - 2);

        STATS_HIT(c, get, key, nkey);

        if (c->cmd == PROTOCOL_BINARY_CMD_GETK) {
            bodylen += nkey;
            keylen = nkey;
        }
        add_bin_header(c, 0, sizeof(rsp->message.body), keylen, bodylen);
        rsp->message.header.response.cas = htonll(info.cas);

        // add the flags
        rsp->message.body.flags = info.flags;
        add_iov(c, &rsp->message.body, sizeof(rsp->message.body));

        if (c->cmd == PROTOCOL_BINARY_CMD_GETK) {
            add_iov(c, info.key, nkey);
        }

        /* Add the data minus the CRLF */
        add_iov(c, info.value[0].iov_base, info.value[0].iov_len - 2);
        conn_set_state(c, conn_mwrite);
        /* Remember this command so we can garbage collect it later */
        c->item = it;
        break;
    case ENGINE_KEY_ENOENT:
        STATS_MISS(c, get, key, nkey);

        MEMCACHED_COMMAND_GET(c->sfd, key, nkey, -1, 0);

        if (c->noreply) {
            conn_set_state(c, conn_new_cmd);
        } else {
            if (c->cmd == PROTOCOL_BINARY_CMD_GETK) {
                char *ofs = c->wbuf + sizeof(protocol_binary_response_header);
                add_bin_header(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT,
                        0, nkey, nkey);
                memcpy(ofs, key, nkey);
                add_iov(c, ofs, nkey);
                conn_set_state(c, conn_mwrite);
            } else {
                write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
            }
        }
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    case ENGINE_ENOTSUP:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, 0);
        break;
    case ENGINE_NOT_MY_VBUCKET:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET, 0);
        break;
    default:
        /* @todo add proper error handling! */
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                        "Unknown error code: %d\n", ret);
        abort();
    }

    if (settings.detail_enabled && ret != ENGINE_EWOULDBLOCK) {
        stats_prefix_record_get(key, nkey, ret == ENGINE_SUCCESS);
    }
}

static void append_bin_stats(const char *key, const uint16_t klen,
                             const char *val, const uint32_t vlen,
                             conn *c) {
    char *buf = c->dynamic_buffer.buffer + c->dynamic_buffer.offset;
    uint32_t bodylen = klen + vlen;
    protocol_binary_response_header header = {
        .response.magic = (uint8_t)PROTOCOL_BINARY_RES,
        .response.opcode = PROTOCOL_BINARY_CMD_STAT,
        .response.keylen = (uint16_t)htons(klen),
        .response.datatype = (uint8_t)PROTOCOL_BINARY_RAW_BYTES,
        .response.bodylen = htonl(bodylen),
        .response.opaque = c->opaque
    };

    memcpy(buf, header.bytes, sizeof(header.response));
    buf += sizeof(header.response);

    if (klen > 0) {
        memcpy(buf, key, klen);
        buf += klen;

        if (vlen > 0) {
            memcpy(buf, val, vlen);
        }
    }

    c->dynamic_buffer.offset += sizeof(header.response) + bodylen;
}

/**
 * Append a key-value pair to the stats output buffer. This function assumes
 * that the output buffer is big enough (it will be if you call it through
 * append_stats)
 */
static void append_ascii_stats(const char *key, const uint16_t klen,
                               const char *val, const uint32_t vlen,
                               conn *c) {
    char *pos = c->dynamic_buffer.buffer + c->dynamic_buffer.offset;
    uint32_t nbytes = 5; /* "END\r\n" or "STAT " */

    if (klen == 0 && vlen == 0) {
        memcpy(pos, "END\r\n", 5);
    } else {
        memcpy(pos, "STAT ", 5);
        memcpy(pos + nbytes, key, klen);
        nbytes += klen;
        if (vlen != 0) {
            pos[nbytes] = ' ';
            ++nbytes;
            memcpy(pos + nbytes, val, vlen);
            nbytes += vlen;
        }
        memcpy(pos + nbytes, "\r\n", 2);
        nbytes += 2;
    }

    c->dynamic_buffer.offset += nbytes;
}

static bool grow_dynamic_buffer(conn *c, size_t needed) {
    size_t nsize = c->dynamic_buffer.size;
    size_t available = nsize - c->dynamic_buffer.offset;
    bool rv = true;

    /* Special case: No buffer -- need to allocate fresh */
    if (c->dynamic_buffer.buffer == NULL) {
        nsize = 1024;
        available = c->dynamic_buffer.size = c->dynamic_buffer.offset = 0;
    }

    while (needed > available) {
        assert(nsize > 0);
        nsize = nsize << 1;
        available = nsize - c->dynamic_buffer.offset;
    }

    if (nsize != c->dynamic_buffer.size) {
        char *ptr = realloc(c->dynamic_buffer.buffer, nsize);
        if (ptr) {
            c->dynamic_buffer.buffer = ptr;
            c->dynamic_buffer.size = nsize;
        } else {
            rv = false;
        }
    }

    return rv;
}

static void append_stats(const char *key, const uint16_t klen,
                  const char *val, const uint32_t vlen,
                  const void *cookie)
{
    /* value without a key is invalid */
    if (klen == 0 && vlen > 0) {
        return ;
    }

    conn *c = (conn*)cookie;

    if (c->protocol == binary_prot) {
        size_t needed = vlen + klen + sizeof(protocol_binary_response_header);
        if (!grow_dynamic_buffer(c, needed)) {
            return ;
        }
        append_bin_stats(key, klen, val, vlen, c);
    } else {
        size_t needed = vlen + klen + 10; // 10 == "STAT = \r\n"
        if (!grow_dynamic_buffer(c, needed)) {
            return ;
        }
        append_ascii_stats(key, klen, val, vlen, c);
    }

    assert(c->dynamic_buffer.offset <= c->dynamic_buffer.size);
}

static void process_bin_stat(conn *c) {
    char *subcommand = binary_get_key(c);
    size_t nkey = c->binary_header.request.keylen;

    if (settings.verbose > 1) {
        char buffer[1024];
        if (key_to_printable_buffer(buffer, sizeof(buffer), c->sfd, true,
                                    "STATS", subcommand, nkey) != -1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c, "%s\n",
                                            buffer);
        }
    }

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    c->ewouldblock = false;

    if (ret == ENGINE_SUCCESS) {
        if (nkey == 0) {
            /* request all statistics */
            ret = settings.engine.v1->get_stats(settings.engine.v0, c, NULL, 0, append_stats);
            if (ret == ENGINE_SUCCESS) {
                server_stats(&append_stats, c, false);
            }
        } else if (strncmp(subcommand, "reset", 5) == 0) {
            stats_reset(c);
            settings.engine.v1->reset_stats(settings.engine.v0, c);
        } else if (strncmp(subcommand, "settings", 8) == 0) {
            process_stat_settings(&append_stats, c);
        } else if (strncmp(subcommand, "detail", 6) == 0) {
            char *subcmd_pos = subcommand + 6;
            if (settings.allow_detailed) {
                if (strncmp(subcmd_pos, " dump", 5) == 0) {
                    int len;
                    char *dump_buf = stats_prefix_dump(&len);
                    if (dump_buf == NULL || len <= 0) {
                        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
                        return ;
                    } else {
                        append_stats("detailed", strlen("detailed"), dump_buf, len, c);
                        free(dump_buf);
                    }
                } else if (strncmp(subcmd_pos, " on", 3) == 0) {
                    settings.detail_enabled = 1;
                } else if (strncmp(subcmd_pos, " off", 4) == 0) {
                    settings.detail_enabled = 0;
                } else {
                    write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
                    return;
                }
            } else {
                write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
                return;
            }
        } else if (strncmp(subcommand, "aggregate", 9) == 0) {
            server_stats(&append_stats, c, true);
        } else if (strncmp(subcommand, "topkeys", 7) == 0) {
            topkeys_t *tk = get_independent_stats(c)->topkeys;
            if (tk != NULL) {
                topkeys_stats(tk, c, current_time, append_stats);
            } else {
                write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
                return;
            }
        } else {
            ret = settings.engine.v1->get_stats(settings.engine.v0, c,
                                                subcommand, nkey,
                                                append_stats);
        }
    }

    switch (ret) {
    case ENGINE_SUCCESS:
        append_stats(NULL, 0, NULL, 0, c);
        write_and_free(c, c->dynamic_buffer.buffer, c->dynamic_buffer.offset);
        c->dynamic_buffer.buffer = NULL;
        break;
    case ENGINE_ENOMEM:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, 0);
        break;
    case ENGINE_KEY_ENOENT:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    case ENGINE_ENOTSUP:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, 0);
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    default:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINVAL, 0);
    }
}

static void bin_read_chunk(conn *c, enum bin_substates next_substate, uint32_t chunk) {
    assert(c);
    c->substate = next_substate;
    c->rlbytes = chunk;

    /* Ok... do we have room for everything in our buffer? */
    ptrdiff_t offset = c->rcurr + sizeof(protocol_binary_request_header) - c->rbuf;
    if (c->rlbytes > c->rsize - offset) {
        size_t nsize = c->rsize;
        size_t size = c->rlbytes + sizeof(protocol_binary_request_header);

        while (size > nsize) {
            nsize *= 2;
        }

        if (nsize != c->rsize) {
            if (settings.verbose > 1) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                        "%d: Need to grow buffer from %lu to %lu\n",
                        c->sfd, (unsigned long)c->rsize, (unsigned long)nsize);
            }
            char *newm = realloc(c->rbuf, nsize);
            if (newm == NULL) {
                if (settings.verbose) {
                    settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                            "%d: Failed to grow buffer.. closing connection\n",
                            c->sfd);
                }
                conn_set_state(c, conn_closing);
                return;
            }

            c->rbuf= newm;
            /* rcurr should point to the same offset in the packet */
            c->rcurr = c->rbuf + offset - sizeof(protocol_binary_request_header);
            c->rsize = nsize;
        }
        if (c->rbuf != c->rcurr) {
            memmove(c->rbuf, c->rcurr, c->rbytes);
            c->rcurr = c->rbuf;
            if (settings.verbose > 1) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                                "%d: Repack input buffer\n",
                                                c->sfd);
            }
        }
    }

    /* preserve the header in the buffer.. */
    c->ritem = c->rcurr + sizeof(protocol_binary_request_header);
    conn_set_state(c, conn_nread);
}

static void bin_read_key(conn *c, enum bin_substates next_substate, int extra) {
    bin_read_chunk(c, next_substate, c->keylen + extra);
}


/* Just write an error message and disconnect the client */
static void handle_binary_protocol_error(conn *c) {
    write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINVAL, 0);
    if (settings.verbose) {
        settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                "%d: Protocol error (opcode %02x), close connection\n",
                c->sfd, c->binary_header.request.opcode);
    }
    c->write_and_go = conn_closing;
}

static void init_sasl_conn(conn *c) {
    assert(c);
    if (!c->sasl_conn) {
        int result=sasl_server_new("memcached",
                                   NULL, NULL, NULL, NULL,
                                   NULL, 0, &c->sasl_conn);
        if (result != SASL_OK) {
            if (settings.verbose) {
                settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                         "%d: Failed to initialize SASL conn.\n",
                         c->sfd);
            }
            c->sasl_conn = NULL;
        }
    }
}

static void get_auth_data(const void *cookie, auth_data_t *data) {
    conn *c = (conn*)cookie;
    if (c->sasl_conn) {
        sasl_getprop(c->sasl_conn, SASL_USERNAME, (void*)&data->username);
#ifdef ENABLE_ISASL
        sasl_getprop(c->sasl_conn, ISASL_CONFIG, (void*)&data->config);
#endif
    }
}

#ifdef SASL_ENABLED
static void bin_list_sasl_mechs(conn *c) {
    init_sasl_conn(c);
    const char *result_string = NULL;
    unsigned int string_length = 0;
    int result=sasl_listmech(c->sasl_conn, NULL,
                             "",   /* What to prepend the string with */
                             " ",  /* What to separate mechanisms with */
                             "",   /* What to append to the string */
                             &result_string, &string_length,
                             NULL);
    if (result != SASL_OK) {
        /* Perhaps there's a better error for this... */
        if (settings.verbose) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                     "%d: Failed to list SASL mechanisms.\n",
                     c->sfd);
        }
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, 0);
        return;
    }
    write_bin_response(c, (char*)result_string, 0, 0, string_length);
}
#endif

struct sasl_tmp {
    int ksize;
    int vsize;
    char data[]; /* data + ksize == value */
};

static void process_bin_sasl_auth(conn *c) {
    assert(c->binary_header.request.extlen == 0);

    int nkey = c->binary_header.request.keylen;
    int vlen = c->binary_header.request.bodylen - nkey;

    if (nkey > MAX_SASL_MECH_LEN) {
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINVAL, vlen);
        c->write_and_go = conn_swallow;
        return;
    }

    char *key = binary_get_key(c);
    assert(key);

    size_t buffer_size = sizeof(struct sasl_tmp) + nkey + vlen + 2;
    struct sasl_tmp *data = calloc(sizeof(struct sasl_tmp) + buffer_size, 1);
    if (!data) {
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, vlen);
        c->write_and_go = conn_swallow;
        return;
    }

    data->ksize = nkey;
    data->vsize = vlen;
    memcpy(data->data, key, nkey);

    c->item = data;
    c->ritem = data->data + nkey;
    c->rlbytes = vlen;
    conn_set_state(c, conn_nread);
    c->substate = bin_reading_sasl_auth_data;
}

static void process_bin_complete_sasl_auth(conn *c) {
    const char *out = NULL;
    unsigned int outlen = 0;

    assert(c->item);
    init_sasl_conn(c);

    int nkey = c->binary_header.request.keylen;
    int vlen = c->binary_header.request.bodylen - nkey;

    struct sasl_tmp *stmp = c->item;
    char mech[nkey+1];
    memcpy(mech, stmp->data, nkey);
    mech[nkey] = 0x00;

    if (settings.verbose) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                "%d: mech: ``%s'' with %d bytes of data\n", c->sfd, mech, vlen);
    }

    const char *challenge = vlen == 0 ? NULL : (stmp->data + nkey);

    int result=-1;

    switch (c->cmd) {
    case PROTOCOL_BINARY_CMD_SASL_AUTH:
        result = sasl_server_start(c->sasl_conn, mech,
                                   challenge, vlen,
                                   &out, &outlen);
        break;
    case PROTOCOL_BINARY_CMD_SASL_STEP:
        result = sasl_server_step(c->sasl_conn,
                                  challenge, vlen,
                                  &out, &outlen);
        break;
    default:
        assert(false); /* CMD should be one of the above */
        /* This code is pretty much impossible, but makes the compiler
           happier */
        if (settings.verbose) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                    "%d: Unhandled command %d with challenge %s\n",
                    c->sfd, c->cmd, challenge);
        }
        break;
    }

    free(c->item);
    c->item = NULL;
    c->ritem = NULL;

    if (settings.verbose) {
        settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                        "%d: sasl result code:  %d\n",
                                        c->sfd, result);
    }

    switch(result) {
    case SASL_OK:
        write_bin_response(c, "Authenticated", 0, 0, strlen("Authenticated"));
        auth_data_t data;
        get_auth_data(c, &data);
        perform_callbacks(ON_AUTH, (const void*)&data, c);
        STATS_NOKEY(c, auth_cmds);
        break;
    case SASL_CONTINUE:
        add_bin_header(c, PROTOCOL_BINARY_RESPONSE_AUTH_CONTINUE, 0, 0, outlen);
        if(outlen > 0) {
            add_iov(c, out, outlen);
        }
        conn_set_state(c, conn_mwrite);
        c->write_and_go = conn_new_cmd;
        break;
    default:
        if (settings.verbose) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                            "%d: Unknown sasl response:  %d\n",
                                            c->sfd, result);
        }
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, 0);
        STATS_NOKEY2(c, auth_cmds, auth_errors);
    }
}

static bool authenticated(conn *c) {
    bool rv = false;

    switch (c->cmd) {
    case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS: /* FALLTHROUGH */
    case PROTOCOL_BINARY_CMD_SASL_AUTH:       /* FALLTHROUGH */
    case PROTOCOL_BINARY_CMD_SASL_STEP:       /* FALLTHROUGH */
    case PROTOCOL_BINARY_CMD_VERSION:         /* FALLTHROUGH */
        rv = true;
        break;
    default:
        if (c->sasl_conn) {
            const void *uname = NULL;
            sasl_getprop(c->sasl_conn, SASL_USERNAME, &uname);
            rv = uname != NULL;
        }
    }

    if (settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                "%d: authenticated() in cmd 0x%02x is %s\n",
                c->sfd, c->cmd, rv ? "true" : "false");
    }

    return rv;
}

static bool binary_response_handler(const void *key, uint16_t keylen,
                                    const void *ext, uint8_t extlen,
                                    const void *body, uint32_t bodylen,
                                    uint8_t datatype, uint16_t status,
                                    uint64_t cas, const void *cookie)
{
    conn *c = (conn*)cookie;
    /* Look at append_bin_stats */
    size_t needed = keylen + extlen + bodylen + sizeof(protocol_binary_response_header);
    if (!grow_dynamic_buffer(c, needed)) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                    "<%d ERROR: Failed to allocate memory for response\n",
                    c->sfd);
        }
        return false;
    }

    char *buf = c->dynamic_buffer.buffer + c->dynamic_buffer.offset;
    protocol_binary_response_header header = {
        .response.magic = (uint8_t)PROTOCOL_BINARY_RES,
        .response.opcode = c->binary_header.request.opcode,
        .response.keylen = (uint16_t)htons(keylen),
        .response.extlen = extlen,
        .response.datatype = datatype,
        .response.status = (uint16_t)htons(status),
        .response.bodylen = htonl(bodylen + keylen + extlen),
        .response.opaque = c->opaque,
        .response.cas = htonll(cas),
    };

    memcpy(buf, header.bytes, sizeof(header.response));
    buf += sizeof(header.response);

    if (extlen > 0) {
        memcpy(buf, ext, extlen);
        buf += extlen;
    }

    if (keylen > 0) {
        memcpy(buf, key, keylen);
        buf += keylen;
    }

    if (bodylen > 0) {
        memcpy(buf, body, bodylen);
    }

    c->dynamic_buffer.offset += needed;

    return true;
}

/**
 * Tap stats (these are only used by the tap thread, so they don't need
 * to be in the threadlocal struct right now...
 */
struct tap_cmd_stats {
    uint64_t connect;
    uint64_t mutation;
    uint64_t delete;
    uint64_t flush;
    uint64_t opaque;
    uint64_t vbucket_set;
};

struct tap_stats {
    pthread_mutex_t mutex;
    struct tap_cmd_stats sent;
    struct tap_cmd_stats received;
} tap_stats = { .mutex = PTHREAD_MUTEX_INITIALIZER };

static void ship_tap_log(conn *c) {
    assert(c->thread->type == TAP);
    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        if (settings.verbose) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                            "%d: Failed to create output headers. Shutting down tap connection\n", c->sfd);
        }
        conn_set_state(c, conn_closing);
        return ;
    }
    /* @todo add check for buffer overflow of c->wbuf) */
    c->wcurr = c->wbuf;

    bool more_data = true;
    bool send_data = false;
    bool disconnect = false;

    item *it;
    uint32_t bodylen;
    int ii = 0;
    c->icurr = c->ilist;
    do {
        /* @todo fixme! */
        if (ii++ == 10) {
            break;
        }

        void *engine;
        uint16_t nengine;
        uint8_t ttl;
        uint16_t tap_flags;
        uint32_t seqno;
        uint16_t vbucket;

        tap_event_t event = c->tap_iterator(settings.engine.v0, c, &it,
                                            &engine, &nengine, &ttl,
                                            &tap_flags, &seqno, &vbucket);
        union {
            protocol_binary_request_tap_mutation mutation;
            protocol_binary_request_tap_delete delete;
            protocol_binary_request_tap_flush flush;
            protocol_binary_request_tap_opaque opaque;
            protocol_binary_request_noop noop;
        } msg = {
            .mutation.message.header.request.magic = (uint8_t)PROTOCOL_BINARY_REQ,
        };

        msg.opaque.message.header.request.opaque = htonl(seqno);
        msg.opaque.message.body.tap.enginespecific_length = htons(nengine);
        msg.opaque.message.body.tap.ttl = ttl;
        msg.opaque.message.body.tap.flags = htons(tap_flags);
        msg.opaque.message.header.request.extlen = 8;
        msg.opaque.message.header.request.vbucket = htons(vbucket);
        item_info info = { .nvalue = 1 };

        switch (event) {
        case TAP_NOOP :
            send_data = true;
            msg.noop.message.header.request.opcode = PROTOCOL_BINARY_CMD_NOOP;
            msg.noop.message.header.request.extlen = 0;
            msg.noop.message.header.request.bodylen = htonl(0);
            memcpy(c->wcurr, msg.noop.bytes, sizeof(msg.noop.bytes));
            add_iov(c, c->wcurr, sizeof(msg.noop.bytes));
            c->wcurr += sizeof(msg.noop.bytes);
            c->wbytes += sizeof(msg.noop.bytes);
            break;
        case TAP_PAUSE :
            more_data = false;
            break;
        case TAP_MUTATION:
            if (!settings.engine.v1->get_item_info(settings.engine.v0, c, it, &info)) {
                settings.engine.v1->release(settings.engine.v0, c, it);
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                                "%d: Failed to get item info\n", c->sfd);
                break;
            }
            send_data = true;
            c->ilist[c->ileft++] = it;

            msg.mutation.message.header.request.opcode = PROTOCOL_BINARY_CMD_TAP_MUTATION;
            msg.mutation.message.header.request.cas = htonll(info.cas);
            msg.mutation.message.header.request.keylen = htons(info.nkey);
            msg.mutation.message.header.request.extlen = 16;

            bodylen = 16 + info.nkey + nengine;
            if ((tap_flags & TAP_FLAG_NO_VALUE) == 0) {
                bodylen += info.nbytes - 2;
            }
            msg.mutation.message.header.request.bodylen = htonl(bodylen);
            msg.mutation.message.body.item.flags = htonl(info.flags);
            msg.mutation.message.body.item.expiration = htonl(info.exptime);
            msg.mutation.message.body.tap.enginespecific_length = htons(nengine);
            msg.mutation.message.body.tap.ttl = ttl;
            msg.mutation.message.body.tap.flags = htons(tap_flags);
            memcpy(c->wcurr, msg.mutation.bytes, sizeof(msg.mutation.bytes));

            add_iov(c, c->wcurr, sizeof(msg.mutation.bytes));
            c->wcurr += sizeof(msg.mutation.bytes);
            c->wbytes += sizeof(msg.mutation.bytes);

            if (nengine > 0) {
                memcpy(c->wcurr, engine, nengine);
                add_iov(c, c->wcurr, nengine);
                c->wcurr += nengine;
                c->wbytes += nengine;
            }

            add_iov(c, info.key, info.nkey);
            if ((tap_flags & TAP_FLAG_NO_VALUE) == 0) {
                add_iov(c, info.value[0].iov_base, info.value[0].iov_len - 2);
            }

            pthread_mutex_lock(&tap_stats.mutex);
            tap_stats.sent.mutation++;
            pthread_mutex_unlock(&tap_stats.mutex);

            break;
        case TAP_DELETION:
            /* This is a delete */
            if (!settings.engine.v1->get_item_info(settings.engine.v0, c, it, &info)) {
                settings.engine.v1->release(settings.engine.v0, c, it);
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                                "%d: Failed to get item info\n", c->sfd);
                break;
            }
            send_data = true;
            c->ilist[c->ileft++] = it;
            msg.mutation.message.header.request.opcode = PROTOCOL_BINARY_CMD_TAP_DELETE;
            msg.delete.message.header.request.keylen = htons(info.nkey);
            msg.delete.message.header.request.bodylen = htonl(info.nkey + 8);
            memcpy(c->wcurr, msg.delete.bytes, sizeof(msg.delete.bytes));
            add_iov(c, c->wcurr, sizeof(msg.delete.bytes));
            c->wcurr += sizeof(msg.delete.bytes);
            c->wbytes += sizeof(msg.delete.bytes);
            add_iov(c, info.key, info.nkey);

            pthread_mutex_lock(&tap_stats.mutex);
            tap_stats.sent.delete++;
            pthread_mutex_unlock(&tap_stats.mutex);
            break;

        case TAP_DISCONNECT:
            disconnect = true;
            more_data = false;
            break;
        case TAP_VBUCKET_SET:
        case TAP_FLUSH:
        case TAP_OPAQUE:
            send_data = true;

            if (event == TAP_OPAQUE) {
                msg.flush.message.header.request.opcode = PROTOCOL_BINARY_CMD_TAP_OPAQUE;
                pthread_mutex_lock(&tap_stats.mutex);
                tap_stats.sent.opaque++;
                pthread_mutex_unlock(&tap_stats.mutex);

            } else if (event == TAP_FLUSH) {
                msg.flush.message.header.request.opcode = PROTOCOL_BINARY_CMD_TAP_FLUSH;
                pthread_mutex_lock(&tap_stats.mutex);
                tap_stats.sent.flush++;
                pthread_mutex_unlock(&tap_stats.mutex);
            } else if (event == TAP_VBUCKET_SET) {
                msg.flush.message.header.request.opcode = PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET;
                msg.flush.message.body.tap.flags = htons(tap_flags);
                pthread_mutex_lock(&tap_stats.mutex);
                tap_stats.sent.vbucket_set++;
                pthread_mutex_unlock(&tap_stats.mutex);
            }

            msg.flush.message.header.request.bodylen = htonl(8 + nengine);
            memcpy(c->wcurr, msg.flush.bytes, sizeof(msg.flush.bytes));
            add_iov(c, c->wcurr, sizeof(msg.flush.bytes));
            c->wcurr += sizeof(msg.flush.bytes);
            c->wbytes += sizeof(msg.flush.bytes);
            if (nengine > 0) {
                memcpy(c->wcurr, engine, nengine);
                add_iov(c, c->wcurr, nengine);
                c->wcurr += nengine;
                c->wbytes += nengine;
            }
            break;
        default:
            abort();
        }
    } while (more_data);

    c->ewouldblock = false;
    if (send_data) {
        conn_set_state(c, conn_mwrite);
        if (disconnect) {
            c->write_and_go = conn_closing;
        } else {
            c->write_and_go = conn_ship_log;
        }
    } else {
        if (disconnect) {
            conn_set_state(c, conn_closing);
        } else {
            /* No more items to ship to the slave at this time.. suspend.. */
            if (settings.verbose > 1) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                                "%d: No more items in tap log.. waiting\n",
                                                c->sfd);
            }
            c->ewouldblock = true;
        }
    }
}

static void process_bin_unknown_packet(conn *c) {
    void *packet = c->rcurr - (c->binary_header.request.bodylen +
                               sizeof(c->binary_header));

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    c->ewouldblock = false;

    if (ret == ENGINE_SUCCESS) {
        ret = settings.engine.v1->unknown_command(settings.engine.v0, c, packet,
                                                  binary_response_handler);
    }

    if (ret == ENGINE_SUCCESS) {
        write_and_free(c, c->dynamic_buffer.buffer, c->dynamic_buffer.offset);
        c->dynamic_buffer.buffer = NULL;
    } else if (ret == ENGINE_ENOTSUP) {
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND, 0);
    } else if (ret == ENGINE_EWOULDBLOCK) {
        c->ewouldblock = true;
    } else {
        /* FATAL ERROR, shut down connection */
        conn_set_state(c, conn_closing);
    }
}

static void process_bin_tap_connect(conn *c) {
    char *packet = (c->rcurr - (c->binary_header.request.bodylen +
                                sizeof(c->binary_header)));
    protocol_binary_request_tap_connect *req = (void*)packet;
    const char *key = packet + sizeof(req->bytes);
    const char *data = key + c->binary_header.request.keylen;
    uint32_t flags = 0;
    size_t ndata = c->binary_header.request.bodylen -
        c->binary_header.request.extlen -
        c->binary_header.request.keylen;

    if (c->binary_header.request.extlen == 4) {
        flags = ntohl(req->message.body.flags);

        if (flags & TAP_CONNECT_FLAG_BACKFILL) {
            /* the userdata has to be at least 8 bytes! */
            if (ndata < 8) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                                "%d: ERROR: Invalid tap connect message\n",
                                                c->sfd);
                conn_set_state(c, conn_closing);
                return ;
            }
        }
    } else {
        data -= 4;
        key -= 4;
    }

    if (settings.verbose && c->binary_header.request.keylen > 0) {
        char buffer[1024];
        int len = c->binary_header.request.keylen;
        if (len >= sizeof(buffer)) {
            len = sizeof(buffer) - 1;
        }
        memcpy(buffer, key, len);
        buffer[len] = '\0';
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        "%d: Trying to connect with named tap connection: <%s>\n",
                                        c->sfd, buffer);
    }

    TAP_ITERATOR iterator = settings.engine.v1->get_tap_iterator(
        settings.engine.v0, c, key, c->binary_header.request.keylen,
        flags, data, ndata);

    if (iterator == NULL) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                        "%d: FATAL: The engine does not support tap\n",
                                        c->sfd);
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, 0);
        c->write_and_go = conn_closing;
    } else {
        c->tap_iterator = iterator;
        c->which = EV_WRITE;
        conn_set_state(c, conn_ship_log);
    }
}

static void process_bin_tap_packet(tap_event_t event, conn *c) {
    assert(c != NULL);
    char *packet = (c->rcurr - (c->binary_header.request.bodylen +
                                sizeof(c->binary_header)));
    protocol_binary_request_tap_no_extras *tap = (void*)packet;
    uint16_t nengine = ntohs(tap->message.body.tap.enginespecific_length);
    uint16_t tap_flags = ntohs(tap->message.body.tap.flags);
    uint32_t seqno = ntohl(tap->message.header.request.opaque);
    uint8_t ttl = tap->message.body.tap.ttl;
    assert(ttl > 0);
    char *engine_specific = packet + sizeof(tap->bytes);
    char *key = engine_specific + nengine;
    uint16_t nkey = c->binary_header.request.keylen;
    char *data = key + nkey;
    uint32_t flags = 0;
    uint32_t exptime = 0;
    uint32_t ndata = c->binary_header.request.bodylen - nengine - nkey - 8;

    if (event == TAP_MUTATION) {
        protocol_binary_request_tap_mutation *mutation = (void*)tap;
        flags = ntohl(mutation->message.body.item.flags);
        exptime = ntohl(mutation->message.body.item.expiration);
        key += 8;
        data += 8;
        ndata -= 8;
    }

    ENGINE_ERROR_CODE ret;
    ret = settings.engine.v1->tap_notify(settings.engine.v0, c,
                                         engine_specific, nengine,
                                         ttl - 1, tap_flags,
                                         event, seqno,
                                         key, nkey,
                                         flags, exptime,
                                         ntohll(tap->message.header.request.cas),
                                         data, ndata,
                                         c->binary_header.request.vbucket);

    if (ret == ENGINE_DISCONNECT) {
        conn_set_state(c, conn_closing);
    } else {
        if (tap_flags & TAP_FLAG_ACK) {
            write_bin_packet(c, engine_error_2_protocol_error(ret), 0);
        } else {
            conn_set_state(c, conn_new_cmd);
        }
    }
}

static void process_bin_tap_ack(conn *c) {
    assert(c != NULL);
    char *packet = (c->rcurr - (c->binary_header.request.bodylen +
                                sizeof(c->binary_header)));
    protocol_binary_response_no_extras *rsp = (void*)packet;
    uint32_t seqno = ntohl(rsp->message.header.response.opaque);
    uint16_t status = ntohs(rsp->message.header.response.status);
    char *key = packet + sizeof(rsp->bytes);

    ENGINE_ERROR_CODE ret = ENGINE_DISCONNECT;
    if (settings.engine.v1->tap_notify != NULL) {
        ret = settings.engine.v1->tap_notify(settings.engine.v0, c, NULL, 0, 0, status,
                                             TAP_ACK, seqno, key,
                                             c->binary_header.request.keylen, 0, 0,
                                             0, NULL, 0, 0);
    }

    if (ret == ENGINE_DISCONNECT) {
        conn_set_state(c, conn_closing);
    } else {
        conn_set_state(c, conn_ship_log);
    }
}

static void process_bin_packet(conn *c) {
    /* @todo this should be an array of funciton pointers and call through */
    switch (c->binary_header.request.opcode) {
    case PROTOCOL_BINARY_CMD_TAP_CONNECT:
        pthread_mutex_lock(&tap_stats.mutex);
        tap_stats.received.connect++;
        pthread_mutex_unlock(&tap_stats.mutex);
        conn_set_state(c, conn_add_tap_client);
        break;
    case PROTOCOL_BINARY_CMD_TAP_MUTATION:
        pthread_mutex_lock(&tap_stats.mutex);
        tap_stats.received.mutation++;
        pthread_mutex_unlock(&tap_stats.mutex);
        process_bin_tap_packet(TAP_MUTATION, c);
        break;
    case PROTOCOL_BINARY_CMD_TAP_DELETE:
        pthread_mutex_lock(&tap_stats.mutex);
        tap_stats.received.delete++;
        pthread_mutex_unlock(&tap_stats.mutex);
        process_bin_tap_packet(TAP_DELETION, c);
        break;
    case PROTOCOL_BINARY_CMD_TAP_FLUSH:
        pthread_mutex_lock(&tap_stats.mutex);
        tap_stats.received.flush++;
        pthread_mutex_unlock(&tap_stats.mutex);
        process_bin_tap_packet(TAP_FLUSH, c);
        break;
    case PROTOCOL_BINARY_CMD_TAP_OPAQUE:
        pthread_mutex_lock(&tap_stats.mutex);
        tap_stats.received.opaque++;
        pthread_mutex_unlock(&tap_stats.mutex);
        process_bin_tap_packet(TAP_OPAQUE, c);
        break;
    case PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET:
        pthread_mutex_lock(&tap_stats.mutex);
        tap_stats.received.vbucket_set++;
        pthread_mutex_unlock(&tap_stats.mutex);
        process_bin_tap_packet(TAP_VBUCKET_SET, c);
        break;
    default:
        process_bin_unknown_packet(c);
    }
}

typedef void (*RESPONSE_HANDLER)(conn*);
/**
 * A map between the response packets op-code and the function to handle
 * the response message.
 */
static RESPONSE_HANDLER response_handlers[256] = {
    [PROTOCOL_BINARY_CMD_TAP_MUTATION] = process_bin_tap_ack,
    [PROTOCOL_BINARY_CMD_TAP_DELETE] = process_bin_tap_ack,
    [PROTOCOL_BINARY_CMD_TAP_FLUSH] = process_bin_tap_ack,
    [PROTOCOL_BINARY_CMD_TAP_OPAQUE] = process_bin_tap_ack,
    [PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET] = process_bin_tap_ack
};

static void dispatch_bin_command(conn *c) {
    int protocol_error = 0;

    int extlen = c->binary_header.request.extlen;
    int keylen = c->binary_header.request.keylen;
    uint32_t bodylen = c->binary_header.request.bodylen;

    if (settings.require_sasl && !authenticated(c)) {
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_AUTH_ERROR, 0);
        c->write_and_go = conn_closing;
        return;
    }

    MEMCACHED_PROCESS_COMMAND_START(c->sfd, c->rcurr, c->rbytes);
    c->noreply = true;

    /* binprot supports 16bit keys, but internals are still 8bit */
    if (keylen > KEY_MAX_LENGTH) {
        handle_binary_protocol_error(c);
        return;
    }

    switch (c->cmd) {
    case PROTOCOL_BINARY_CMD_SETQ:
        c->cmd = PROTOCOL_BINARY_CMD_SET;
        break;
    case PROTOCOL_BINARY_CMD_ADDQ:
        c->cmd = PROTOCOL_BINARY_CMD_ADD;
        break;
    case PROTOCOL_BINARY_CMD_REPLACEQ:
        c->cmd = PROTOCOL_BINARY_CMD_REPLACE;
        break;
    case PROTOCOL_BINARY_CMD_DELETEQ:
        c->cmd = PROTOCOL_BINARY_CMD_DELETE;
        break;
    case PROTOCOL_BINARY_CMD_INCREMENTQ:
        c->cmd = PROTOCOL_BINARY_CMD_INCREMENT;
        break;
    case PROTOCOL_BINARY_CMD_DECREMENTQ:
        c->cmd = PROTOCOL_BINARY_CMD_DECREMENT;
        break;
    case PROTOCOL_BINARY_CMD_QUITQ:
        c->cmd = PROTOCOL_BINARY_CMD_QUIT;
        break;
    case PROTOCOL_BINARY_CMD_FLUSHQ:
        c->cmd = PROTOCOL_BINARY_CMD_FLUSH;
        break;
    case PROTOCOL_BINARY_CMD_APPENDQ:
        c->cmd = PROTOCOL_BINARY_CMD_APPEND;
        break;
    case PROTOCOL_BINARY_CMD_PREPENDQ:
        c->cmd = PROTOCOL_BINARY_CMD_PREPEND;
        break;
    case PROTOCOL_BINARY_CMD_GETQ:
        c->cmd = PROTOCOL_BINARY_CMD_GET;
        break;
    case PROTOCOL_BINARY_CMD_GETKQ:
        c->cmd = PROTOCOL_BINARY_CMD_GETK;
        break;
    default:
        c->noreply = false;
    }

    switch (c->cmd) {
        case PROTOCOL_BINARY_CMD_VERSION:
            if (extlen == 0 && keylen == 0 && bodylen == 0) {
                write_bin_response(c, VERSION, 0, 0, strlen(VERSION));
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_FLUSH:
            if (keylen == 0 && bodylen == extlen && (extlen == 0 || extlen == 4)) {
                bin_read_key(c, bin_read_flush_exptime, extlen);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_NOOP:
            if (extlen == 0 && keylen == 0 && bodylen == 0) {
                write_bin_response(c, NULL, 0, 0, 0);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_SET: /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_ADD: /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_REPLACE:
            if (extlen == 8 && keylen != 0 && bodylen >= (keylen + 8)) {
                bin_read_key(c, bin_reading_set_header, 8);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_GETQ:  /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_GET:   /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_GETKQ: /* FALLTHROUGH */
        case PROTOCOL_BINARY_CMD_GETK:
            if (extlen == 0 && bodylen == keylen && keylen > 0) {
                bin_read_key(c, bin_reading_get_key, 0);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_DELETE:
            if (keylen > 0 && extlen == 0 && bodylen == keylen) {
                bin_read_key(c, bin_reading_del_header, extlen);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_INCREMENT:
        case PROTOCOL_BINARY_CMD_DECREMENT:
            if (keylen > 0 && extlen == 20 && bodylen == (keylen + extlen)) {
                bin_read_key(c, bin_reading_incr_header, 20);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_APPEND:
        case PROTOCOL_BINARY_CMD_PREPEND:
            if (keylen > 0 && extlen == 0) {
                bin_read_key(c, bin_reading_set_header, 0);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_STAT:
            if (extlen == 0) {
                bin_read_key(c, bin_reading_stat, 0);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_QUIT:
            if (keylen == 0 && extlen == 0 && bodylen == 0) {
                write_bin_response(c, NULL, 0, 0, 0);
                c->write_and_go = conn_closing;
                if (c->noreply) {
                    conn_set_state(c, conn_closing);
                }
            } else {
                protocol_error = 1;
            }
            break;
       case PROTOCOL_BINARY_CMD_TAP_CONNECT:
            if (settings.engine.v1->get_tap_iterator == NULL) {
                write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, bodylen);
            } else {
                bin_read_chunk(c, bin_reading_packet,
                               c->binary_header.request.bodylen);
            }
            break;
       case PROTOCOL_BINARY_CMD_TAP_MUTATION:
       case PROTOCOL_BINARY_CMD_TAP_DELETE:
       case PROTOCOL_BINARY_CMD_TAP_FLUSH:
       case PROTOCOL_BINARY_CMD_TAP_OPAQUE:
       case PROTOCOL_BINARY_CMD_TAP_VBUCKET_SET:
            if (settings.engine.v1->tap_notify == NULL) {
                write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, bodylen);
            } else {
                bin_read_chunk(c, bin_reading_packet, c->binary_header.request.bodylen);
            }
            break;
#ifdef SASL_ENABLED
        case PROTOCOL_BINARY_CMD_SASL_LIST_MECHS:
            if (extlen == 0 && keylen == 0 && bodylen == 0) {
                bin_list_sasl_mechs(c);
            } else {
                protocol_error = 1;
            }
            break;
        case PROTOCOL_BINARY_CMD_SASL_AUTH:
        case PROTOCOL_BINARY_CMD_SASL_STEP:
            if (extlen == 0 && keylen != 0) {
                bin_read_key(c, bin_reading_sasl_auth, 0);
            } else {
                protocol_error = 1;
            }
            break;
#endif
        default:
            if (settings.engine.v1->unknown_command == NULL) {
                write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_UNKNOWN_COMMAND,
                                bodylen);
            } else {
                bin_read_chunk(c, bin_reading_packet, c->binary_header.request.bodylen);
            }
    }

    if (protocol_error)
        handle_binary_protocol_error(c);
}

static void process_bin_update(conn *c) {
    char *key;
    int nkey;
    int vlen;
    item *it;
    protocol_binary_request_set* req = binary_get_request(c);

    assert(c != NULL);

    key = binary_get_key(c);
    nkey = c->binary_header.request.keylen;

    /* fix byteorder in the request */
    req->message.body.flags = req->message.body.flags;
    req->message.body.expiration = ntohl(req->message.body.expiration);

    vlen = c->binary_header.request.bodylen - (nkey + c->binary_header.request.extlen);

    if (settings.verbose > 1) {
        char buffer[1024];
        const char *prefix;
        if (c->cmd == PROTOCOL_BINARY_CMD_ADD) {
            prefix = "ADD";
        } else if (c->cmd == PROTOCOL_BINARY_CMD_SET) {
            prefix = "SET";
        } else {
            prefix = "REPLACE";
        }

        size_t nw;
        nw = key_to_printable_buffer(buffer, sizeof(buffer), c->sfd, true,
                                     prefix, key, nkey);

        if (nw != -1) {
            if (snprintf(buffer + nw, sizeof(buffer) - nw,
                         " Value len is %d\n", vlen)) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c, "%s",
                                                buffer);
            }
        }
    }

    if (settings.detail_enabled) {
        stats_prefix_record_set(key, nkey);
    }

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    c->ewouldblock = false;
    item_info info = { .nvalue = 1 };

    if (ret == ENGINE_SUCCESS) {
        ret = settings.engine.v1->allocate(settings.engine.v0, c,
                                           &it, key, nkey,
                                           vlen + 2,
                                           req->message.body.flags,
                                           realtime(req->message.body.expiration));
        if (ret == ENGINE_SUCCESS && !settings.engine.v1->get_item_info(settings.engine.v0,
                                                                        c, it, &info)) {
            settings.engine.v1->release(settings.engine.v0, c, it);
            write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINTERNAL, 0);
            return;
        }
    }

    switch (ret) {
    case ENGINE_SUCCESS:
        item_set_cas(c, it, c->binary_header.request.cas);

        switch (c->cmd) {
        case PROTOCOL_BINARY_CMD_ADD:
            c->store_op = OPERATION_ADD;
            break;
        case PROTOCOL_BINARY_CMD_SET:
            c->store_op = OPERATION_SET;
            break;
        case PROTOCOL_BINARY_CMD_REPLACE:
            c->store_op = OPERATION_REPLACE;
            break;
        default:
            assert(0);
        }

        if (c->binary_header.request.cas != 0) {
            c->store_op = OPERATION_CAS;
        }

        c->item = it;
        c->ritem = info.value[0].iov_base;
        c->rlbytes = vlen;
        conn_set_state(c, conn_nread);
        c->substate = bin_read_set_value;
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    default:
        if (ret == ENGINE_E2BIG) {
            write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_E2BIG, vlen);
        } else {
            write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, vlen);
        }

        /*
         * Avoid stale data persisting in cache because we failed alloc.
         * Unacceptable for SET (but only if cas matches).
         * Anywhere else too?
         */
        if (c->cmd == PROTOCOL_BINARY_CMD_SET) {
            /* @todo fix this for the ASYNC interface! */
            settings.engine.v1->remove(settings.engine.v0, c, key, nkey,
                                       ntohll(req->message.header.request.cas),
                                       c->binary_header.request.vbucket);
        }

        /* swallow the data line */
        c->write_and_go = conn_swallow;
    }
}

static void process_bin_append_prepend(conn *c) {
    char *key;
    int nkey;
    int vlen;
    item *it;

    assert(c != NULL);

    key = binary_get_key(c);
    nkey = c->binary_header.request.keylen;
    vlen = c->binary_header.request.bodylen - nkey;

    if (settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        "Value len is %d\n", vlen);
    }

    if (settings.detail_enabled) {
        stats_prefix_record_set(key, nkey);
    }

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    c->ewouldblock = false;
    item_info info = { .nvalue = 1 };

    if (ret == ENGINE_SUCCESS) {
        ret = settings.engine.v1->allocate(settings.engine.v0, c,
                                           &it, key, nkey,
                                           vlen + 2, 0, 0);
        if (ret == ENGINE_SUCCESS && !settings.engine.v1->get_item_info(settings.engine.v0,
                                                                        c, it, &info)) {
            settings.engine.v1->release(settings.engine.v0, c, it);
            write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINTERNAL, 0);
            return;
        }
    }

    switch (ret) {
    case ENGINE_SUCCESS:
        item_set_cas(c, it, c->binary_header.request.cas);

        switch (c->cmd) {
        case PROTOCOL_BINARY_CMD_APPEND:
            c->store_op = OPERATION_APPEND;
            break;
        case PROTOCOL_BINARY_CMD_PREPEND:
            c->store_op = OPERATION_PREPEND;
            break;
        default:
            assert(0);
        }

        c->item = it;
        c->ritem = info.value[0].iov_base;
        c->rlbytes = vlen;
        conn_set_state(c, conn_nread);
        c->substate = bin_read_set_value;
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    default:
        if (ret == ENGINE_E2BIG) {
            write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_E2BIG, vlen);
        } else {
            write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_ENOMEM, vlen);
        }
        /* swallow the data line */
        c->write_and_go = conn_swallow;
    }
}

static void process_bin_flush(conn *c) {
    time_t exptime = 0;
    protocol_binary_request_flush* req = binary_get_request(c);

    if (c->binary_header.request.extlen == sizeof(req->message.body)) {
        exptime = ntohl(req->message.body.expiration);
    }

    if (settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        "%d: flush %ld", c->sfd,
                                        (long)exptime);
    }

    ENGINE_ERROR_CODE ret;
    ret = settings.engine.v1->flush(settings.engine.v0, c, exptime);

    if (ret == ENGINE_SUCCESS) {
        write_bin_response(c, NULL, 0, 0, 0);
    } else if (ret == ENGINE_ENOTSUP) {
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_SUPPORTED, 0);
    } else {
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINVAL, 0);
    }
    STATS_NOKEY(c, cmd_flush);
}

static void process_bin_delete(conn *c) {
    protocol_binary_request_delete* req = binary_get_request(c);

    char* key = binary_get_key(c);
    size_t nkey = c->binary_header.request.keylen;

    assert(c != NULL);

    if (settings.verbose > 1) {
        char buffer[1024];
        if (key_to_printable_buffer(buffer, sizeof(buffer), c->sfd, true,
                                    "DELETE", key, nkey) != -1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c, "%s\n",
                                            buffer);
        }
    }

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    c->ewouldblock = false;

    if (ret == ENGINE_SUCCESS) {
        if (settings.detail_enabled) {
            stats_prefix_record_delete(key, nkey);
        }
        ret = settings.engine.v1->remove(settings.engine.v0, c, key, nkey,
                                         ntohll(req->message.header.request.cas),
                                         c->binary_header.request.vbucket);
    }

    switch (ret) {
    case ENGINE_SUCCESS:
        write_bin_response(c, NULL, 0, 0, 0);
        break;
    case ENGINE_KEY_EEXISTS:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_EEXISTS, 0);
        break;
    case ENGINE_KEY_ENOENT:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_KEY_ENOENT, 0);
        break;
    case ENGINE_NOT_MY_VBUCKET:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_NOT_MY_VBUCKET, 0);
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    default:
        write_bin_packet(c, PROTOCOL_BINARY_RESPONSE_EINVAL, 0);
    }
}

static void complete_nread_binary(conn *c) {
    assert(c != NULL);
    assert(c->cmd >= 0);

    switch(c->substate) {
    case bin_reading_set_header:
        if (c->cmd == PROTOCOL_BINARY_CMD_APPEND ||
                c->cmd == PROTOCOL_BINARY_CMD_PREPEND) {
            process_bin_append_prepend(c);
        } else {
            process_bin_update(c);
        }
        break;
    case bin_read_set_value:
        complete_update_bin(c);
        break;
    case bin_reading_get_key:
        process_bin_get(c);
        break;
    case bin_reading_stat:
        process_bin_stat(c);
        break;
    case bin_reading_del_header:
        process_bin_delete(c);
        break;
    case bin_reading_incr_header:
        complete_incr_bin(c);
        break;
    case bin_read_flush_exptime:
        process_bin_flush(c);
        break;
    case bin_reading_sasl_auth:
        process_bin_sasl_auth(c);
        break;
    case bin_reading_sasl_auth_data:
        process_bin_complete_sasl_auth(c);
        break;
    case bin_reading_packet:
        if (c->binary_header.request.magic == PROTOCOL_BINARY_RES) {
            RESPONSE_HANDLER handler;
            handler = response_handlers[c->binary_header.request.opcode];
            if (handler) {
                handler(c);
            } else {
                settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                       "%d: ERROR: Unsupported response packet received: %u\n",
                        c->sfd, (unsigned int)c->binary_header.request.opcode);
                conn_set_state(c, conn_closing);
            }
        } else {
            process_bin_packet(c);
        }
        break;
    default:
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                "Not handling substate %d\n", c->substate);
        abort();
    }
}

static void reset_cmd_handler(conn *c) {
    c->ascii_cmd = NULL;
    c->cmd = -1;
    c->substate = bin_no_state;
    if(c->item != NULL) {
        settings.engine.v1->release(settings.engine.v0, c, c->item);
        c->item = NULL;
    }
    conn_shrink(c);
    if (c->rbytes > 0) {
        conn_set_state(c, conn_parse_cmd);
    } else {
        conn_set_state(c, conn_waiting);
    }
}

static bool ascii_response_handler(const void *cookie,
                                   int nbytes,
                                   const char *dta)
{
    conn *c = (conn*)cookie;
    if (!grow_dynamic_buffer(c, nbytes)) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                    "<%d ERROR: Failed to allocate memory for response\n",
                    c->sfd);
        }
        return false;
    }

    char *buf = c->dynamic_buffer.buffer + c->dynamic_buffer.offset;
    memcpy(buf, dta, nbytes);
    c->dynamic_buffer.offset += nbytes;

    return true;
}

static void complete_nread_ascii(conn *c) {
    if (c->ascii_cmd != NULL) {
        if (!c->ascii_cmd->execute(c->ascii_cmd->cookie, c, 0, NULL,
                                   ascii_response_handler)) {
            conn_set_state(c, conn_closing);
        } else if (c->dynamic_buffer.buffer != NULL) {
            write_and_free(c, c->dynamic_buffer.buffer,
                           c->dynamic_buffer.offset);
            c->dynamic_buffer.buffer = NULL;
        } else {
            conn_set_state(c, conn_new_cmd);
        }
    } else {
        complete_update_ascii(c);
    }
}

static void complete_nread(conn *c) {
    assert(c != NULL);
    assert(c->protocol == ascii_prot
           || c->protocol == binary_prot);

    if (c->protocol == ascii_prot) {
        complete_nread_ascii(c);
    } else if (c->protocol == binary_prot) {
        complete_nread_binary(c);
    }
}

#define COMMAND_TOKEN 0
#define SUBCOMMAND_TOKEN 1
#define KEY_TOKEN 1

#define MAX_TOKENS 30

/*
 * Tokenize the command string by replacing whitespace with '\0' and update
 * the token array tokens with pointer to start of each token and length.
 * Returns total number of tokens.  The last valid token is the terminal
 * token (value points to the first unprocessed character of the string and
 * length zero).
 *
 * Usage example:
 *
 *  while(tokenize_command(command, ncommand, tokens, max_tokens) > 0) {
 *      for(int ix = 0; tokens[ix].length != 0; ix++) {
 *          ...
 *      }
 *      ncommand = tokens[ix].value - command;
 *      command  = tokens[ix].value;
 *   }
 */
static size_t tokenize_command(char *command, token_t *tokens, const size_t max_tokens) {
    char *s, *e;
    size_t ntokens = 0;

    assert(command != NULL && tokens != NULL && max_tokens > 1);

    for (s = e = command; ntokens < max_tokens - 1; ++e) {
        if (*e == ' ') {
            if (s != e) {
                tokens[ntokens].value = s;
                tokens[ntokens].length = e - s;
                ntokens++;
                *e = '\0';
            }
            s = e + 1;
        }
        else if (*e == '\0') {
            if (s != e) {
                tokens[ntokens].value = s;
                tokens[ntokens].length = e - s;
                ntokens++;
            }

            break; /* string end */
        }
    }

    /*
     * If we scanned the whole string, the terminal value pointer is null,
     * otherwise it is the first unprocessed character.
     */
    tokens[ntokens].value =  *e == '\0' ? NULL : e;
    tokens[ntokens].length = 0;
    ntokens++;

    return ntokens;
}

static void detokenize(token_t *tokens, int ntokens, char **out, int *nbytes) {
    int i, nb;
    char *buf, *p;

    nb = ntokens; // account for spaces, which is ntokens-1, plus the null
    for (i = 0; i < ntokens; ++i) {
        nb += tokens[i].length;
    }

    buf = malloc(nb * sizeof(char));
    if (buf != NULL) {
        p = buf;
        for (i = 0; i < ntokens; ++i) {
            memcpy(p, tokens[i].value, tokens[i].length);
            p += tokens[i].length;
            *p = ' ';
            p++;
        }
        buf[nb - 1] = '\0';
        *nbytes = nb - 1;
        *out = buf;
    }
}


/* set up a connection to write a buffer then free it, used for stats */
static void write_and_free(conn *c, char *buf, int bytes) {
    if (buf) {
        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        conn_set_state(c, conn_write);
        c->write_and_go = conn_new_cmd;
    } else {
        out_string(c, "SERVER_ERROR out of memory writing stats");
    }
}

static inline bool set_noreply_maybe(conn *c, token_t *tokens, size_t ntokens)
{
    int noreply_index = ntokens - 2;

    /*
      NOTE: this function is not the first place where we are going to
      send the reply.  We could send it instead from process_command()
      if the request line has wrong number of tokens.  However parsing
      malformed line for "noreply" option is not reliable anyway, so
      it can't be helped.
    */
    if (tokens[noreply_index].value
        && strcmp(tokens[noreply_index].value, "noreply") == 0) {
        c->noreply = true;
    }
    return c->noreply;
}

void append_stat(const char *name, ADD_STAT add_stats, conn *c,
                 const char *fmt, ...) {
    char val_str[STAT_VAL_LEN];
    int vlen;
    va_list ap;

    assert(name);
    assert(add_stats);
    assert(c);
    assert(fmt);

    va_start(ap, fmt);
    vlen = vsnprintf(val_str, sizeof(val_str) - 1, fmt, ap);
    va_end(ap);

    add_stats(name, strlen(name), val_str, vlen, c);
}

inline static void process_stats_detail(conn *c, const char *command) {
    assert(c != NULL);

    if (settings.allow_detailed) {
        if (strcmp(command, "on") == 0) {
            settings.detail_enabled = 1;
            out_string(c, "OK");
        }
        else if (strcmp(command, "off") == 0) {
            settings.detail_enabled = 0;
            out_string(c, "OK");
        }
        else if (strcmp(command, "dump") == 0) {
            int len;
            char *stats = stats_prefix_dump(&len);
            write_and_free(c, stats, len);
        }
        else {
            out_string(c, "CLIENT_ERROR usage: stats detail on|off|dump");
        }
    }
    else {
        out_string(c, "CLIENT_ERROR detailed stats disabled");
    }
}

static void aggregate_callback(void *in, void *out) {
    struct thread_stats *out_thread_stats = out;
    struct independent_stats *in_independent_stats = in;
    threadlocal_stats_aggregate(in_independent_stats->thread_stats,
                                out_thread_stats);
}

/* return server specific stats only */
static void server_stats(ADD_STAT add_stats, conn *c, bool aggregate) {
    pid_t pid = getpid();
    rel_time_t now = current_time;

    struct thread_stats thread_stats;
    threadlocal_stats_clear(&thread_stats);

    if (aggregate && settings.engine.v1->aggregate_stats != NULL) {
        settings.engine.v1->aggregate_stats(settings.engine.v0,
                                            (const void *)c,
                                            aggregate_callback,
                                            &thread_stats);
    } else {
        threadlocal_stats_aggregate(get_independent_stats(c)->thread_stats,
                                    &thread_stats);
    }

    struct slab_stats slab_stats;
    slab_stats_aggregate(&thread_stats, &slab_stats);

#ifndef __WIN32__
    struct rusage usage;
    getrusage(RUSAGE_SELF, &usage);
#endif

    STATS_LOCK();

    APPEND_STAT("pid", "%lu", (long)pid);
    APPEND_STAT("uptime", "%u", now);
    APPEND_STAT("time", "%ld", now + (long)process_started);
    APPEND_STAT("version", "%s", VERSION);
    APPEND_STAT("libevent", "%s", event_get_version());
    APPEND_STAT("pointer_size", "%d", (int)(8 * sizeof(void *)));

#ifndef __WIN32__
    append_stat("rusage_user", add_stats, c, "%ld.%06ld",
                (long)usage.ru_utime.tv_sec,
                (long)usage.ru_utime.tv_usec);
    append_stat("rusage_system", add_stats, c, "%ld.%06ld",
                (long)usage.ru_stime.tv_sec,
                (long)usage.ru_stime.tv_usec);
#endif

    APPEND_STAT("daemon_connections", "%u", stats.daemon_conns);
    APPEND_STAT("curr_connections", "%u", stats.curr_conns);
    APPEND_STAT("total_connections", "%u", stats.total_conns);
    APPEND_STAT("connection_structures", "%u", stats.conn_structs);
    APPEND_STAT("cmd_get", "%"PRIu64, thread_stats.cmd_get);
    APPEND_STAT("cmd_set", "%"PRIu64, slab_stats.cmd_set);
    APPEND_STAT("cmd_flush", "%"PRIu64, thread_stats.cmd_flush);
    APPEND_STAT("auth_cmds", "%"PRIu64, thread_stats.auth_cmds);
    APPEND_STAT("auth_errors", "%"PRIu64, thread_stats.auth_errors);
    APPEND_STAT("get_hits", "%"PRIu64, slab_stats.get_hits);
    APPEND_STAT("get_misses", "%"PRIu64, thread_stats.get_misses);
    APPEND_STAT("delete_misses", "%"PRIu64, thread_stats.delete_misses);
    APPEND_STAT("delete_hits", "%"PRIu64, slab_stats.delete_hits);
    APPEND_STAT("incr_misses", "%"PRIu64, thread_stats.incr_misses);
    APPEND_STAT("incr_hits", "%"PRIu64, thread_stats.incr_hits);
    APPEND_STAT("decr_misses", "%"PRIu64, thread_stats.decr_misses);
    APPEND_STAT("decr_hits", "%"PRIu64, thread_stats.decr_hits);
    APPEND_STAT("cas_misses", "%"PRIu64, thread_stats.cas_misses);
    APPEND_STAT("cas_hits", "%"PRIu64, slab_stats.cas_hits);
    APPEND_STAT("cas_badval", "%"PRIu64, slab_stats.cas_badval);
    APPEND_STAT("bytes_read", "%"PRIu64, thread_stats.bytes_read);
    APPEND_STAT("bytes_written", "%"PRIu64, thread_stats.bytes_written);
    APPEND_STAT("limit_maxbytes", "%"PRIu64, settings.maxbytes);
    APPEND_STAT("rejected_conns", "%" PRIu64, (unsigned long long)stats.rejected_conns);
    APPEND_STAT("threads", "%d", settings.num_threads);
    APPEND_STAT("conn_yields", "%" PRIu64, (unsigned long long)thread_stats.conn_yields);
    STATS_UNLOCK();

    /*
     * Add tap stats (only if non-zero)
     */
    struct tap_stats ts;
    pthread_mutex_lock(&tap_stats.mutex);
    ts = tap_stats;
    pthread_mutex_unlock(&tap_stats.mutex);

    if (ts.sent.connect) {
        APPEND_STAT("tap_connect_sent", "%"PRIu64, ts.sent.connect);
    }
    if (ts.sent.mutation) {
        APPEND_STAT("tap_mutation_sent", "%"PRIu64, ts.sent.mutation);
    }
    if (ts.sent.delete) {
        APPEND_STAT("tap_delete_sent", "%"PRIu64, ts.sent.delete);
    }
    if (ts.sent.flush) {
        APPEND_STAT("tap_flush_sent", "%"PRIu64, ts.sent.flush);
    }
    if (ts.sent.opaque) {
        APPEND_STAT("tap_opaque_sent", "%"PRIu64, ts.sent.opaque);
    }
    if (ts.sent.vbucket_set) {
        APPEND_STAT("tap_vbucket_set_sent", "%"PRIu64,
                    ts.sent.vbucket_set);
    }
    if (ts.received.connect) {
        APPEND_STAT("tap_connect_received", "%"PRIu64, ts.received.connect);
    }
    if (ts.received.mutation) {
        APPEND_STAT("tap_mutation_received", "%"PRIu64, ts.received.mutation);
    }
    if (ts.received.delete) {
        APPEND_STAT("tap_delete_received", "%"PRIu64, ts.received.delete);
    }
    if (ts.received.flush) {
        APPEND_STAT("tap_flush_received", "%"PRIu64, ts.received.flush);
    }
    if (ts.received.opaque) {
        APPEND_STAT("tap_opaque_received", "%"PRIu64, ts.received.opaque);
    }
    if (ts.received.vbucket_set) {
        APPEND_STAT("tap_vbucket_set_received", "%"PRIu64,
                    ts.received.vbucket_set);
    }
}

static void process_stat_settings(ADD_STAT add_stats, void *c) {
    assert(add_stats);
    APPEND_STAT("maxbytes", "%u", (unsigned int)settings.maxbytes);
    APPEND_STAT("maxconns", "%d", settings.maxconns);
    APPEND_STAT("tcpport", "%d", settings.port);
    APPEND_STAT("udpport", "%d", settings.udpport);
    APPEND_STAT("inter", "%s", settings.inter ? settings.inter : "NULL");
    APPEND_STAT("verbosity", "%d", settings.verbose);
    APPEND_STAT("oldest", "%lu", (unsigned long)settings.oldest_live);
    APPEND_STAT("evictions", "%s", settings.evict_to_free ? "on" : "off");
    APPEND_STAT("domain_socket", "%s",
                settings.socketpath ? settings.socketpath : "NULL");
    APPEND_STAT("umask", "%o", settings.access);
    APPEND_STAT("growth_factor", "%.2f", settings.factor);
    APPEND_STAT("chunk_size", "%d", settings.chunk_size);
    APPEND_STAT("num_threads", "%d", settings.num_threads);
    APPEND_STAT("stat_key_prefix", "%c", settings.prefix_delimiter);
    APPEND_STAT("detail_enabled", "%s",
                settings.detail_enabled ? "yes" : "no");
    APPEND_STAT("allow_detailed", "%s",
                settings.allow_detailed ? "yes" : "no");
    APPEND_STAT("reqs_per_event", "%d", settings.reqs_per_event);
    APPEND_STAT("cas_enabled", "%s", settings.use_cas ? "yes" : "no");
    APPEND_STAT("tcp_backlog", "%d", settings.backlog);
    APPEND_STAT("binding_protocol", "%s",
                prot_text(settings.binding_protocol));
#ifdef SASL_ENABLED
    APPEND_STAT("auth_enabled_sasl", "%s", "yes");
#else
    APPEND_STAT("auth_enabled_sasl", "%s", "no");
#endif

#ifdef ENABLE_ISASL
    APPEND_STAT("auth_sasl_engine", "%s", "isasl");
#elif defined(ENABLE_SASL)
    APPEND_STAT("auth_sasl_engine", "%s", "cyrus");
#else
    APPEND_STAT("auth_sasl_engine", "%s", "none");
#endif
    APPEND_STAT("auth_required_sasl", "%s", settings.require_sasl ? "yes" : "no");
    APPEND_STAT("item_size_max", "%d", settings.item_size_max);
    APPEND_STAT("topkeys", "%d", settings.topkeys);

    for (EXTENSION_DAEMON_DESCRIPTOR *ptr = settings.extensions.daemons;
         ptr != NULL;
         ptr = ptr->next) {
        APPEND_STAT("extension", "%s", ptr->get_name());
    }

    APPEND_STAT("logger", "%s", settings.extensions.logger->get_name());

    for (EXTENSION_ASCII_PROTOCOL_DESCRIPTOR *ptr = settings.extensions.ascii;
         ptr != NULL;
         ptr = ptr->next) {
        APPEND_STAT("ascii_extension", "%s", ptr->get_name(ptr->cookie));
    }
}

static void process_stat(conn *c, token_t *tokens, const size_t ntokens) {
    const char *subcommand = tokens[SUBCOMMAND_TOKEN].value;
    assert(c != NULL);

    if (ntokens < 2) {
        out_string(c, "CLIENT_ERROR bad command line");
        return;
    }

    if (ntokens == 2) {
        server_stats(&append_stats, c, false);
        (void)settings.engine.v1->get_stats(settings.engine.v0, c,
                                            NULL, 0, &append_stats);
    } else if (strcmp(subcommand, "reset") == 0) {
        stats_reset(c);
        out_string(c, "RESET");
        return ;
    } else if (strcmp(subcommand, "detail") == 0) {
        /* NOTE: how to tackle detail with binary? */
        if (ntokens < 4)
            process_stats_detail(c, "");  /* outputs the error message */
        else
            process_stats_detail(c, tokens[2].value);
        /* Output already generated */
        return ;
    } else if (strcmp(subcommand, "settings") == 0) {
        process_stat_settings(&append_stats, c);
    } else if (strcmp(subcommand, "cachedump") == 0) {
        char *buf = NULL;
        unsigned int bytes = 0, id, limit = 0;

        if (ntokens < 5) {
            out_string(c, "CLIENT_ERROR bad command line");
            return;
        }

        if (!safe_strtoul(tokens[2].value, &id) ||
            !safe_strtoul(tokens[3].value, &limit)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        if (id >= POWER_LARGEST) {
            out_string(c, "CLIENT_ERROR Illegal slab id");
            return;
        }

#ifdef FUTURE
        buf = item_cachedump(id, limit, &bytes);
#endif
        write_and_free(c, buf, bytes);
        return ;
    } else if (strcmp(subcommand, "aggregate") == 0) {
        server_stats(&append_stats, c, true);
    } else if (strcmp(subcommand, "topkeys") == 0) {
        topkeys_t *tk = get_independent_stats(c)->topkeys;
        if (tk != NULL) {
            topkeys_stats(tk, c, current_time, append_stats);
        } else {
            out_string(c, "ERROR");
            return;
        }
    } else {
        /* getting here means that the subcommand is either engine specific or
           is invalid. query the engine and see. */
        ENGINE_ERROR_CODE ret;
        char *buf = NULL;
        int nb = -1;
        detokenize(&tokens[1], ntokens - 2, &buf, &nb);
        ret = settings.engine.v1->get_stats(settings.engine.v0, c, buf,
                                            nb, append_stats);
        free(buf);

        switch (ret) {
        case ENGINE_SUCCESS:
            append_stats(NULL, 0, NULL, 0, c);
            write_and_free(c, c->dynamic_buffer.buffer, c->dynamic_buffer.offset);
            c->dynamic_buffer.buffer = NULL;
            break;
        case ENGINE_ENOMEM:
            out_string(c, "SERVER_ERROR out of memory writing stats");
            break;
        case ENGINE_DISCONNECT:
            c->state = conn_closing;
            break;
        case ENGINE_ENOTSUP:
            out_string(c, "SERVER_ERROR not supported");
            break;
        default:
            out_string(c, "ERROR");
            break;
        }
        return ;
    }

    /* append terminator and start the transfer */
    append_stats(NULL, 0, NULL, 0, c);

    if (c->dynamic_buffer.buffer == NULL) {
        out_string(c, "SERVER_ERROR out of memory writing stats");
    } else {
        write_and_free(c, c->dynamic_buffer.buffer, c->dynamic_buffer.offset);
        c->dynamic_buffer.buffer = NULL;
    }
}

/**
 * Get a suffix buffer and insert it into the list of used suffix buffers
 * @param c the connection object
 * @return a pointer to a new suffix buffer or NULL if allocation failed
 */
static char *get_suffix_buffer(conn *c) {
    if (c->suffixleft == c->suffixsize) {
        char **new_suffix_list;
        size_t sz = sizeof(char*) * c->suffixsize * 2;

        new_suffix_list = realloc(c->suffixlist, sz);
        if (new_suffix_list) {
            c->suffixsize *= 2;
            c->suffixlist = new_suffix_list;
        } else {
            if (settings.verbose > 1) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                        "=%d Failed to resize suffix buffer\n", c->sfd);
            }

            return NULL;
        }
    }

    char *suffix = cache_alloc(c->thread->suffix_cache);
    if (suffix != NULL) {
        *(c->suffixlist + c->suffixleft) = suffix;
        ++c->suffixleft;
    }

    return suffix;
}

/* ntokens is overwritten here... shrug.. */
static inline void process_get_command(conn *c, token_t *tokens, size_t ntokens, bool return_cas) {
    char *key;
    size_t nkey;
    int i = 0;
    item *it;
    token_t *key_token = &tokens[KEY_TOKEN];
    assert(c != NULL);

    do {
        while(key_token->length != 0) {

            key = key_token->value;
            nkey = key_token->length;

            if(nkey > KEY_MAX_LENGTH) {
                out_string(c, "CLIENT_ERROR bad command line format");
                return;
            }

            if (settings.engine.v1->get(settings.engine.v0, c, &it,
                                        key, nkey, 0) != ENGINE_SUCCESS) {
                it = NULL;
            }

            if (settings.detail_enabled) {
                stats_prefix_record_get(key, nkey, NULL != it);
            }

            if (it) {
                item_info info = { .nvalue = 1 };
                if (!settings.engine.v1->get_item_info(settings.engine.v0, c, it,
                                                       &info)) {
                    settings.engine.v1->release(settings.engine.v0, c, it);
                    out_string(c, "SERVER_ERROR error getting item data");
                    break;
                }

                assert(memcmp((char*)info.value[0].iov_base + info.nbytes - 2, "\r\n", 2) == 0);

                if (i >= c->isize) {
                    item **new_list = realloc(c->ilist, sizeof(item *) * c->isize * 2);
                    if (new_list) {
                        c->isize *= 2;
                        c->ilist = new_list;
                    } else {
                        settings.engine.v1->release(settings.engine.v0, c, it);
                        break;
                    }
                }

                /* Rebuild the suffix */
                char *suffix = get_suffix_buffer(c);
                if (suffix == NULL) {
                    out_string(c, "SERVER_ERROR out of memory rebuilding suffix");
                    settings.engine.v1->release(settings.engine.v0, c, it);
                    return;
                }
                int suffix_len = snprintf(suffix, SUFFIX_SIZE,
                                          " %u %u\r\n", htonl(info.flags),
                                          info.nbytes - 2);

                /*
                 * Construct the response. Each hit adds three elements to the
                 * outgoing data list:
                 *   "VALUE "
                 *   key
                 *   " " + flags + " " + data length + "\r\n" + data (with \r\n)
                 */

                MEMCACHED_COMMAND_GET(c->sfd, info.key, info.nkey,
                                      info.nbytes, info.cas);
                if (return_cas)
                {

                  char *cas = get_suffix_buffer(c);
                  if (cas == NULL) {
                    out_string(c, "SERVER_ERROR out of memory making CAS suffix");
                    settings.engine.v1->release(settings.engine.v0, c, it);
                    return;
                  }
                  int cas_len = snprintf(cas, SUFFIX_SIZE, " %"PRIu64"\r\n",
                                         info.cas);
                  if (add_iov(c, "VALUE ", 6) != 0 ||
                      add_iov(c, info.key, info.nkey) != 0 ||
                      add_iov(c, suffix, suffix_len - 2) != 0 ||
                      add_iov(c, cas, cas_len) != 0 ||
                      add_iov(c, info.value[0].iov_base, info.value[0].iov_len) != 0)
                      {
                          settings.engine.v1->release(settings.engine.v0, c, it);
                          break;
                      }
                }
                else
                {
                  if (add_iov(c, "VALUE ", 6) != 0 ||
                      add_iov(c, info.key, info.nkey) != 0 ||
                      add_iov(c, suffix, suffix_len) != 0 ||
                      add_iov(c, info.value[0].iov_base, info.value[0].iov_len) != 0)
                      {
                          settings.engine.v1->release(settings.engine.v0, c, it);
                          break;
                      }
                }


                if (settings.verbose > 1) {
                    settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                                    ">%d sending key %s\n",
                                                    c->sfd, info.key);
                }

                /* item_get() has incremented it->refcount for us */
                STATS_HIT(c, get, key, nkey);
                *(c->ilist + i) = it;
                i++;

            } else {
                STATS_MISS(c, get, key, nkey);
                MEMCACHED_COMMAND_GET(c->sfd, key, nkey, -1, 0);
            }

            key_token++;
        }

        /*
         * If the command string hasn't been fully processed, get the next set
         * of tokens.
         */
        if(key_token->value != NULL) {
            ntokens = tokenize_command(key_token->value, tokens, MAX_TOKENS);
            key_token = tokens;
        }

    } while(key_token->value != NULL);

    c->icurr = c->ilist;
    c->ileft = i;
    c->suffixcurr = c->suffixlist;

    if (settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        ">%d END\n", c->sfd);
    }

    /*
        If the loop was terminated because of out-of-memory, it is not
        reliable to add END\r\n to the buffer, because it might not end
        in \r\n. So we send SERVER_ERROR instead.
    */
    if (key_token->value != NULL || add_iov(c, "END\r\n", 5) != 0
        || (IS_UDP(c->transport) && build_udp_headers(c) != 0)) {
        out_string(c, "SERVER_ERROR out of memory writing get response");
    }
    else {
        conn_set_state(c, conn_mwrite);
        c->msgcurr = 0;
    }

    return;
}

static void process_update_command(conn *c, token_t *tokens, const size_t ntokens, ENGINE_STORE_OPERATION store_op, bool handle_cas) {
    char *key;
    size_t nkey;
    unsigned int flags;
    int32_t exptime_int = 0;
    time_t exptime;
    int vlen;
    uint64_t req_cas_id=0;
    item *it;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if (! (safe_strtoul(tokens[2].value, (uint32_t *)&flags)
           && safe_strtol(tokens[3].value, &exptime_int)
           && safe_strtol(tokens[4].value, (int32_t *)&vlen))) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    /* Ubuntu 8.04 breaks when I pass exptime to safe_strtol */
    exptime = exptime_int;

    // does cas value exist?
    if (handle_cas) {
        if (!safe_strtoull(tokens[5].value, &req_cas_id)) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
    }

    vlen += 2;
    if (vlen < 0 || vlen - 2 < 0) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (settings.detail_enabled) {
        stats_prefix_record_set(key, nkey);
    }

    ENGINE_ERROR_CODE ret = c->aiostat;
    c->aiostat = ENGINE_SUCCESS;
    c->ewouldblock = false;

    if (ret == ENGINE_SUCCESS) {
        ret = settings.engine.v1->allocate(settings.engine.v0, c,
                                           &it, key, nkey,
                                           vlen, htonl(flags), realtime(exptime));
    }

    item_info info = { .nvalue = 1 };
    switch (ret) {
    case ENGINE_SUCCESS:
        item_set_cas(c, it, req_cas_id);
        if (!settings.engine.v1->get_item_info(settings.engine.v0, c, it, &info)) {
            settings.engine.v1->release(settings.engine.v0, c, it);
            out_string(c, "SERVER_ERROR error getting item data");
            break;
        }
        c->item = it;
        c->ritem = info.value[0].iov_base;
        c->rlbytes = vlen;
        c->store_op = store_op;
        conn_set_state(c, conn_nread);
        break;
    case ENGINE_EWOULDBLOCK:
        c->ewouldblock = true;
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    default:
        if (ret == ENGINE_E2BIG) {
            out_string(c, "SERVER_ERROR object too large for cache");
        } else {
            out_string(c, "SERVER_ERROR out of memory storing object");
        }
        /* swallow the data line */
        c->write_and_go = conn_swallow;
        c->sbytes = vlen;

        /* Avoid stale data persisting in cache because we failed alloc.
         * Unacceptable for SET. Anywhere else too? */
        if (store_op == OPERATION_SET) {
            settings.engine.v1->remove(settings.engine.v0, c, key, nkey, 0, 0);
        }
    }
}

static void process_arithmetic_command(conn *c, token_t *tokens, const size_t ntokens, const bool incr) {

    uint64_t delta;
    char *key;
    size_t nkey;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);

    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if (!safe_strtoull(tokens[2].value, &delta)) {
        out_string(c, "CLIENT_ERROR invalid numeric delta argument");
        return;
    }

    ENGINE_ERROR_CODE ret;
    uint64_t cas;
    uint64_t result;
    ret = settings.engine.v1->arithmetic(settings.engine.v0, c, key, nkey,
                                         incr, false, delta, 0, 0, &cas,
                                         &result, 0);

    char temp[INCR_MAX_STORAGE_LEN];
    switch (ret) {
    case ENGINE_SUCCESS:
        if (incr) {
            STATS_INCR(c, incr_hits, key, nkey);
        } else {
            STATS_INCR(c, decr_hits, key, nkey);
        }
        snprintf(temp, sizeof(temp), "%"PRIu64, result);
        out_string(c, temp);
        break;
    case ENGINE_KEY_ENOENT:
        if (incr) {
            STATS_INCR(c, incr_misses, key, nkey);
        } else {
            STATS_INCR(c, decr_misses, key, nkey);
        }
        out_string(c, "NOT_FOUND");
        break;
    case ENGINE_ENOMEM:
        out_string(c, "SERVER_ERROR out of memory");
        break;
    case ENGINE_EINVAL:
        out_string(c, "CLIENT_ERROR cannot increment or decrement non-numeric value");
        break;
    case ENGINE_NOT_STORED:
        out_string(c, "SERVER_ERROR failed to store item");
        break;
    case ENGINE_DISCONNECT:
        c->state = conn_closing;
        break;
    case ENGINE_ENOTSUP:
        out_string(c, "SERVER_ERROR not supported");
        break;
    default:
        abort();
    }
}

static void process_delete_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;

    assert(c != NULL);

    if (ntokens > 3) {
        bool hold_is_zero = strcmp(tokens[KEY_TOKEN+1].value, "0") == 0;
        bool sets_noreply = set_noreply_maybe(c, tokens, ntokens);
        bool valid = (ntokens == 4 && (hold_is_zero || sets_noreply))
            || (ntokens == 5 && hold_is_zero && sets_noreply);
        if (!valid) {
            out_string(c, "CLIENT_ERROR bad command line format.  "
                       "Usage: delete <key> [noreply]");
            return;
        }
    }


    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if(nkey > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (settings.detail_enabled) {
        stats_prefix_record_delete(key, nkey);
    }

    ENGINE_ERROR_CODE ret;
    ret = settings.engine.v1->remove(settings.engine.v0, c, key, nkey, 0, 0);

    /* For some reason the SLAB_INCR tries to access this... */
    item_info info = { .nvalue = 1 };
    if (ret == ENGINE_SUCCESS) {
        out_string(c, "DELETED");
        SLAB_INCR(c, delete_hits, key, nkey);
    } else {
        out_string(c, "NOT_FOUND");
        STATS_INCR(c, delete_misses, key, nkey);
    }
}

static void process_verbosity_command(conn *c, token_t *tokens, const size_t ntokens) {
    unsigned int level;

    assert(c != NULL);

    set_noreply_maybe(c, tokens, ntokens);
    if (c->noreply && ntokens == 3) {
        /* "verbosity noreply" is not according to the correct syntax */
        c->noreply = false;
        out_string(c, "ERROR");
        return;
    }

    if (safe_strtoul(tokens[1].value, &level)) {
        settings.verbose = level > MAX_VERBOSITY_LEVEL ? MAX_VERBOSITY_LEVEL : level;
        perform_callbacks(ON_LOG_LEVEL, NULL, NULL);
        out_string(c, "OK");
    } else {
        out_string(c, "ERROR");
    }
}

static void process_command(conn *c, char *command) {

    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    int comm;

    assert(c != NULL);

    MEMCACHED_PROCESS_COMMAND_START(c->sfd, c->rcurr, c->rbytes);

    if (settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                        "<%d %s\n", c->sfd, command);
    }

    /*
     * for commands set/add/replace, we build an item and read the data
     * directly into it, then continue in nread_complete().
     */

    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        out_string(c, "SERVER_ERROR out of memory preparing response");
        return;
    }

    ntokens = tokenize_command(command, tokens, MAX_TOKENS);
    if (ntokens >= 3 &&
        ((strcmp(tokens[COMMAND_TOKEN].value, "get") == 0) ||
         (strcmp(tokens[COMMAND_TOKEN].value, "bget") == 0))) {

        process_get_command(c, tokens, ntokens, false);

    } else if ((ntokens == 6 || ntokens == 7) &&
               ((strcmp(tokens[COMMAND_TOKEN].value, "add") == 0 && (comm = (int)OPERATION_ADD)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "set") == 0 && (comm = (int)OPERATION_SET)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "replace") == 0 && (comm = (int)OPERATION_REPLACE)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "prepend") == 0 && (comm = (int)OPERATION_PREPEND)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "append") == 0 && (comm = (int)OPERATION_APPEND)) )) {

        process_update_command(c, tokens, ntokens, (ENGINE_STORE_OPERATION)comm, false);

    } else if ((ntokens == 7 || ntokens == 8) && (strcmp(tokens[COMMAND_TOKEN].value, "cas") == 0 && (comm = (int)OPERATION_CAS))) {

        process_update_command(c, tokens, ntokens, (ENGINE_STORE_OPERATION)comm, true);

    } else if ((ntokens == 4 || ntokens == 5) && (strcmp(tokens[COMMAND_TOKEN].value, "incr") == 0)) {

        process_arithmetic_command(c, tokens, ntokens, 1);

    } else if (ntokens >= 3 && (strcmp(tokens[COMMAND_TOKEN].value, "gets") == 0)) {

        process_get_command(c, tokens, ntokens, true);

    } else if ((ntokens == 4 || ntokens == 5) && (strcmp(tokens[COMMAND_TOKEN].value, "decr") == 0)) {

        process_arithmetic_command(c, tokens, ntokens, 0);

    } else if (ntokens >= 3 && ntokens <= 5 && (strcmp(tokens[COMMAND_TOKEN].value, "delete") == 0)) {

        process_delete_command(c, tokens, ntokens);

    } else if (ntokens >= 2 && (strcmp(tokens[COMMAND_TOKEN].value, "stats") == 0)) {

        process_stat(c, tokens, ntokens);

    } else if (ntokens >= 2 && ntokens <= 4 && (strcmp(tokens[COMMAND_TOKEN].value, "flush_all") == 0)) {
        time_t exptime;

        set_noreply_maybe(c, tokens, ntokens);

        if (ntokens == (c->noreply ? 3 : 2)) {
            exptime = 0;
        } else {
            exptime = strtol(tokens[1].value, NULL, 10);
            if(errno == ERANGE) {
                out_string(c, "CLIENT_ERROR bad command line format");
                return;
            }
        }

        ENGINE_ERROR_CODE ret;
        ret = settings.engine.v1->flush(settings.engine.v0, c, exptime);
        if (ret == ENGINE_SUCCESS) {
            out_string(c, "OK");
        } else if (ret == ENGINE_ENOTSUP) {
            out_string(c, "SERVER_ERROR not supported");
        } else {
            out_string(c, "SERVER_ERROR failed to flush cache");
        }
        STATS_NOKEY(c, cmd_flush);
        return;

    } else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "version") == 0)) {

        out_string(c, "VERSION " VERSION);

    } else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "quit") == 0)) {

        conn_set_state(c, conn_closing);

    } else if ((ntokens == 3 || ntokens == 4) && (strcmp(tokens[COMMAND_TOKEN].value, "verbosity") == 0)) {
        process_verbosity_command(c, tokens, ntokens);
    } else if (settings.extensions.ascii != NULL) {
        EXTENSION_ASCII_PROTOCOL_DESCRIPTOR *cmd;
        size_t nbytes = 0;
        char *ptr;

        if (ntokens > 0) {
            if (ntokens == MAX_TOKENS) {
                out_string(c, "ERROR too many arguments");
                return;
            }

            if (tokens[ntokens - 1].length == 0) {
                --ntokens;
            }
        }

        for (cmd = settings.extensions.ascii; cmd != NULL; cmd = cmd->next) {
            if (cmd->accept(cmd->cookie, c, ntokens, tokens, &nbytes, &ptr)) {
                break;
            }
        }

        if (cmd == NULL) {
            out_string(c, "ERROR unknown command");
        } else if (nbytes == 0) {
            if (!cmd->execute(cmd->cookie, c, ntokens, tokens,
                              ascii_response_handler)) {
                conn_set_state(c, conn_closing);
            } else {
                if (c->dynamic_buffer.buffer != NULL) {
                    write_and_free(c, c->dynamic_buffer.buffer,
                                   c->dynamic_buffer.offset);
                    c->dynamic_buffer.buffer = NULL;
                } else {
                    conn_set_state(c, conn_new_cmd);
                }
            }
        } else {
            c->rlbytes = nbytes;
            c->ritem = ptr;
            c->ascii_cmd = cmd;
            /* NOT SUPPORTED YET! */
            conn_set_state(c, conn_nread);
        }
    } else {
        out_string(c, "ERROR");
    }
    return;
}

/*
 * if we have a complete line in the buffer, process it.
 */
static int try_read_command(conn *c) {
    assert(c != NULL);
    assert(c->rcurr <= (c->rbuf + c->rsize));
    assert(c->rbytes > 0);

    if (c->protocol == negotiating_prot || c->transport == udp_transport)  {
        if ((unsigned char)c->rbuf[0] == (unsigned char)PROTOCOL_BINARY_REQ) {
            c->protocol = binary_prot;
        } else {
            c->protocol = ascii_prot;
        }

        if (settings.verbose > 1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                    "%d: Client using the %s protocol\n", c->sfd,
                    prot_text(c->protocol));
        }
    }

    if (c->protocol == binary_prot) {
        /* Do we have the complete packet header? */
        if (c->rbytes < sizeof(c->binary_header)) {
            /* need more data! */
            return 0;
        } else {
#ifdef NEED_ALIGN
            if (((long)(c->rcurr)) % 8 != 0) {
                /* must realign input buffer */
                memmove(c->rbuf, c->rcurr, c->rbytes);
                c->rcurr = c->rbuf;
                if (settings.verbose > 1) {
                    settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                             "%d: Realign input buffer\n", c->sfd);
                }
            }
#endif
            protocol_binary_request_header* req;
            req = (protocol_binary_request_header*)c->rcurr;

            if (settings.verbose > 1) {
                /* Dump the packet before we convert it to host order */
                char buffer[1024];
                ssize_t nw;
                nw = bytes_to_output_string(buffer, sizeof(buffer), c->sfd,
                                            true, "Read binary protocol data:",
                                            (const char*)req->bytes,
                                            sizeof(req->bytes));
                if (nw != -1) {
                    settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                                                    "%s", buffer);
                }
            }

            c->binary_header = *req;
            c->binary_header.request.keylen = ntohs(req->request.keylen);
            c->binary_header.request.bodylen = ntohl(req->request.bodylen);
            c->binary_header.request.vbucket = ntohs(req->request.vbucket);
            c->binary_header.request.cas = ntohll(req->request.cas);


            if (c->binary_header.request.magic != PROTOCOL_BINARY_REQ &&
                !(c->binary_header.request.magic == PROTOCOL_BINARY_RES &&
                  response_handlers[c->binary_header.request.opcode])) {
                if (settings.verbose) {
                    if (c->binary_header.request.magic != PROTOCOL_BINARY_RES) {
                        settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                              "%d: Invalid magic:  %x\n", c->sfd,
                              c->binary_header.request.magic);
                    } else {
                        settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                              "%d: ERROR: Unsupported response packet received: %u\n",
                              c->sfd, (unsigned int)c->binary_header.request.opcode);

                    }
                }
                conn_set_state(c, conn_closing);
                return -1;
            }

            c->msgcurr = 0;
            c->msgused = 0;
            c->iovused = 0;
            if (add_msghdr(c) != 0) {
                out_string(c, "SERVER_ERROR out of memory");
                return 0;
            }

            c->cmd = c->binary_header.request.opcode;
            c->keylen = c->binary_header.request.keylen;
            c->opaque = c->binary_header.request.opaque;
            /* clear the returned cas value */
            c->cas = 0;

            dispatch_bin_command(c);

            c->rbytes -= sizeof(c->binary_header);
            c->rcurr += sizeof(c->binary_header);
        }
    } else {
        char *el, *cont;

        if (c->rbytes == 0)
            return 0;

        el = memchr(c->rcurr, '\n', c->rbytes);
        if (!el) {
            if (c->rbytes > 1024) {
                /*
                 * We didn't have a '\n' in the first k. This _has_ to be a
                 * large multiget, if not we should just nuke the connection.
                 */
                char *ptr = c->rcurr;
                while (*ptr == ' ') { /* ignore leading whitespaces */
                    ++ptr;
                }

                if (ptr - c->rcurr > 100 ||
                    (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {

                    conn_set_state(c, conn_closing);
                    return 1;
                }
            }

            return 0;
        }
        cont = el + 1;
        if ((el - c->rcurr) > 1 && *(el - 1) == '\r') {
            el--;
        }
        *el = '\0';

        assert(cont <= (c->rcurr + c->rbytes));

        process_command(c, c->rcurr);

        c->rbytes -= (cont - c->rcurr);
        c->rcurr = cont;

        assert(c->rcurr <= (c->rbuf + c->rsize));
    }

    return 1;
}

/*
 * read a UDP request.
 */
static enum try_read_result try_read_udp(conn *c) {
    int res;

    assert(c != NULL);

    c->request_addr_size = sizeof(c->request_addr);
    res = recvfrom(c->sfd, c->rbuf, c->rsize,
                   0, &c->request_addr, &c->request_addr_size);
    if (res > 8) {
        unsigned char *buf = (unsigned char *)c->rbuf;
        STATS_ADD(c, bytes_read, res);

        /* Beginning of UDP packet is the request ID; save it. */
        c->request_id = buf[0] * 256 + buf[1];

        /* If this is a multi-packet request, drop it. */
        if (buf[4] != 0 || buf[5] != 1) {
            out_string(c, "SERVER_ERROR multi-packet request not supported");
            return READ_NO_DATA_RECEIVED;
        }

        /* Don't care about any of the rest of the header. */
        res -= 8;
        memmove(c->rbuf, c->rbuf + 8, res);

        c->rbytes += res;
        c->rcurr = c->rbuf;
        return READ_DATA_RECEIVED;
    }
    return READ_NO_DATA_RECEIVED;
}

/*
 * read from network as much as we can, handle buffer overflow and connection
 * close.
 * before reading, move the remaining incomplete fragment of a command
 * (if any) to the beginning of the buffer.
 *
 * To protect us from someone flooding a connection with bogus data causing
 * the connection to eat up all available memory, break out and start looking
 * at the data I've got after a number of reallocs...
 *
 * @return enum try_read_result
 */
static enum try_read_result try_read_network(conn *c) {
    enum try_read_result gotdata = READ_NO_DATA_RECEIVED;
    int res;
    int num_allocs = 0;
    assert(c != NULL);

    if (c->rcurr != c->rbuf) {
        if (c->rbytes != 0) /* otherwise there's nothing to copy */
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1) {
        if (c->rbytes >= c->rsize) {
            if (num_allocs == 4) {
                return gotdata;
            }
            ++num_allocs;
            char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
            if (!new_rbuf) {
                if (settings.verbose > 0) {
                 settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                          "Couldn't realloc input buffer\n");
                }
                c->rbytes = 0; /* ignore what we read */
                out_string(c, "SERVER_ERROR out of memory reading request");
                c->write_and_go = conn_closing;
                return READ_MEMORY_ERROR;
            }
            c->rcurr = c->rbuf = new_rbuf;
            c->rsize *= 2;
        }

        int avail = c->rsize - c->rbytes;
        res = read(c->sfd, c->rbuf + c->rbytes, avail);
        if (res > 0) {
            STATS_ADD(c, bytes_read, res);
            gotdata = READ_DATA_RECEIVED;
            c->rbytes += res;
            if (res == avail) {
                continue;
            } else {
                break;
            }
        }
        if (res == 0) {
            return READ_ERROR;
        }
        if (res == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            return READ_ERROR;
        }
    }
    return gotdata;
}

static bool update_event(conn *c, const int new_flags) {
    assert(c != NULL);

    struct event_base *base = c->event.ev_base;
    if (c->ev_flags == new_flags)
        return true;

    settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                    "Updated event for %d to read=%s, write=%s\n",
                                    c->sfd, (new_flags & EV_READ ? "yes" : "no"),
                                    (new_flags & EV_WRITE ? "yes" : "no"));

    if (event_del(&c->event) == -1) return false;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return false;
    return true;
}

/*
 * Transmit the next chunk of data from our list of msgbuf structures.
 *
 * Returns:
 *   TRANSMIT_COMPLETE   All done writing.
 *   TRANSMIT_INCOMPLETE More data remaining to write.
 *   TRANSMIT_SOFT_ERROR Can't write any more right now.
 *   TRANSMIT_HARD_ERROR Can't write (c->state is set to conn_closing)
 */
static enum transmit_result transmit(conn *c) {
    assert(c != NULL);

    if (c->msgcurr < c->msgused &&
            c->msglist[c->msgcurr].msg_iovlen == 0) {
        /* Finished writing the current msg; advance to the next. */
        c->msgcurr++;
    }
    if (c->msgcurr < c->msgused) {
        ssize_t res;
        struct msghdr *m = &c->msglist[c->msgcurr];

        res = sendmsg(c->sfd, m, 0);
        if (res > 0) {
            STATS_ADD(c, bytes_written, res);

            /* We've written some of the data. Remove the completed
               iovec entries from the list of pending writes. */
            while (m->msg_iovlen > 0 && res >= m->msg_iov->iov_len) {
                res -= m->msg_iov->iov_len;
                m->msg_iovlen--;
                m->msg_iov++;
            }

            /* Might have written just part of the last iovec entry;
               adjust it so the next write will do the rest. */
            if (res > 0) {
                m->msg_iov->iov_base = (caddr_t)m->msg_iov->iov_base + res;
                m->msg_iov->iov_len -= res;
            }
            return TRANSMIT_INCOMPLETE;
        }
        if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                if (settings.verbose > 0) {
                    settings.extensions.logger->log(EXTENSION_LOG_DEBUG, c,
                            "Couldn't update event\n");
                }
                conn_set_state(c, conn_closing);
                return TRANSMIT_HARD_ERROR;
            }
            return TRANSMIT_SOFT_ERROR;
        }
        /* if res == 0 or res == -1 and error is not EAGAIN or EWOULDBLOCK,
           we have a real error, on which we close the connection */
        if (settings.verbose > 0)
            perror("Failed to write, and not due to blocking");

        if (IS_UDP(c->transport))
            conn_set_state(c, conn_read);
        else
            conn_set_state(c, conn_closing);
        return TRANSMIT_HARD_ERROR;
    } else {
        return TRANSMIT_COMPLETE;
    }
}

bool conn_listening(conn *c)
{
    int sfd, flags = 1;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    if ((sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen)) == -1) {
        if (errno == EMFILE) {
            if (settings.verbose > 0) {
                settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                                "Too many open connections\n");
            }
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                            "Failed to accept new client: %s\n",
                                            strerror(errno));

        }

        return false;
    }

    STATS_LOCK();
    int curr_conns = stats.curr_conns;
    STATS_UNLOCK();

    if (curr_conns >= settings.maxconns) {
        STATS_LOCK();
        ++stats.rejected_conns;
        STATS_UNLOCK();

        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                            "Too many open connections\n");
        }
        safe_close(sfd);

        return false;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                        "Failed to set nonblocking io: %s\n",
                                        strerror(errno));
        safe_close(sfd);
        return false;
    }

    dispatch_conn_new(sfd, conn_new_cmd, EV_READ | EV_PERSIST,
                      DATA_BUFFER_SIZE, tcp_transport);

    return false;
}

/**
 * Ship tap log to the other end. This state differs with all other states
 * in the way that it support full duplex dialog. We're listening to both read
 * and write events from libevent most of the time. If a read event occurs we
 * switch to the conn_read state to read and execute the input message (that would
 * be an ack message from the other side). If a write event occurs we continue to
 * send tap log to the other end.
 * @param c the tap connection to drive
 * @return true if we should continue to process work for this connection, false
 *              if we should start processing events for other connections.
 */
bool conn_ship_log(conn *c) {
    bool cont = false;

    if (c->pending_close.active) {
        // Remove the event if it is present..
        event_del(&c->event);
        return false;
    }

    short mask = EV_READ | EV_PERSIST | EV_WRITE;

    if (c->which & EV_READ) {
        if (c->rbytes > 0) {
            if (try_read_command(c) == 0) {
                conn_set_state(c, conn_read);
            }
        } else {
            conn_set_state(c, conn_read);
        }

        // we're going to process something.. let's proceed
        cont = true;
    } else if (c->which & EV_WRITE) {
        --c->nevents;
        if (c->nevents >= 0) {
            LOCK_THREAD(c->thread);
            c->ewouldblock = false;
            ship_tap_log(c);
            if (c->ewouldblock) {
                mask = EV_READ | EV_PERSIST;
            } else {
                cont = true;
            }
            UNLOCK_THREAD(c->thread);
        }
    }

    if (!update_event(c, mask)) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO,
                                            c, "Couldn't update event\n");
        }
        conn_set_state(c, conn_closing);
    }

    return cont;
}

bool conn_waiting(conn *c) {
    if (!update_event(c, EV_READ | EV_PERSIST)) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                            "Couldn't update event\n");
        }
        conn_set_state(c, conn_closing);
        return true;
    }
    conn_set_state(c, conn_read);
    return false;
}

bool conn_read(conn *c) {
    int res = IS_UDP(c->transport) ? try_read_udp(c) : try_read_network(c);
    switch (res) {
    case READ_NO_DATA_RECEIVED:
        conn_set_state(c, conn_waiting);
        break;
    case READ_DATA_RECEIVED:
        conn_set_state(c, conn_parse_cmd);
        break;
    case READ_ERROR:
        conn_set_state(c, conn_closing);
        break;
    case READ_MEMORY_ERROR: /* Failed to allocate more memory */
        /* State already set by try_read_network */
        break;
    }

    return true;
}

bool conn_parse_cmd(conn *c) {
    if (try_read_command(c) == 0) {
        /* wee need more data! */
        conn_set_state(c, conn_waiting);
    }

    return true;
}

bool conn_new_cmd(conn *c) {
    /* Only process nreqs at a time to avoid starving other connections */
    --c->nevents;
    if (c->nevents >= 0) {
        reset_cmd_handler(c);
    } else {
        STATS_NOKEY(c, conn_yields);
        if (c->rbytes > 0) {
            /* We have already read in data into the input buffer,
               so libevent will most likely not signal read events
               on the socket (unless more data is available. As a
               hack we should just put in a request to write data,
               because that should be possible ;-)
            */
            if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                if (settings.verbose > 0) {
                    settings.extensions.logger->log(EXTENSION_LOG_INFO,
                                                    c, "Couldn't update event\n");
                }
                conn_set_state(c, conn_closing);
                return true;
            }
        }
        return false;
    }

    return true;
}


bool conn_swallow(conn *c) {
    ssize_t res;
    /* we are reading sbytes and throwing them away */
    if (c->sbytes == 0) {
        conn_set_state(c, conn_new_cmd);
        return true;
    }

    /* first check if we have leftovers in the conn_read buffer */
    if (c->rbytes > 0) {
        int tocopy = c->rbytes > c->sbytes ? c->sbytes : c->rbytes;
        c->sbytes -= tocopy;
        c->rcurr += tocopy;
        c->rbytes -= tocopy;
        return true;
    }

    /*  now try reading from the socket */
    res = read(c->sfd, c->rbuf, c->rsize > c->sbytes ? c->sbytes : c->rsize);
    if (res > 0) {
        STATS_ADD(c, bytes_read, res);
        c->sbytes -= res;
        return true;
    }
    if (res == 0) { /* end of stream */
        conn_set_state(c, conn_closing);
        return true;
    }
    if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        if (!update_event(c, EV_READ | EV_PERSIST)) {
            if (settings.verbose > 0) {
                settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                                "Couldn't update event\n");
            }
            conn_set_state(c, conn_closing);
            return true;
        }
        return false;
    }
    /* otherwise we have a real error, on which we close the connection */
    settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                    "Failed to read, and not due to blocking\n");
    conn_set_state(c, conn_closing);
    return true;

}

bool conn_nread(conn *c) {
    ssize_t res;

    if (c->rlbytes == 0) {
        LIBEVENT_THREAD *t = c->thread;
        LOCK_THREAD(t);
        bool block = c->ewouldblock = false;
        complete_nread(c);
        UNLOCK_THREAD(t);
        /* Breaking this into two, as complete_nread may have
           moved us to a different thread */
        t = c->thread;
        LOCK_THREAD(t);
        if (c->ewouldblock) {
            event_del(&c->event);
            block = true;
        }
        UNLOCK_THREAD(t);
        return !block;
    }
    /* first check if we have leftovers in the conn_read buffer */
    if (c->rbytes > 0) {
        int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
        if (c->ritem != c->rcurr) {
            memmove(c->ritem, c->rcurr, tocopy);
        }
        c->ritem += tocopy;
        c->rlbytes -= tocopy;
        c->rcurr += tocopy;
        c->rbytes -= tocopy;
        if (c->rlbytes == 0) {
            return true;
        }
    }

    /*  now try reading from the socket */
    res = read(c->sfd, c->ritem, c->rlbytes);
    if (res > 0) {
        STATS_ADD(c, bytes_read, res);
        if (c->rcurr == c->ritem) {
            c->rcurr += res;
        }
        c->ritem += res;
        c->rlbytes -= res;
        return true;
    }
    if (res == 0) { /* end of stream */
        conn_set_state(c, conn_closing);
        return true;
    }
    if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        if (!update_event(c, EV_READ | EV_PERSIST)) {
            if (settings.verbose > 0) {
                settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                                "Couldn't update event\n");
            }
            conn_set_state(c, conn_closing);
            return true;
        }
        return false;
    }

    /* otherwise we have a real error, on which we close the connection */
    settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                    "Failed to read, and not due to blocking:\n"
                                    "errno: %d %s \n"
                                    "rcurr=%lx ritem=%lx rbuf=%lx rlbytes=%d rsize=%d\n",
                                    errno, strerror(errno),
                                    (long)c->rcurr, (long)c->ritem, (long)c->rbuf,
                                    (int)c->rlbytes, (int)c->rsize);

    conn_set_state(c, conn_closing);
    return true;
}

bool conn_write(conn *c) {
    /*
     * We want to write out a simple response. If we haven't already,
     * assemble it into a msgbuf list (this will be a single-entry
     * list for TCP or a two-entry list for UDP).
     */
    if (c->iovused == 0 || (IS_UDP(c->transport) && c->iovused == 1)) {
        if (add_iov(c, c->wcurr, c->wbytes) != 0) {
            if (settings.verbose > 0) {
                settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                                "Couldn't build response\n");
            }
            conn_set_state(c, conn_closing);
            return true;
        }
    }

    return conn_mwrite(c);
}

bool conn_mwrite(conn *c) {
    if (IS_UDP(c->transport) && c->msgcurr == 0 && build_udp_headers(c) != 0) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                            "Failed to build UDP headers\n");
        }
        conn_set_state(c, conn_closing);
        return true;
    }

    switch (transmit(c)) {
    case TRANSMIT_COMPLETE:
        if (c->state == conn_mwrite) {
            while (c->ileft > 0) {
                item *it = *(c->icurr);
                settings.engine.v1->release(settings.engine.v0, c, it);
                c->icurr++;
                c->ileft--;
            }
            while (c->suffixleft > 0) {
                char *suffix = *(c->suffixcurr);
                cache_free(c->thread->suffix_cache, suffix);
                c->suffixcurr++;
                c->suffixleft--;
            }
            /* XXX:  I don't know why this wasn't the general case */
            if(c->protocol == binary_prot) {
                conn_set_state(c, c->write_and_go);
            } else {
                conn_set_state(c, conn_new_cmd);
            }
        } else if (c->state == conn_write) {
            if (c->write_and_free) {
                free(c->write_and_free);
                c->write_and_free = 0;
            }
            conn_set_state(c, c->write_and_go);
        } else {
            if (settings.verbose > 0) {
                settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                                                "Unexpected state %d\n", c->state);
            }
            conn_set_state(c, conn_closing);
        }
        break;

    case TRANSMIT_INCOMPLETE:
    case TRANSMIT_HARD_ERROR:
        break;                   /* Continue in state machine. */

    case TRANSMIT_SOFT_ERROR:
        return false;
    }

    return true;
}

bool conn_pending_close(conn *c) {
    assert(!c->pending_close.active);
    assert(c->sfd != -1);
    settings.extensions.logger->log(EXTENSION_LOG_WARNING, c,
                                    "Tap client connect closed (%d)."
                                    " Putting it (%p) in pending close\n",
                                    c->sfd, (void*)c);
    LOCK_THREAD(c->thread);
    c->pending_close.timeout = current_time + 5;
    c->pending_close.active = true;
    c->thread->pending_io = list_remove(c->thread->pending_io, c);
    if (!list_contains(c->thread->pending_close, c)) {
        c->next = c->thread->pending_close;
        c->thread->pending_close = c;
    }
    assert(!has_cycle(c->thread->pending_close));
    assert(list_contains(c->thread->pending_close, c));
    UNLOCK_THREAD(c->thread);

    // We don't want any network notifications anymore..
    event_del(&c->event);
    safe_close(c->sfd);
    c->sfd = -1;

    /*
     * tell the tap connection that we're disconnecting it now,
     * but give it a grace period
     */
    perform_callbacks(ON_DISCONNECT, NULL, c);

    /* disconnect callback may have changed the state for the object
     * so we might complete the disconnect now
     */
    return c->state != conn_pending_close;
}

bool conn_immediate_close(conn *c) {
    if (IS_UDP(c->transport)) {
        conn_cleanup(c);
    } else {
        conn_close(c);
    }

    return false;
}

bool conn_closing(conn *c) {
    assert(c->thread->type == TAP || c->thread->type == GENERAL);
    if (c->thread == &tap_thread) {
        conn_set_state(c, conn_pending_close);
    } else {
        conn_set_state(c, conn_immediate_close);
    }

    return true;
}

bool conn_add_tap_client(conn *c) {
    LIBEVENT_THREAD *tp = &tap_thread;
    c->ewouldblock = true;

    event_del(&c->event);

    LOCK_THREAD(tp);
    c->ev_flags = 0;
    conn_set_state(c, conn_setup_tap_stream);
    settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                    "Moving %d conn from %p to %p\n",
                                    c->sfd, c->thread, tp);
    c->thread = tp;
    c->event.ev_base = tp->base;
    assert(c->next == NULL);
    c->next = tp->pending_io;
    tp->pending_io = c;
    assert(!has_cycle(c));
    assert(number_of_pending(c, tp->pending_io) == 1);
    UNLOCK_THREAD(tp);

    if (write(tp->notify_send_fd, "", 1) != 1) {
        perror("Writing to tap thread notify pipe");
    }

    return false;
}

bool conn_setup_tap_stream(conn *c) {
    process_bin_tap_connect(c);
    return true;
}

void event_handler(const int fd, const short which, void *arg) {
    conn *c;

    c = (conn *)arg;
    assert(c != NULL);

    if (memcached_shutdown) {
        event_base_loopbreak(c->event.ev_base);
        return ;
    }

    c->which = which;

    /* sanity */
    if (fd != c->sfd) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_INFO, c,
                    "Catastrophic: event fd doesn't match conn fd!\n");
        }
        conn_close(c);
        return;
    }

    perform_callbacks(ON_SWITCH_CONN, c, c);

    c->nevents = settings.reqs_per_event;
    if (c->state == conn_ship_log) {
        c->nevents = settings.reqs_per_tap_event;
    }

    // Do we have pending closes?
    const size_t max_items = 256;
    conn *pending_close[max_items];
    size_t n_pending_close = 0;
    if (c->thread != NULL) {
        LIBEVENT_THREAD *me = c->thread;
        LOCK_THREAD(me);
        if (me->pending_close && me->last_checked != current_time) {
            assert(!has_cycle(me->pending_close));
            me->last_checked = current_time;

            n_pending_close = list_to_array(pending_close, max_items,
                                            &me->pending_close);
        }
        UNLOCK_THREAD(me);
    }

    while (c->state(c)) {
        /* do task */
    }

    /* Close any connections pending close */
    if (n_pending_close > 0) {
        for (size_t i = 0; i < n_pending_close; ++i) {
            conn *ce = pending_close[i];
            if (ce->pending_close.timeout < current_time) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                                "OK, time to nuke: %p: (%d)\n", (void*)ce,
                                                ce->sfd);
                conn_close(ce);
            } else {
                LOCK_THREAD(ce->thread);
                ce->next = ce->thread->pending_close;
                ce->thread->pending_close = ce;
                assert(!has_cycle(ce->thread->pending_close));
                UNLOCK_THREAD(ce->thread);
            }
        }
    }
}

static int new_socket(struct addrinfo *ai) {
    int sfd;
    int flags;

    if ((sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        safe_close(sfd);
        return -1;
    }
    return sfd;
}


/*
 * Sets a socket's send buffer size to the maximum allowed by the system.
 */
static void maximize_sndbuf(const int sfd) {
    socklen_t intsize = sizeof(int);
    int last_good = 0;
    int min, max, avg;
    int old_size;

    /* Start with the default size. */
    if (getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, (void *)&old_size, &intsize) != 0) {
        if (settings.verbose > 0)
            perror("getsockopt(SO_SNDBUF)");
        return;
    }

    /* Binary-search for the real maximum. */
    min = old_size;
    max = MAX_SENDBUF_SIZE;

    while (min <= max) {
        avg = ((unsigned int)(min + max)) / 2;
        if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, (void *)&avg, intsize) == 0) {
            last_good = avg;
            min = avg + 1;
        } else {
            max = avg - 1;
        }
    }

    if (settings.verbose > 1) {
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                 "<%d send buffer was %d, now %d\n", sfd, old_size, last_good);
    }
}



/**
 * Create a socket and bind it to a specific port number
 * @param port the port number to bind to
 * @param transport the transport protocol (TCP / UDP)
 * @param portnumber_file A filepointer to write the port numbers to
 *        when they are successfully added to the list of ports we
 *        listen on.
 */
static int server_socket(int port, enum network_transport transport,
                         FILE *portnumber_file) {
    int sfd;
    struct linger ling = {0, 0};
    struct addrinfo *ai;
    struct addrinfo *next;
    struct addrinfo hints = { .ai_flags = AI_PASSIVE,
                              .ai_family = AF_UNSPEC };
    char port_buf[NI_MAXSERV];
    int error;
    int success = 0;
    int flags =1;

    hints.ai_socktype = IS_UDP(transport) ? SOCK_DGRAM : SOCK_STREAM;

    if (port == -1) {
        port = 0;
    }
    snprintf(port_buf, sizeof(port_buf), "%d", port);
    error= getaddrinfo(settings.inter, port_buf, &hints, &ai);
    if (error != 0) {
        if (error != EAI_SYSTEM) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                     "getaddrinfo(): %s\n", gai_strerror(error));
        } else {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                     "getaddrinfo(): %s\n", strerror(error));
        }
        return 1;
    }

    for (next= ai; next; next= next->ai_next) {
        conn *listen_conn_add;
        if ((sfd = new_socket(next)) == -1) {
            /* getaddrinfo can return "junk" addresses,
             * we make sure at least one works before erroring.
             */
            continue;
        }

#ifdef IPV6_V6ONLY
        if (next->ai_family == AF_INET6) {
            error = setsockopt(sfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &flags, sizeof(flags));
            if (error != 0) {
                perror("setsockopt");
                safe_close(sfd);
                continue;
            }
        }
#endif

        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
        if (IS_UDP(transport)) {
            maximize_sndbuf(sfd);
        } else {
            error = setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
            if (error != 0)
                perror("setsockopt");

            error = setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));
            if (error != 0)
                perror("setsockopt");

            error = setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
            if (error != 0)
                perror("setsockopt");
        }

        if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1) {
            if (errno != EADDRINUSE) {
                perror("bind()");
                safe_close(sfd);
                freeaddrinfo(ai);
                return 1;
            }
            safe_close(sfd);
            continue;
        } else {
            success++;
            if (!IS_UDP(transport) && listen(sfd, settings.backlog) == -1) {
                perror("listen()");
                safe_close(sfd);
                freeaddrinfo(ai);
                return 1;
            }
            if (portnumber_file != NULL &&
                (next->ai_addr->sa_family == AF_INET ||
                 next->ai_addr->sa_family == AF_INET6)) {
                union {
                    struct sockaddr_in in;
                    struct sockaddr_in6 in6;
                } my_sockaddr;
                socklen_t len = sizeof(my_sockaddr);
                if (getsockname(sfd, (struct sockaddr*)&my_sockaddr, &len)==0) {
                    if (next->ai_addr->sa_family == AF_INET) {
                        fprintf(portnumber_file, "%s INET: %u\n",
                                IS_UDP(transport) ? "UDP" : "TCP",
                                ntohs(my_sockaddr.in.sin_port));
                    } else {
                        fprintf(portnumber_file, "%s INET6: %u\n",
                                IS_UDP(transport) ? "UDP" : "TCP",
                                ntohs(my_sockaddr.in6.sin6_port));
                    }
                }
            }
        }

        if (IS_UDP(transport)) {
            int c;

            for (c = 0; c < settings.num_threads; c++) {
                /* this is guaranteed to hit all threads because we round-robin */
                dispatch_conn_new(sfd, conn_read, EV_READ | EV_PERSIST,
                                  UDP_READ_BUFFER_SIZE, transport);
                STATS_LOCK();
                ++stats.daemon_conns;
                STATS_UNLOCK();
            }
        } else {
            if (!(listen_conn_add = conn_new(sfd, conn_listening,
                                             EV_READ | EV_PERSIST, 1,
                                             transport, main_base, NULL))) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "failed to create listening connection\n");
                exit(EXIT_FAILURE);
            }
            listen_conn_add->next = listen_conn;
            listen_conn = listen_conn_add;
            STATS_LOCK();
            ++stats.daemon_conns;
            STATS_UNLOCK();
        }
    }

    freeaddrinfo(ai);

    /* Return zero iff we detected no errors in starting up connections */
    return success == 0;
}

static int new_socket_unix(void) {
    int sfd;
    int flags;

    if ((sfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket()");
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        safe_close(sfd);
        return -1;
    }
    return sfd;
}

/* this will probably not work on windows */
static int server_socket_unix(const char *path, int access_mask) {
    int sfd;
    struct linger ling = {0, 0};
    struct sockaddr_un addr;
    struct stat tstat;
    int flags =1;
    int old_umask;

    if (!path) {
        return 1;
    }

    if ((sfd = new_socket_unix()) == -1) {
        return 1;
    }

    /*
     * Clean up a previous socket file if we left it around
     */
    if (lstat(path, &tstat) == 0) {
        if (S_ISSOCK(tstat.st_mode))
            unlink(path);
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));

    /*
     * the memset call clears nonstandard fields in some impementations
     * that otherwise mess things up.
     */
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);
    assert(strcmp(addr.sun_path, path) == 0);
    old_umask = umask( ~(access_mask&0777));
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind()");
        safe_close(sfd);
        umask(old_umask);
        return 1;
    }
    umask(old_umask);
    if (listen(sfd, settings.backlog) == -1) {
        perror("listen()");
        safe_close(sfd);
        return 1;
    }
    if (!(listen_conn = conn_new(sfd, conn_listening,
                                 EV_READ | EV_PERSIST, 1,
                                 local_transport, main_base, NULL))) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                 "failed to create listening connection\n");
        exit(EXIT_FAILURE);
    }

    STATS_LOCK();
    ++stats.daemon_conns;
    STATS_UNLOCK();

    return 0;
}

static struct event clockevent;

/* time-sensitive callers can call it by hand with this, outside the normal ever-1-second timer */
static void set_current_time(void) {
    struct timeval timer;

    gettimeofday(&timer, NULL);
    current_time = (rel_time_t) (timer.tv_sec - process_started);
}

static void clock_handler(const int fd, const short which, void *arg) {
    struct timeval t = {.tv_sec = 1, .tv_usec = 0};
    static bool initialized = false;

    if (memcached_shutdown) {
        event_base_loopbreak(main_base);
        return ;
    }

    if (initialized) {
        /* only delete the event if it's actually there. */
        evtimer_del(&clockevent);
    } else {
        initialized = true;
    }

    evtimer_set(&clockevent, clock_handler, 0);
    event_base_set(main_base, &clockevent);
    evtimer_add(&clockevent, &t);

    set_current_time();
}

static void usage(void) {
    printf(PACKAGE " " VERSION "\n");
    printf("-p <num>      TCP port number to listen on (default: 11211)\n"
           "-U <num>      UDP port number to listen on (default: 11211, 0 is off)\n"
           "-s <file>     UNIX socket path to listen on (disables network support)\n"
           "-a <mask>     access mask for UNIX socket, in octal (default: 0700)\n"
           "-l <ip_addr>  interface to listen on (default: INADDR_ANY, all addresses)\n"
           "-d            run as a daemon\n"
           "-r            maximize core file limit\n"
           "-u <username> assume identity of <username> (only when run as root)\n"
           "-m <num>      max memory to use for items in megabytes (default: 64 MB)\n"
           "-M            return error on memory exhausted (rather than removing items)\n"
           "-c <num>      max simultaneous connections (default: 1024)\n"
           "-k            lock down all paged memory.  Note that there is a\n"
           "              limit on how much memory you may lock.  Trying to\n"
           "              allocate more than that would fail, so be sure you\n"
           "              set the limit correctly for the user you started\n"
           "              the daemon with (not for -u <username> user;\n"
           "              under sh this is done with 'ulimit -S -l NUM_KB').\n"
           "-v            verbose (print errors/warnings while in event loop)\n"
           "-vv           very verbose (also print client commands/reponses)\n"
           "-vvv          extremely verbose (also print internal state transitions)\n"
           "-h            print this help and exit\n"
           "-i            print memcached and libevent license\n"
           "-P <file>     save PID in <file>, only used with -d option\n"
           "-f <factor>   chunk size growth factor (default: 1.25)\n"
           "-n <bytes>    minimum space allocated for key+value+flags (default: 48)\n");
    printf("-L            Try to use large memory pages (if available). Increasing\n"
           "              the memory page size could reduce the number of TLB misses\n"
           "              and improve the performance. In order to get large pages\n"
           "              from the OS, memcached will allocate the total item-cache\n"
           "              in one large chunk.\n");
    printf("-D <char>     Use <char> as the delimiter between key prefixes and IDs.\n"
           "              This is used for per-prefix stats reporting. The default is\n"
           "              \":\" (colon). If this option is specified, stats collection\n"
           "              is turned on automatically; if not, then it may be turned on\n"
           "              by sending the \"stats detail on\" command to the server.\n");
    printf("-t <num>      number of threads to use (default: 4)\n");
    printf("-R            Maximum number of requests per event, limits the number of\n"
           "              requests process for a given connection to prevent \n"
           "              starvation (default: 20)\n");
    printf("-C            Disable use of CAS\n");
    printf("-b            Set the backlog queue limit (default: 1024)\n");
    printf("-B            Binding protocol - one of ascii, binary, or auto (default)\n");
    printf("-I            Override the size of each slab page. Adjusts max item size\n"
           "              (default: 1mb, min: 1k, max: 128m)\n");
    printf("-q            Disable detailed stats commands\n");
#ifdef SASL_ENABLED
    printf("-S            Require SASL authentication\n");
#endif
    printf("-X module,cfg Load the module and initialize it with the config\n");
    printf("-O ip:port    Tap ip:port\n");
    printf("\nEnvironment variables:\n"
           "MEMCACHED_PORT_FILENAME   File to write port information to\n"
           "MEMCACHED_TOP_KEYS        Number of top keys to keep track of\n"
           "MEMCACHED_REQS_TAP_EVENT  Similar to -R but for tap_ship_log\n");
}

static void usage_license(void) {
    printf(PACKAGE " " VERSION "\n\n");
    printf(
    "Copyright (c) 2003, Danga Interactive, Inc. <http://www.danga.com/>\n"
    "All rights reserved.\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions are\n"
    "met:\n"
    "\n"
    "    * Redistributions of source code must retain the above copyright\n"
    "notice, this list of conditions and the following disclaimer.\n"
    "\n"
    "    * Redistributions in binary form must reproduce the above\n"
    "copyright notice, this list of conditions and the following disclaimer\n"
    "in the documentation and/or other materials provided with the\n"
    "distribution.\n"
    "\n"
    "    * Neither the name of the Danga Interactive nor the names of its\n"
    "contributors may be used to endorse or promote products derived from\n"
    "this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS\n"
    "\"AS IS\" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT\n"
    "LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR\n"
    "A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT\n"
    "OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,\n"
    "SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT\n"
    "LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
    "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
    "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
    "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE\n"
    "OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    "\n"
    "\n"
    "This product includes software developed by Niels Provos.\n"
    "\n"
    "[ libevent ]\n"
    "\n"
    "Copyright 2000-2003 Niels Provos <provos@citi.umich.edu>\n"
    "All rights reserved.\n"
    "\n"
    "Redistribution and use in source and binary forms, with or without\n"
    "modification, are permitted provided that the following conditions\n"
    "are met:\n"
    "1. Redistributions of source code must retain the above copyright\n"
    "   notice, this list of conditions and the following disclaimer.\n"
    "2. Redistributions in binary form must reproduce the above copyright\n"
    "   notice, this list of conditions and the following disclaimer in the\n"
    "   documentation and/or other materials provided with the distribution.\n"
    "3. All advertising materials mentioning features or use of this software\n"
    "   must display the following acknowledgement:\n"
    "      This product includes software developed by Niels Provos.\n"
    "4. The name of the author may not be used to endorse or promote products\n"
    "   derived from this software without specific prior written permission.\n"
    "\n"
    "THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR\n"
    "IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES\n"
    "OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.\n"
    "IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,\n"
    "INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT\n"
    "NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,\n"
    "DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY\n"
    "THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT\n"
    "(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF\n"
    "THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.\n"
    );

    return;
}

static void save_pid(const pid_t pid, const char *pid_file) {
    FILE *fp;
    if (pid_file == NULL) {
        return;
    }

    if ((fp = fopen(pid_file, "w")) == NULL) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                 "Could not open the pid file %s for writing: %s\n",
                 pid_file, strerror(errno));
        return;
    }

    fprintf(fp,"%ld\n", (long)pid);
    if (fclose(fp) == -1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "Could not close the pid file %s: %s\n",
                pid_file, strerror(errno));
    }
}

static void remove_pidfile(const char *pid_file) {
    if (pid_file != NULL) {
        if (unlink(pid_file) != 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Could not remove the pid file %s: %s\n",
                    pid_file, strerror(errno));
        }
    }
}

#ifndef HAVE_SIGIGNORE
static int sigignore(int sig) {
    struct sigaction sa = { .sa_handler = SIG_IGN, .sa_flags = 0 };

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(sig, &sa, 0) == -1) {
        return -1;
    }
    return 0;
}
#endif /* !HAVE_SIGIGNORE */

static void sigterm_handler(int sig) {
    assert(sig == SIGTERM || sig == SIGINT);
    memcached_shutdown = 1;
}

static int install_sigterm_handler(void) {
    struct sigaction sa = {.sa_handler = sigterm_handler, .sa_flags = 0};

    if (sigemptyset(&sa.sa_mask) == -1 || sigaction(SIGTERM, &sa, 0) == -1 ||
        sigaction(SIGINT, &sa, 0) == -1) {
        return -1;
    }

    return 0;
}

/*
 * On systems that supports multiple page sizes we may reduce the
 * number of TLB-misses by using the biggest available page size
 */
static int enable_large_pages(void) {
#if defined(HAVE_GETPAGESIZES) && defined(HAVE_MEMCNTL)
    int ret = -1;
    size_t sizes[32];
    int avail = getpagesizes(sizes, 32);
    if (avail != -1) {
        size_t max = sizes[0];
        struct memcntl_mha arg = {0};
        int ii;

        for (ii = 1; ii < avail; ++ii) {
            if (max < sizes[ii]) {
                max = sizes[ii];
            }
        }

        arg.mha_flags   = 0;
        arg.mha_pagesize = max;
        arg.mha_cmd = MHA_MAPSIZE_BSSBRK;

        if (memcntl(0, 0, MC_HAT_ADVISE, (caddr_t)&arg, 0, 0) == -1) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                  "Failed to set large pages: %s\nWill use default page size\n",
                  strerror(errno));
        } else {
            ret = 0;
        }
    } else {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
          "Failed to get supported pagesizes: %s\nWill use default page size\n",
          strerror(errno));
    }

    return ret;
#else
    return 0;
#endif
}

static const char* get_server_version(void) {
    return VERSION;
}

static void store_engine_specific(const void *cookie,
                                  void *engine_data) {
    conn *c = (conn*)cookie;
    c->engine_storage = engine_data;
}

static void *get_engine_specific(const void *cookie) {
    conn *c = (conn*)cookie;
    return c->engine_storage;
}

static int get_socket_fd(const void *cookie) {
    conn *c = (conn *)cookie;
    return c->sfd;
}

static int num_independent_stats(void) {
    return settings.num_threads + 1;
}

static void *new_independent_stats(void) {
    int ii;
    int nrecords = num_independent_stats();
    struct independent_stats *independent_stats = calloc(sizeof(independent_stats) + sizeof(struct thread_stats) * nrecords, 1);
    if (settings.topkeys > 0)
        independent_stats->topkeys = topkeys_init(settings.topkeys);
    for (ii = 0; ii < nrecords; ii++)
        pthread_mutex_init(&independent_stats->thread_stats[ii].mutex, NULL);
    return independent_stats;
}

static void release_independent_stats(void *stats) {
    int ii;
    int nrecords = num_independent_stats();
    struct independent_stats *independent_stats = stats;
    if (independent_stats->topkeys)
        topkeys_free(independent_stats->topkeys);
    for (ii = 0; ii < nrecords; ii++)
        pthread_mutex_destroy(&independent_stats->thread_stats[ii].mutex);
    free(independent_stats);
}

static inline struct independent_stats *get_independent_stats(conn *c) {
    struct independent_stats *independent_stats;
    if (settings.engine.v1->get_stats_struct != NULL) {
        independent_stats = settings.engine.v1->get_stats_struct(settings.engine.v0, (const void *)c);
        if (independent_stats == NULL)
            independent_stats = default_independent_stats;
    } else {
        independent_stats = default_independent_stats;
    }
    return independent_stats;
}

static inline struct thread_stats *get_thread_stats(conn *c) {
    struct independent_stats *independent_stats = get_independent_stats(c);
    assert(c->thread->index < num_independent_stats());
    return &independent_stats->thread_stats[c->thread->index];
}

static void register_callback(ENGINE_HANDLE *eh,
                              ENGINE_EVENT_TYPE type,
                              EVENT_CALLBACK cb, const void *cb_data) {
    struct engine_event_handler *h =
        calloc(sizeof(struct engine_event_handler), 1);

    assert(h);
    h->cb = cb;
    h->cb_data = cb_data;
    h->next = engine_event_handlers[type];
    engine_event_handlers[type] = h;
}

static rel_time_t get_current_time(void)
{
    return current_time;
}

static void count_eviction(const void *cookie, const void *key, const int nkey) {
    topkeys_t *tk = get_independent_stats((conn*)cookie)->topkeys;
    TK(tk, evictions, key, nkey, get_current_time());
}

/**
 * To make it easy for engine implementors that doesn't want to care about
 * writing their own incr/decr code, they can just set the arithmetic function
 * to NULL and use this implementation. It is not efficient, due to the fact
 * that it does multiple calls through the interface (get and then cas store).
 * If you don't care, feel free to use it..
 */
static ENGINE_ERROR_CODE internal_arithmetic(ENGINE_HANDLE* handle,
                                             const void* cookie,
                                             const void* key,
                                             const int nkey,
                                             const bool increment,
                                             const bool create,
                                             const uint64_t delta,
                                             const uint64_t initial,
                                             const rel_time_t exptime,
                                             uint64_t *cas,
                                             uint64_t *result,
                                             uint16_t vbucket)
{
    ENGINE_HANDLE_V1 *e = (ENGINE_HANDLE_V1*)handle;

    item *it = NULL;

    ENGINE_ERROR_CODE ret;
    ret = e->get(handle, cookie, &it, key, nkey, vbucket);

    if (ret == ENGINE_SUCCESS) {
        item_info info = { .nvalue = 1 };

        if (!e->get_item_info(handle, cookie, it, &info)) {
            e->release(handle, cookie, it);
            return ENGINE_FAILED;
        }

        /* Ensure that we don't run away into random memory */
        char *endptr = info.value[0].iov_base;
        int ii;
        for (ii = 0; ii < info.value[0].iov_len; ++ii) {
            if (isdigit(endptr[ii]) == 0) {
                break;
            }
        }

        uint64_t val;
        if (ii == info.value[0].iov_len || !safe_strtoull((const char*)info.value[0].iov_base, &val)) {
            e->release(handle, cookie, it);
            return ENGINE_EINVAL;
        }

        if (increment) {
            val += delta;
        } else {
            if (delta > val) {
                val = 0;
            } else {
                val -= delta;
            }
        }

        char value[80];
        size_t nb = snprintf(value, sizeof(value), "%"PRIu64"\r\n", val);
        *result = val;
        item *nit = NULL;
        if (e->allocate(handle, cookie, &nit, key,
                        nkey, nb, info.flags, info.exptime) != ENGINE_SUCCESS) {
            e->release(handle, cookie, it);
            return ENGINE_ENOMEM;
        }

        item_info i2 = { .nvalue = 1 };
        if (!e->get_item_info(handle, cookie, nit, &i2)) {
            e->release(handle, cookie, it);
            e->release(handle, cookie, nit);
            return ENGINE_FAILED;
        }

        memcpy(i2.value[0].iov_base, value, nb);
        e->item_set_cas(handle, cookie, nit, info.cas);
        ret = e->store(handle, cookie, nit, cas, OPERATION_CAS, vbucket);
        e->release(handle, cookie, it);
        e->release(handle, cookie, nit);
    } else if (ret == ENGINE_KEY_ENOENT && create) {
        char value[80];
        size_t nb = snprintf(value, sizeof(value), "%"PRIu64"\r\n", initial);
        *result = initial;
        if (e->allocate(handle, cookie, &it, key, nkey, nb, 0, exptime) != ENGINE_SUCCESS) {
            e->release(handle, cookie, it);
            return ENGINE_ENOMEM;
        }

        item_info info = { .nvalue = 1 };
        if (!e->get_item_info(handle, cookie, it, &info)) {
            e->release(handle, cookie, it);
            return ENGINE_FAILED;
        }

        memcpy(info.value[0].iov_base, value, nb);
        ret = e->store(handle, cookie, it, cas, OPERATION_CAS, vbucket);
        e->release(handle, cookie, it);
    }

    /* We had a race condition.. just call ourself recursively to retry */
    if (ret == ENGINE_KEY_EEXISTS) {
        return internal_arithmetic(handle, cookie, key, nkey, increment, create, delta,
                                   initial, exptime, cas, result, vbucket);
    }

    return ret;
}

/**
 * Register an extension if it's not already registered
 *
 * @param type the type of the extension to register
 * @param extension the extension to register
 * @return true if success, false otherwise
 */
static bool register_extension(extension_type_t type, void *extension)
{
    if (extension == NULL) {
        return false;
    }

    switch (type) {
    case EXTENSION_DAEMON:
        for (EXTENSION_DAEMON_DESCRIPTOR *ptr = settings.extensions.daemons;
             ptr != NULL;
             ptr = ptr->next) {
            if (ptr == extension) {
                return false;
            }
        }
        ((EXTENSION_DAEMON_DESCRIPTOR *)(extension))->next = settings.extensions.daemons;
        settings.extensions.daemons = extension;
        return true;
    case EXTENSION_LOGGER:
        settings.extensions.logger = extension;
        return true;
    case EXTENSION_ASCII_PROTOCOL:
        if (settings.extensions.ascii != NULL) {
            EXTENSION_ASCII_PROTOCOL_DESCRIPTOR *last;
            for (last = settings.extensions.ascii; last->next != NULL;
                 last = last->next) {
                if (last == extension) {
                    return false;
                }
            }
            if (last == extension) {
                return false;
            }
            last->next = extension;
            last->next->next = NULL;
        } else {
            settings.extensions.ascii = extension;
            settings.extensions.ascii->next = NULL;
        }
        return true;

    default:
        return false;
    }
}

/**
 * Unregister an extension
 *
 * @param type the type of the extension to remove
 * @param extension the extension to remove
 */
static void unregister_extension(extension_type_t type, void *extension)
{
    switch (type) {
    case EXTENSION_DAEMON:
        {
            EXTENSION_DAEMON_DESCRIPTOR *prev = NULL;
            EXTENSION_DAEMON_DESCRIPTOR *ptr = settings.extensions.daemons;

            while (ptr != NULL && ptr != extension) {
                prev = ptr;
                ptr = ptr->next;
            }

            if (ptr != NULL && prev != NULL) {
                prev->next = ptr->next;
            }

            if (settings.extensions.daemons == ptr) {
                settings.extensions.daemons = ptr->next;
            }
        }
        break;
    case EXTENSION_LOGGER:
        if (settings.extensions.logger == extension) {
            if (get_stderr_logger() == extension) {
                settings.extensions.logger = get_null_logger();
            } else {
                settings.extensions.logger = get_stderr_logger();
            }
        }
        break;
    case EXTENSION_ASCII_PROTOCOL:
        {
            EXTENSION_ASCII_PROTOCOL_DESCRIPTOR *prev = NULL;
            EXTENSION_ASCII_PROTOCOL_DESCRIPTOR *ptr = settings.extensions.ascii;

            while (ptr != NULL && ptr != extension) {
                prev = ptr;
                ptr = ptr->next;
            }

            if (ptr != NULL && prev != NULL) {
                prev->next = ptr->next;
            }

            if (settings.extensions.ascii == ptr) {
                settings.extensions.ascii = ptr->next;
            }
        }
        break;

    default:
        ;
    }

}

/**
 * Get the named extension
 */
static void* get_extension(extension_type_t type)
{
    switch (type) {
    case EXTENSION_DAEMON:
        return settings.extensions.daemons;

    case EXTENSION_LOGGER:
        return settings.extensions.logger;

    case EXTENSION_ASCII_PROTOCOL:
        return settings.extensions.ascii;

    default:
        return NULL;
    }
}

static void shutdown_server(void) {
    memcached_shutdown = 1;
}

static EXTENSION_LOGGER_DESCRIPTOR* get_logger(void)
{
    return settings.extensions.logger;
}

static EXTENSION_LOG_LEVEL get_log_level(void)
{
    EXTENSION_LOG_LEVEL ret;
    switch (settings.verbose) {
    case 0: ret = EXTENSION_LOG_WARNING; break;
    case 1: ret = EXTENSION_LOG_INFO; break;
    case 2: ret = EXTENSION_LOG_DEBUG; break;
    default:
        ret = EXTENSION_LOG_DETAIL;
    }
    return ret;
}

static void set_log_level(EXTENSION_LOG_LEVEL severity)
{
    switch (severity) {
    case EXTENSION_LOG_WARNING: settings.verbose = 0; break;
    case EXTENSION_LOG_INFO: settings.verbose = 1; break;
    case EXTENSION_LOG_DEBUG: settings.verbose = 2; break;
    default:
        settings.verbose = 3;
    }
}

/**
 * Callback the engines may call to get the public server interface
 * @return pointer to a structure containing the interface. The client should
 *         know the layout and perform the proper casts.
 */
static SERVER_HANDLE_V1 *get_server_api(void)
{
    static SERVER_CORE_API core_api = {
        .get_auth_data = get_auth_data,
        .store_engine_specific = store_engine_specific,
        .get_engine_specific = get_engine_specific,
        .get_socket_fd = get_socket_fd,
        .server_version = get_server_version,
        .hash = hash,
        .realtime = realtime,
        .notify_io_complete = notify_io_complete,
        .get_current_time = get_current_time,
        .parse_config = parse_config,
        .shutdown = shutdown_server
    };

    static SERVER_STAT_API server_stat_api = {
        .new_stats = new_independent_stats,
        .release_stats = release_independent_stats,
        .evicting = count_eviction
    };

    static SERVER_LOG_API server_log_api = {
        .get_logger = get_logger,
        .get_level = get_log_level,
        .set_level = set_log_level
    };

    static SERVER_EXTENSION_API extension_api = {
        .register_extension = register_extension,
        .unregister_extension = unregister_extension,
        .get_extension = get_extension
    };

    static SERVER_CALLBACK_API callback_api = {
        .register_callback = register_callback,
        .perform_callbacks = perform_callbacks,
    };

    static SERVER_HANDLE_V1 rv = {
        .interface = 1,
        .core = &core_api,
        .stat = &server_stat_api,
        .extension = &extension_api,
        .callback = &callback_api,
        .log = &server_log_api
    };

    if (rv.engine == NULL) {
        rv.engine = settings.engine.v0;
    }

    return &rv;
}

/**
 * Load a shared object and initialize all the extensions in there.
 *
 * @param soname the name of the shared object (may not be NULL)
 * @param config optional configuration parameters
 * @return true if success, false otherwise
 */
static bool load_extension(const char *soname, const char *config) {
    if (soname == NULL) {
        return false;
    }

    /* Hack to remove the warning from C99 */
    union my_hack {
        MEMCACHED_EXTENSIONS_INITIALIZE initialize;
        void* voidptr;
    } funky = {.initialize = NULL };

    void *handle = dlopen(soname, RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        const char *msg = dlerror();
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "Failed to open library \"%s\": %s\n",
                soname, msg ? msg : "unknown error");
        return false;
    }

    void *symbol = dlsym(handle, "memcached_extensions_initialize");
    if (symbol == NULL) {
        const char *msg = dlerror();
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "Could not find symbol \"memcached_extensions_initialize\" in %s: %s\n",
                soname, msg ? msg : "unknown error");
        return false;
    }
    funky.voidptr = symbol;

    EXTENSION_ERROR_CODE error = (*funky.initialize)(config, get_server_api);

    if (error != EXTENSION_SUCCESS) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "Failed to initalize extensions from %s. Error code: %d\n",
                soname, error);
        dlclose(handle);
        return false;
    }

    if (settings.verbose > 0) {
        settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL,
                "Loaded extensions from: %s\n", soname);
    }

    return true;
}

/**
 * Do basic sanity check of the runtime environment
 * @return true if no errors found, false if we can't use this env
 */
static bool sanitycheck(void) {
    /* One of our biggest problems is old and bogus libevents */
    const char *ever = event_get_version();
    if (ever != NULL) {
        if (strncmp(ever, "1.", 2) == 0) {
            /* Require at least 1.3 (that's still a couple of years old) */
            if ((ever[2] == '1' || ever[2] == '2') && !isdigit(ever[3])) {
                fprintf(stderr, "You are using libevent %s.\nPlease upgrade to"
                        " a more recent version (1.3 or newer)\n",
                        event_get_version());
                return false;
            }
        }
    }

    return true;
}

int main (int argc, char **argv) {
    int c;
    bool lock_memory = false;
    bool do_daemonize = false;
    bool preallocate = false;
    int maxcore = 0;
    char *username = NULL;
    char *pid_file = NULL;
    struct passwd *pw;
    struct rlimit rlim;
    char unit = '\0';
    int size_max = 0;

    bool protocol_specified = false;
    bool tcp_specified = false;
    bool udp_specified = false;

    const char *engine = NULL;
    const char *engine_config = NULL;
    char old_options[1024] = { [0] = '\0' };
    char *old_opts = old_options;

    if (!sanitycheck()) {
        return EX_OSERR;
    }

    /* init settings */
    settings_init();

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    if (memcached_initialize_stderr_logger(get_server_api) != EXTENSION_SUCCESS) {
        fprintf(stderr, "Failed to initialize log system\n");
        return EX_OSERR;
    }

    /* process arguments */
    while (-1 != (c = getopt(argc, argv,
          "a:"  /* access mask for unix socket */
          "p:"  /* TCP port number to listen on */
          "s:"  /* unix socket path to listen on */
          "U:"  /* UDP port number to listen on */
          "m:"  /* max memory to use for items in megabytes */
          "M"   /* return error on memory exhausted */
          "c:"  /* max simultaneous connections */
          "k"   /* lock down all paged memory */
          "hi"  /* help, licence info */
          "r"   /* maximize core file limit */
          "v"   /* verbose */
          "d"   /* daemon mode */
          "l:"  /* interface to listen on */
          "u:"  /* user identity to run as */
          "P:"  /* save PID in file */
          "f:"  /* factor? */
          "n:"  /* minimum space allocated for key+value+flags */
          "t:"  /* threads */
          "D:"  /* prefix delimiter? */
          "L"   /* Large memory pages */
          "R:"  /* max requests per event */
          "C"   /* Disable use of CAS */
          "b:"  /* backlog queue limit */
          "B:"  /* Binding protocol */
          "I:"  /* Max item size */
          "S"   /* Sasl ON */
          "E:"  /* Engine to load */
          "e:"  /* Engine options */
          "q"   /* Disallow detailed stats */
          "X:"  /* Load extension */
        ))) {
        switch (c) {
        case 'a':
            /* access for unix domain socket, as octal mask (like chmod)*/
            settings.access= strtol(optarg,NULL,8);
            break;

        case 'U':
            settings.udpport = atoi(optarg);
            udp_specified = true;
            break;
        case 'p':
            settings.port = atoi(optarg);
            tcp_specified = true;
            break;
        case 's':
            settings.socketpath = optarg;
            break;
        case 'm':
            settings.maxbytes = ((size_t)atoi(optarg)) * 1024 * 1024;
             old_opts += sprintf(old_opts, "cache_size=%lu;",
                                 (unsigned long)settings.maxbytes);
           break;
        case 'M':
            settings.evict_to_free = 0;
            old_opts += sprintf(old_opts, "eviction=false;");
            break;
        case 'c':
            settings.maxconns = atoi(optarg);
            break;
        case 'h':
            usage();
            exit(EXIT_SUCCESS);
        case 'i':
            usage_license();
            exit(EXIT_SUCCESS);
        case 'k':
            lock_memory = true;
            break;
        case 'v':
            settings.verbose++;
            perform_callbacks(ON_LOG_LEVEL, NULL, NULL);
            break;
        case 'l':
            settings.inter= strdup(optarg);
            break;
        case 'd':
            do_daemonize = true;
            break;
        case 'r':
            maxcore = 1;
            break;
        case 'R':
            settings.reqs_per_event = atoi(optarg);
            if (settings.reqs_per_event == 0) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                      "Number of requests per event must be greater than 0\n");
                return 1;
            }
            break;
        case 'u':
            username = optarg;
            break;
        case 'P':
            pid_file = optarg;
            break;
        case 'f':
            settings.factor = atof(optarg);
            if (settings.factor <= 1.0) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Factor must be greater than 1\n");
                return 1;
            }
             old_opts += sprintf(old_opts, "factor=%f;",
                                 settings.factor);
           break;
        case 'n':
            settings.chunk_size = atoi(optarg);
            if (settings.chunk_size == 0) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Chunk size must be greater than 0\n");
                return 1;
            }
            old_opts += sprintf(old_opts, "chunk_size=%u;",
                                settings.chunk_size);
            break;
        case 't':
            settings.num_threads = atoi(optarg);
            if (settings.num_threads <= 0) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Number of threads must be greater than 0\n");
                return 1;
            }
            /* There're other problems when you get above 64 threads.
             * In the future we should portably detect # of cores for the
             * default.
             */
            if (settings.num_threads > 64) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "WARNING: Setting a high number of worker"
                        "threads is not recommended.\n"
                        " Set this value to the number of cores in"
                        " your machine or less.\n");
            }
            break;
        case 'D':
            settings.prefix_delimiter = optarg[0];
            settings.detail_enabled = 1;
            break;
        case 'L' :
            if (enable_large_pages() == 0) {
                preallocate = true;
                old_opts += sprintf(old_opts, "preallocate=true;");
            }
            break;
        case 'C' :
            settings.use_cas = false;
            break;
        case 'b' :
            settings.backlog = atoi(optarg);
            break;
        case 'B':
            protocol_specified = true;
            if (strcmp(optarg, "auto") == 0) {
                settings.binding_protocol = negotiating_prot;
            } else if (strcmp(optarg, "binary") == 0) {
                settings.binding_protocol = binary_prot;
            } else if (strcmp(optarg, "ascii") == 0) {
                settings.binding_protocol = ascii_prot;
            } else {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Invalid value for binding protocol: %s\n"
                        " -- should be one of auto, binary, or ascii\n", optarg);
                exit(EX_USAGE);
            }
            break;
        case 'I':
            unit = optarg[strlen(optarg)-1];
            if (unit == 'k' || unit == 'm' ||
                unit == 'K' || unit == 'M') {
                optarg[strlen(optarg)-1] = '\0';
                size_max = atoi(optarg);
                if (unit == 'k' || unit == 'K')
                    size_max *= 1024;
                if (unit == 'm' || unit == 'M')
                    size_max *= 1024 * 1024;
                settings.item_size_max = size_max;
            } else {
                settings.item_size_max = atoi(optarg);
            }
            if (settings.item_size_max < 1024) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Item max size cannot be less than 1024 bytes.\n");
                return 1;
            }
            if (settings.item_size_max > 1024 * 1024 * 128) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Cannot set item size limit higher than 128 mb.\n");
                return 1;
            }
            if (settings.item_size_max > 1024 * 1024) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "WARNING: Setting item max size above 1MB is not"
                    " recommended!\n"
                    " Raising this limit increases the minimum memory requirements\n"
                    " and will decrease your memory efficiency.\n"
                );
            }
#ifndef __WIN32__
            old_opts += sprintf(old_opts, "item_size_max=%zu;",
                                settings.item_size_max);
#else
            old_opts += sprintf(old_opts, "item_size_max=%lu;", (long unsigned)
                                settings.item_size_max);
#endif
            break;
        case 'E':
            engine = optarg;
            break;
        case 'e':
            engine_config = optarg;
            break;
        case 'q':
            settings.allow_detailed = false;
            break;
        case 'S': /* set Sasl authentication to true. Default is false */
#ifndef SASL_ENABLED
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "This server is not built with SASL support.\n");
            exit(EX_USAGE);
#endif
            settings.require_sasl = true;
            break;
        case 'X' :
            {
                char *ptr = strchr(optarg, ',');
                if (ptr != NULL) {
                    *ptr = '\0';
                    ++ptr;
                }
                if (!load_extension(optarg, ptr)) {
                    exit(EXIT_FAILURE);
                }
                if (ptr != NULL) {
                    *(ptr - 1) = ',';
                }
            }
            break;
        default:
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Illegal argument \"%c\"\n", c);
            return 1;
        }
    }

    if (getenv("MEMCACHED_REQS_TAP_EVENT") != NULL) {
        settings.reqs_per_tap_event = atoi(getenv("MEMCACHED_REQS_TAP_EVENT"));
    }

    if (settings.reqs_per_tap_event == 0) {
        settings.reqs_per_tap_event = DEFAULT_REQS_PER_TAP_EVENT;
    }


    if (install_sigterm_handler() != 0) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Failed to install SIGTERM handler\n");
        exit(EXIT_FAILURE);
    }

    char *topkeys_env = getenv("MEMCACHED_TOP_KEYS");
    if (topkeys_env != NULL) {
        settings.topkeys = atoi(topkeys_env);
        if (settings.topkeys < 0) {
            settings.topkeys = 0;
        }
    }

    if (settings.require_sasl) {
        if (!protocol_specified) {
            settings.binding_protocol = binary_prot;
        } else {
            if (settings.binding_protocol == negotiating_prot) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "ERROR: You cannot use auto-negotiating protocol while requiring SASL.\n");
                exit(EX_USAGE);
            }
            if (settings.binding_protocol == ascii_prot) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "ERROR: You cannot use only ASCII protocol while requiring SASL.\n");
                exit(EX_USAGE);
            }
        }
    }

    if (tcp_specified && !udp_specified) {
        settings.udpport = settings.port;
    } else if (udp_specified && !tcp_specified) {
        settings.port = settings.udpport;
    }

    if (engine_config != NULL && strlen(old_options) > 0) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "ERROR: You can't mix -e with the old options\n");
        return EX_USAGE;
    } else if (engine_config == NULL && strlen(old_options) > 0) {
        engine_config = old_options;
    }

    if (maxcore != 0) {
        struct rlimit rlim_new;
        /*
         * First try raising to infinity; if that fails, try bringing
         * the soft limit to the hard.
         */
        if (getrlimit(RLIMIT_CORE, &rlim) == 0) {
            rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
            if (setrlimit(RLIMIT_CORE, &rlim_new)!= 0) {
                /* failed. try raising just to the old max */
                rlim_new.rlim_cur = rlim_new.rlim_max = rlim.rlim_max;
                (void)setrlimit(RLIMIT_CORE, &rlim_new);
            }
        }
        /*
         * getrlimit again to see what we ended up with. Only fail if
         * the soft limit ends up 0, because then no core files will be
         * created at all.
         */

        if ((getrlimit(RLIMIT_CORE, &rlim) != 0) || rlim.rlim_cur == 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "failed to ensure corefile creation\n");
            exit(EX_OSERR);
        }
    }

    /*
     * If needed, increase rlimits to allow as many connections
     * as needed.
     */

    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "failed to getrlimit number of files\n");
        exit(EX_OSERR);
    } else {
        int maxfiles = settings.maxconns;
        if (rlim.rlim_cur < maxfiles)
            rlim.rlim_cur = maxfiles;
        if (rlim.rlim_max < rlim.rlim_cur)
            rlim.rlim_max = rlim.rlim_cur;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "failed to set rlimit for open files. Try running as"
                    " root or requesting smaller maxconns value.\n");
            exit(EX_OSERR);
        }
    }

    /* Sanity check for the connection structures */
    int nfiles = 0;
    if (settings.port != 0) {
        nfiles += 2;
    }
    if (settings.udpport != 0) {
        nfiles += settings.num_threads * 2;
    }

    if (settings.maxconns <= nfiles) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "Configuratioin error. \n"
                "You specified %d connections, but the system will use at "
                "least %d\nconnection structures to start.\n",
                settings.maxconns, nfiles);
        exit(EX_USAGE);
    }

    /* lose root privileges if we have them */
    if (getuid() == 0 || geteuid() == 0) {
        if (username == 0 || *username == '\0') {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "can't run as root without the -u switch\n");
            exit(EX_USAGE);
        }
        if ((pw = getpwnam(username)) == 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "can't find the user %s to switch to\n", username);
            exit(EX_NOUSER);
        }
        if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "failed to assume identity of user %s: %s\n", username,
                    strerror(errno));
            exit(EX_OSERR);
        }
    }

#ifdef SASL_ENABLED
    init_sasl();
#endif /* SASL */

    /* daemonize if requested */
    /* if we want to ensure our ability to dump core, don't chdir to / */
    if (do_daemonize) {
        if (sigignore(SIGHUP) == -1) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "Failed to ignore SIGHUP: ", strerror(errno));
        }
        if (daemonize(maxcore, settings.verbose) == -1) {
             settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "failed to daemon() in order to daemonize\n");
            exit(EXIT_FAILURE);
        }
    }

    /* lock paged memory if needed */
    if (lock_memory) {
#ifdef HAVE_MLOCKALL
        int res = mlockall(MCL_CURRENT | MCL_FUTURE);
        if (res != 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                    "warning: -k invalid, mlockall() failed: %s\n",
                    strerror(errno));
        }
#else
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "warning: -k invalid, mlockall() not supported on this platform.  proceeding without.\n");
#endif
    }

    /* initialize main thread libevent instance */
    main_base = event_init();

    /* Load the storage engine */
    ENGINE_HANDLE *engine_handle = NULL;
    if (!load_engine(engine,get_server_api,settings.extensions.logger,&engine_handle)) {
        /* Error already reported */
        exit(EXIT_FAILURE);
    }

    if(!init_engine(engine_handle,engine_config,settings.extensions.logger)) {
        return false;
    }

    if(settings.verbose > 0) {
        log_engine_details(engine_handle,settings.extensions.logger);
    }
    settings.engine.v1 = (ENGINE_HANDLE_V1 *) engine_handle;

    if (settings.engine.v1->arithmetic == NULL) {
        settings.engine.v1->arithmetic = internal_arithmetic;
    }

    /* initialize other stuff */
    stats_init();

    if (!(conn_cache = cache_create("conn", sizeof(conn), sizeof(void*),
                                    conn_constructor, conn_destructor))) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "Failed to create connection cache\n");
        exit(EXIT_FAILURE);
    }

    default_independent_stats = new_independent_stats();

#ifndef __WIN32__
    /*
     * ignore SIGPIPE signals; we can use errno == EPIPE if we
     * need that information
     */
    if (sigignore(SIGPIPE) == -1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                "failed to ignore SIGPIPE; sigaction");
        exit(EX_OSERR);
    }
#endif

    /* start up worker threads if MT mode */
    thread_init(settings.num_threads, main_base);
    /* save the PID in if we're a daemon, do this after thread_init due to
       a file descriptor handling bug somewhere in libevent */

    if (do_daemonize)
        save_pid(getpid(), pid_file);
    /* initialise clock event */
    clock_handler(0, 0, 0);

    /* create unix mode sockets after dropping privileges */
    if (settings.socketpath != NULL) {
        if (server_socket_unix(settings.socketpath,settings.access)) {
            vperror("failed to listen on UNIX socket: %s", settings.socketpath);
            exit(EX_OSERR);
        }
    }

    /* create the listening socket, bind it, and init */
    if (settings.socketpath == NULL) {
        int udp_port;

        const char *portnumber_filename = getenv("MEMCACHED_PORT_FILENAME");
        char temp_portnumber_filename[PATH_MAX];
        FILE *portnumber_file = NULL;

        if (portnumber_filename != NULL) {
            snprintf(temp_portnumber_filename,
                     sizeof(temp_portnumber_filename),
                     "%s.lck", portnumber_filename);

            portnumber_file = fopen(temp_portnumber_filename, "a");
            if (portnumber_file == NULL) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                        "Failed to open \"%s\": %s\n",
                        temp_portnumber_filename, strerror(errno));
            }
        }

        if (settings.port && server_socket(settings.port, tcp_transport,
                                           portnumber_file)) {
            vperror("failed to listen on TCP port %d", settings.port);
            exit(EX_OSERR);
        }

        /*
         * initialization order: first create the listening sockets
         * (may need root on low ports), then drop root if needed,
         * then daemonise if needed, then init libevent (in some cases
         * descriptors created by libevent wouldn't survive forking).
         */
        udp_port = settings.udpport ? settings.udpport : settings.port;

        /* create the UDP listening socket and bind it */
        if (settings.udpport && server_socket(settings.udpport, udp_transport,
                                              portnumber_file)) {
            vperror("failed to listen on UDP port %d", settings.udpport);
            exit(EX_OSERR);
        }

        if (portnumber_file) {
            fclose(portnumber_file);
            rename(temp_portnumber_filename, portnumber_filename);
        }
    }

    /* Drop privileges no longer needed */
    drop_privileges();

    /* enter the event loop */
    event_base_loop(main_base, 0);

    if (settings.verbose) {
        settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL,
                                        "Initiating shutdown\n");
    }
    threads_shutdown();

    settings.engine.v1->destroy(settings.engine.v0);

    /* remove the PID file if we're a daemon */
    if (do_daemonize)
        remove_pidfile(pid_file);
    /* Clean up strdup() call for bind() address */
    if (settings.inter)
      free(settings.inter);

    return EXIT_SUCCESS;
}

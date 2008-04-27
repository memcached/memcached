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
std *
 *  $Id$
 */
#include "memcached.h"
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/uio.h>
#include <ctype.h>

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
#include <fcntl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <limits.h>

#ifdef HAVE_MALLOC_H
/* OpenBSD has a malloc.h, but warns to use stdlib.h instead */
#ifndef __OpenBSD__
#include <malloc.h>
#endif
#endif

/* FreeBSD 4.x doesn't have IOV_MAX exposed. */
#ifndef IOV_MAX
#if defined(__FreeBSD__) || defined(__APPLE__)
# define IOV_MAX 1024
#endif
#endif

/*
 * forward declarations
 */
static void drive_machine(conn *c);
static int new_socket(struct addrinfo *ai);
static int *server_socket(const int port, const int prot, int *count);
static int try_read_command(conn *c);
static int try_read_network(conn *c);
static int try_read_udp(conn *c);
static void conn_set_state(conn *, int);

/* stats */
static void stats_reset(void);
static void stats_init(void);

/* defaults */
static void settings_init(void);

/* event handling, network IO */
static void event_handler(const int fd, const short which, void *arg);
static void conn_close(conn *c);
static void conn_init(void);
static void accept_new_conns(const bool do_accept);
static bool update_event(conn *c, const int new_flags);
static void complete_nread(conn *c);
static void process_command(conn *c, char *command);
static int transmit(conn *c);
static int ensure_iov_space(conn *c);
static int add_iov(conn *c, const void *buf, int len);
static int add_msghdr(conn *c);

/* time handling */
static void set_current_time(void);  /* update the global variable holding
                              global 32-bit seconds-since-start time
                              (to avoid 64 bit time_t) */

static void conn_free(conn *c);

/** exported globals **/
struct stats stats;
struct settings settings;

/** file scope variables **/
static item **todelete = NULL;
static int delcurr;
static int deltotal;
static conn *listen_conn = NULL;
static struct event_base *main_base;

#define TRANSMIT_COMPLETE   0
#define TRANSMIT_INCOMPLETE 1
#define TRANSMIT_SOFT_ERROR 2
#define TRANSMIT_HARD_ERROR 3

static int *buckets = 0; /* bucket->generation array for a managed instance */

#define REALTIME_MAXDELTA 60*60*24*30
/*
 * given time value that's either unix time or delta from current unix time, return
 * unix time. Use the fact that delta can't exceed one month (and real time value can't
 * be that low).
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
        if (exptime <= stats.started)
            return (rel_time_t)1;
        return (rel_time_t)(exptime - stats.started);
    } else {
        return (rel_time_t)(exptime + current_time);
    }
}

static void stats_init(void) {
    stats.curr_items = stats.total_items = stats.curr_conns = stats.total_conns = stats.conn_structs = 0;
    stats.get_cmds = stats.set_cmds = stats.get_hits = stats.get_misses = stats.evictions = 0;
    stats.curr_bytes = stats.bytes_read = stats.bytes_written = 0;

    /* make the time we started always be 2 seconds before we really
       did, so time(0) - time.started is never zero.  if so, things
       like 'settings.oldest_live' which act as booleans as well as
       values are now false in boolean context... */
    stats.started = time(0) - 2;
    stats_prefix_init();
}

static void stats_reset(void) {
    STATS_LOCK();
    stats.total_items = stats.total_conns = 0;
    stats.get_cmds = stats.set_cmds = stats.get_hits = stats.get_misses = stats.evictions = 0;
    stats.bytes_read = stats.bytes_written = 0;
    stats_prefix_clear();
    STATS_UNLOCK();
}

static void settings_init(void) {
    settings.access=0700;
    settings.port = 11211;
    settings.udpport = 0;
    /* By default this string should be NULL for getaddrinfo() */
    settings.inter = NULL;
    settings.maxbytes = 64 * 1024 * 1024; /* default is 64MB */
    settings.maxconns = 1024;         /* to limit connections-related memory to about 5MB */
    settings.verbose = 0;
    settings.oldest_live = 0;
    settings.evict_to_free = 1;       /* push old items out of cache when memory runs out */
    settings.socketpath = NULL;       /* by default, not using a unix socket */
    settings.managed = false;
    settings.factor = 1.25;
    settings.chunk_size = 48;         /* space for a modest key and value */
#ifdef USE_THREADS
    settings.num_threads = 4;
#else
    settings.num_threads = 1;
#endif
    settings.prefix_delimiter = ':';
    settings.detail_enabled = 0;
}

/* returns true if a deleted item's delete-locked-time is over, and it
   should be removed from the namespace */
static bool item_delete_lock_over (item *it) {
    assert(it->it_flags & ITEM_DELETED);
    return (current_time >= it->exptime);
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

    if (IS_UDP(c->protocol)) {
        /* Leave room for the UDP header, which we'll fill in later. */
        return add_iov(c, NULL, UDP_HEADER_SIZE);
    }

    return 0;
}


/*
 * Free list management for connections.
 */

static conn **freeconns;
static int freetotal;
static int freecurr;


static void conn_init(void) {
    freetotal = 200;
    freecurr = 0;
    if ((freeconns = (conn **)malloc(sizeof(conn *) * freetotal)) == NULL) {
        fprintf(stderr, "malloc()\n");
    }
    return;
}

/*
 * Returns a connection from the freelist, if any. Should call this using
 * conn_from_freelist() for thread safety.
 */
conn *do_conn_from_freelist() {
    conn *c;

    if (freecurr > 0) {
        c = freeconns[--freecurr];
    } else {
        c = NULL;
    }

    return c;
}

/*
 * Adds a connection to the freelist. 0 = success. Should call this using
 * conn_add_to_freelist() for thread safety.
 */
bool do_conn_add_to_freelist(conn *c) {
    if (freecurr < freetotal) {
        freeconns[freecurr++] = c;
        return false;
    } else {
        /* try to enlarge free connections array */
        conn **new_freeconns = realloc(freeconns, sizeof(conn *) * freetotal * 2);
        if (new_freeconns) {
            freetotal *= 2;
            freeconns = new_freeconns;
            freeconns[freecurr++] = c;
            return false;
        }
    }
    return true;
}

conn *conn_new(const int sfd, const int init_state, const int event_flags,
                const int read_buffer_size, const int prot,
                struct event_base *base) {
    conn *c = conn_from_freelist();

    if (NULL == c) {
        if (!(c = (conn *)malloc(sizeof(conn)))) {
            fprintf(stderr, "malloc()\n");
            return NULL;
        }
        c->rbuf = c->wbuf = 0;
        c->ilist = 0;
        c->suffixlist = 0;
        c->iov = 0;
        c->msglist = 0;
        c->hdrbuf = 0;

        c->rsize = read_buffer_size;
        c->wsize = DATA_BUFFER_SIZE;
        c->isize = ITEM_LIST_INITIAL;
        c->suffixsize = SUFFIX_LIST_INITIAL;
        c->iovsize = IOV_LIST_INITIAL;
        c->msgsize = MSG_LIST_INITIAL;
        c->hdrsize = 0;

        c->rbuf = (char *)malloc((size_t)c->rsize);
        c->wbuf = (char *)malloc((size_t)c->wsize);
        c->ilist = (item **)malloc(sizeof(item *) * c->isize);
        c->suffixlist = (char **)malloc(sizeof(char *) * c->suffixsize);
        c->iov = (struct iovec *)malloc(sizeof(struct iovec) * c->iovsize);
        c->msglist = (struct msghdr *)malloc(sizeof(struct msghdr) * c->msgsize);

        if (c->rbuf == 0 || c->wbuf == 0 || c->ilist == 0 || c->iov == 0 ||
                c->msglist == 0 || c->suffixlist == 0) {
            if (c->rbuf != 0) free(c->rbuf);
            if (c->wbuf != 0) free(c->wbuf);
            if (c->ilist !=0) free(c->ilist);
            if (c->suffixlist != 0) free(c->suffixlist);
            if (c->iov != 0) free(c->iov);
            if (c->msglist != 0) free(c->msglist);
            free(c);
            fprintf(stderr, "malloc()\n");
            return NULL;
        }

        STATS_LOCK();
        stats.conn_structs++;
        STATS_UNLOCK();
    }

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
            fprintf(stderr, "<%d server listening\n", sfd);
        } else if (IS_UDP(prot)) {
            fprintf(stderr, "<%d server listening (udp)\n", sfd);
        } else if (prot == binary_prot) {
            fprintf(stderr, "<%d new binary client connection\n", sfd);
        } else if (prot == ascii_prot) {
            fprintf(stderr, "<%d new ascii client connection\n", sfd);
        } else {
            fprintf(stderr, "<%d new unknown (%d) client connection\n",
                sfd, prot);
            abort();
        }
    }

    c->sfd = sfd;
    c->protocol = prot;
    c->state = init_state;
    c->rlbytes = 0;
    c->cmd = -1;
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

    c->write_and_go = init_state;
    c->write_and_free = 0;
    c->item = 0;
    c->bucket = -1;
    c->gen = 0;

    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = event_flags;

    if (event_add(&c->event, 0) == -1) {
        if (conn_add_to_freelist(c)) {
            conn_free(c);
        }
        perror("event_add");
        return NULL;
    }

    STATS_LOCK();
    stats.curr_conns++;
    stats.total_conns++;
    STATS_UNLOCK();

    return c;
}

static void conn_cleanup(conn *c) {
    assert(c != NULL);

    if (c->item) {
        item_remove(c->item);
        c->item = 0;
    }

    if (c->ileft != 0) {
        for (; c->ileft > 0; c->ileft--,c->icurr++) {
            item_remove(*(c->icurr));
        }
    }

    if (c->suffixleft != 0) {
        for (; c->suffixleft > 0; c->suffixleft--, c->suffixcurr++) {
            if(suffix_add_to_freelist(*(c->suffixcurr))) {
                free(*(c->suffixcurr));
            }
        }
    }

    if (c->write_and_free) {
        free(c->write_and_free);
        c->write_and_free = 0;
    }
}

/*
 * Frees a connection.
 */
void conn_free(conn *c) {
    if (c) {
        if (c->hdrbuf)
            free(c->hdrbuf);
        if (c->msglist)
            free(c->msglist);
        if (c->rbuf)
            free(c->rbuf);
        if (c->wbuf)
            free(c->wbuf);
        if (c->ilist)
            free(c->ilist);
        if (c->suffixlist)
            free(c->suffixlist);
        if (c->iov)
            free(c->iov);
        free(c);
    }
}

static void conn_close(conn *c) {
    assert(c != NULL);

    /* delete the event, the socket and the conn */
    event_del(&c->event);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closed.\n", c->sfd);

    close(c->sfd);
    accept_new_conns(true);
    conn_cleanup(c);

    /* if the connection has big buffers, just free it */
    if (c->rsize > READ_BUFFER_HIGHWAT || conn_add_to_freelist(c)) {
        conn_free(c);
    }

    STATS_LOCK();
    stats.curr_conns--;
    STATS_UNLOCK();

    return;
}

static int get_init_state(conn *c) {
    int rv=0;
    assert(c != NULL);

    switch(c->protocol) {
        case binary_prot:
            rv=conn_bin_init;
            break;
        default:
            rv=conn_read;
    }
    return rv;
}

/* Set the given connection to its initial state.  The initial state will vary
 * base don protocol type. */
static void conn_set_init_state(conn *c) {
    assert(c != NULL);

    conn_set_state(c, get_init_state(c));
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

    if (IS_UDP(c->protocol))
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

/*
 * Sets a connection's current state in the state machine. Any special
 * processing that needs to happen on certain state transitions can
 * happen here.
 */
static void conn_set_state(conn *c, int state) {
    assert(c != NULL);

    if (state != c->state) {
        if (state == conn_read) {
            conn_shrink(c);
            assoc_move_next_bucket();
        }
        c->state = state;
    }
}

/*
 * Free list management for suffix buffers.
 */

static char **freesuffix;
static int freesuffixtotal;
static int freesuffixcurr;

static void suffix_init(void) {
    freesuffixtotal = 500;
    freesuffixcurr  = 0;

    freesuffix = (char **)malloc( sizeof(char *) * freesuffixtotal );
    if (freesuffix == NULL) {
        fprintf(stderr, "malloc()\n");
    }
    return;
}

/*
 * Returns a suffix buffer from the freelist, if any. Should call this using
 * suffix_from_freelist() for thread safety.
 */
char *do_suffix_from_freelist() {
    char *s;

    if (freesuffixcurr > 0) {
        s = freesuffix[--freesuffixcurr];
    } else {
        /* If malloc fails, let the logic fall through without spamming
         * STDERR on the server. */
        s = malloc( SUFFIX_SIZE );
    }

    return s;
}

/*
 * Adds a connection to the freelist. 0 = success. Should call this using
 * conn_add_to_freelist() for thread safety.
 */
bool do_suffix_add_to_freelist(char *s) {
    if (freesuffixcurr < freesuffixtotal) {
        freesuffix[freesuffixcurr++] = s;
        return false;
    } else {
        /* try to enlarge free connections array */
        char **new_freesuffix = realloc(freesuffix, freesuffixtotal * 2);
        if (new_freesuffix) {
            freesuffixtotal *= 2;
            freesuffix = new_freesuffix;
            freesuffix[freesuffixcurr++] = s;
            return false;
        }
    }
    return true;
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
        limit_to_mtu = IS_UDP(c->protocol) || (1 == c->msgused);

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
        c->msglist[i].msg_iov[0].iov_base = hdr;
        c->msglist[i].msg_iov[0].iov_len = UDP_HEADER_SIZE;
        *hdr++ = c->request_id / 256;
        *hdr++ = c->request_id % 256;
        *hdr++ = i / 256;
        *hdr++ = i % 256;
        *hdr++ = c->msgused / 256;
        *hdr++ = c->msgused % 256;
        *hdr++ = 0;
        *hdr++ = 0;
        assert((void *) hdr == (void *)c->msglist[i].msg_iov[0].iov_base + UDP_HEADER_SIZE);
    }

    return 0;
}


static void out_string(conn *c, const char *str) {
    size_t len;

    assert(c != NULL);

    if (settings.verbose > 1)
        fprintf(stderr, ">%d %s\n", c->sfd, str);

    len = strlen(str);
    if ((len + 2) > c->wsize) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    memcpy(c->wbuf, str, len);
    memcpy(c->wbuf + len, "\r\n", 3);
    c->wbytes = len + 2;
    c->wcurr = c->wbuf;

    conn_set_state(c, conn_write);
    c->write_and_go = get_init_state(c);
    return;
}

/*
 * we get here after reading the value in set/add/replace commands. The command
 * has been stored in c->item_comm, and the item is ready in c->item.
 */
static void complete_nread_ascii(conn *c) {
    assert(c != NULL);

    item *it = c->item;
    int comm = c->item_comm;
    int ret;

    STATS_LOCK();
    stats.set_cmds++;
    STATS_UNLOCK();

    if (strncmp(ITEM_data(it) + it->nbytes - 2, "\r\n", 2) != 0) {
        out_string(c, "CLIENT_ERROR bad data chunk");
    } else {
      ret = store_item(it, comm);
      if (ret == 1)
          out_string(c, "STORED");
      else if(ret == 2)
          out_string(c, "EXISTS");
      else if(ret == 3)
          out_string(c, "NOT_FOUND");
      else
          out_string(c, "NOT_STORED");
    }

    item_remove(c->item);       /* release the c->item reference */
    c->item = 0;
}

static void add_bin_header(conn *c, int err, int hdr_len, int body_len) {
    int i=0;
    uint32_t res_header[BIN_PKT_HDR_WORDS];

    assert(c);
    assert(body_len >= 0);

    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        /* XXX:  out_string is inappropriate here */
        out_string(c, "SERVER_ERROR out of memory");
        return;
    }

    res_header[0] = BIN_RES_MAGIC << 24;
    res_header[0] |= ((0xff & c->cmd) << 16);
    res_header[0] |= err & 0xffff;

    res_header[1] = hdr_len << 24;
    /* TODO:  Support datatype */
    res_header[2] = body_len;
    res_header[3] = c->opaque;

    if(settings.verbose > 1) {
        fprintf(stderr, "Writing bin response:  %08x %08x %08x %08x\n",
            res_header[0], res_header[1], res_header[2], res_header[3]);
    }

    for(i=0; i<BIN_PKT_HDR_WORDS; i++) {
        res_header[i] = htonl(res_header[i]);
    }

    assert(c->wsize >= MIN_BIN_PKT_LENGTH);
    memcpy(c->wbuf, &res_header, MIN_BIN_PKT_LENGTH);
    add_iov(c, c->wbuf, MIN_BIN_PKT_LENGTH);
}

static void write_bin_error(conn *c, int err, int swallow) {
    char *errstr="Unknown error";
    switch(err) {
        case ERR_UNKNOWN_CMD:
            errstr="Unknown command";
            break;
        case ERR_NOT_FOUND:
            errstr="Not found";
            break;
        case ERR_INVALID_ARGUMENTS:
            errstr="Invalid arguments";
            break;
        case ERR_EXISTS:
            errstr="Data exists for key.";
            break;
        case ERR_TOO_LARGE:
            errstr="Too large.";
            break;
        case ERR_NOT_STORED:
            errstr="Not stored.";
            break;
        default:
            errstr="UNHANDLED ERROR";
            fprintf(stderr, "UNHANDLED ERROR:  %d\n", err);
    }
    if(settings.verbose > 0) {
        fprintf(stderr, "Writing an error:  %s\n", errstr);
    }
    add_bin_header(c, err, 0, strlen(errstr));
    add_iov(c, errstr, strlen(errstr));

    conn_set_state(c, conn_mwrite);
    if(swallow > 0) {
        c->sbytes=swallow;
        c->write_and_go = conn_swallow;
    } else {
        c->write_and_go = conn_bin_init;
    }
}

/* Form and send a response to a command over the binary protocol */
static void write_bin_response(conn *c, void *d, int hlen, int dlen) {
    add_bin_header(c, 0, hlen, dlen);
    if(dlen > 0) {
        add_iov(c, d, dlen);
    }
    conn_set_state(c, conn_mwrite);
    c->write_and_go = conn_bin_init;
}

/* Byte swap a 64-bit number */
static int64_t swap64(int64_t in) {
#ifdef ENDIAN_LITTLE
    /* Little endian, flip the bytes around until someone makes a faster/better
    * way to do this. */
    int64_t rv=0;
    int i=0;
     for(i=0; i<8; i++) {
        rv = (rv << 8) | (in & 0xff);
        in >>= 8;
     }
    return rv;
#else
    /* big-endian machines don't need byte swapping */
    return in;
#endif
}

static void complete_incr_bin(conn *c) {
    item *it;
    int64_t delta;
    uint64_t initial;
    int32_t exptime;
    char *key;
    size_t nkey;
    int i;
    uint64_t *responseBuf = (uint64_t*) c->wbuf + BIN_INCR_HDR_LEN;

    assert(c != NULL);

    key=c->rbuf + BIN_INCR_HDR_LEN;
    nkey=c->keylen;
    key[nkey]=0x00;

    delta = swap64(*((int64_t*)(c->rbuf)));
    initial = (uint64_t)swap64(*((int64_t*)(c->rbuf + 8)));
    exptime = ntohl(*((int*)(c->rbuf + 16)));

    if(settings.verbose) {
        fprintf(stderr, "incr ");
        for(i=0; i<nkey; i++) {
            fprintf(stderr, "%c", key[i]);
        }
        fprintf(stderr, " %lld, %llu, %d\n", delta, initial, exptime);
    }

    /* XXX:  Not sure what to do with these yet
    if (settings.managed) {
        int bucket = c->bucket;
        if (bucket == -1) {
            out_string(c, "CLIENT_ERROR no BG data in managed mode");
            return;
        }
        c->bucket = -1;
        if (buckets[bucket] != c->gen) {
            out_string(c, "ERROR_NOT_OWNER");
            return;
        }
    }
    */

    it = item_get(key, nkey);
    if (it) {
        /* Weird magic in add_delta forces me to pad here */
        char tmpbuf[INCR_MAX_STORAGE_LEN];
        uint64_t l=0;
        memset(tmpbuf, ' ', INCR_MAX_STORAGE_LEN);
        tmpbuf[INCR_MAX_STORAGE_LEN]=0x00;
        add_delta(it, c->cmd == CMD_INCR, delta, tmpbuf);
        *responseBuf=swap64(strtoull(tmpbuf, NULL, 10));

        write_bin_response(c, responseBuf, BIN_INCR_HDR_LEN, INCR_RES_LEN);
        item_remove(it);         /* release our reference */
    } else {
        if(exptime >= 0) {
            /* Save some room for the response */
            assert(c->wsize > BIN_INCR_HDR_LEN + BIN_DEL_HDR_LEN);
            *responseBuf=swap64(initial);
            it = item_alloc(key, nkey, 0, realtime(exptime),
                INCR_MAX_STORAGE_LEN);
            snprintf(ITEM_data(it), INCR_MAX_STORAGE_LEN, "%llu", initial);

            if(store_item(it, NREAD_SET)) {
                write_bin_response(c, responseBuf, BIN_INCR_HDR_LEN,
                    INCR_RES_LEN);
            } else {
                write_bin_error(c, ERR_NOT_STORED, 0);
            }
            item_remove(it);         /* release our reference */
        } else {
            write_bin_error(c, ERR_NOT_FOUND, 0);
        }
    }
}

static void complete_update_bin(conn *c) {
    int eno=-1, ret=0;
    assert(c != NULL);

    item *it = c->item;

    STATS_LOCK();
    stats.set_cmds++;
    STATS_UNLOCK();

    /* We don't actually receive the trailing two characters in the bin
     * protocol, so we're going to just set them here */
    *(ITEM_data(it) + it->nbytes - 2) = '\r';
    *(ITEM_data(it) + it->nbytes - 1) = '\n';

    switch (store_item(it, c->item_comm)) {
        case 1:
            /* Stored */
            write_bin_response(c, NULL, BIN_SET_HDR_LEN, 0);
            break;
        case 2:
            write_bin_error(c, ERR_EXISTS, 0);
            break;
        case 3:
            write_bin_error(c, ERR_NOT_FOUND, 0);
            break;
        default:
            if(c->item_comm == NREAD_ADD) {
                eno=ERR_EXISTS;
            } else if(c->item_comm == NREAD_REPLACE) {
                eno=ERR_NOT_FOUND;
            } else {
                eno=ERR_NOT_STORED;
            }
            write_bin_error(c, eno, 0);
    }

    item_remove(c->item);       /* release the c->item reference */
    c->item = 0;
}

static void process_bin_get(conn *c) {
    item *it;

    it = item_get(c->rbuf, c->keylen);
    if (it) {
        int *flags;
        uint64_t* identifier;

        assert(c->rsize >= MIN_BIN_PKT_LENGTH + 4);

        /* This is a bit of magic.  I'm using wbuf as the header, so I'll place
        this is int in far enough to cover the header */
        flags=(int*)(c->wbuf + MIN_BIN_PKT_LENGTH);
        *flags=htonl(strtoul(ITEM_suffix(it), NULL, 10));

        /* the length has two unnecessary bytes, and then we write four more */
        add_bin_header(c, 0, GET_RES_HDR_LEN, it->nbytes - 2 + GET_RES_HDR_LEN);
        /* Flags */
        add_iov(c, flags, 4);
        identifier=(uint64_t*)(c->wbuf + MIN_BIN_PKT_LENGTH + 4);
        *identifier=swap64((uint32_t)it->cas_id);
        add_iov(c, identifier, 8);
        /* bytes minus the CRLF */
        add_iov(c, ITEM_data(it), it->nbytes - 2);
        conn_set_state(c, conn_mwrite);
    } else {
        if(c->cmd == CMD_GETQ) {
            conn_set_state(c, conn_bin_init);
        } else {
            write_bin_error(c, ERR_NOT_FOUND, 0);
        }
    }
}

static void bin_read_key(conn *c, int next_substate, int extra) {
    assert(c);
    c->substate = next_substate;
    c->rlbytes = c->keylen + extra;
    assert(c->rsize >= c->rlbytes);
    c->ritem = c->rbuf;
    conn_set_state(c, conn_nread);
}

static void dispatch_bin_command(conn *c) {
    time_t exptime = 0;
    switch(c->cmd) {
        case CMD_VERSION:
            write_bin_response(c, VERSION, 0, strlen(VERSION));
            break;
        case CMD_FLUSH:
            set_current_time();

            settings.oldest_live = current_time - 1;
            item_flush_expired();
            write_bin_response(c, NULL, 0, 0);
            break;
        case CMD_NOOP:
            write_bin_response(c, NULL, 0, 0);
            break;
        case CMD_SET:
            /* Fallthrough */
        case CMD_ADD:
            /* Fallthrough */
        case CMD_REPLACE:
            bin_read_key(c, bin_reading_set_header, BIN_SET_HDR_LEN);
            break;
        case CMD_GETQ:
        case CMD_GET:
            bin_read_key(c, bin_reading_get_key, 0);
            break;
        case CMD_DELETE:
            bin_read_key(c, bin_reading_del_header, BIN_DEL_HDR_LEN);
            break;
        case CMD_INCR:
        case CMD_DECR:
            bin_read_key(c, bin_reading_incr_header, BIN_INCR_HDR_LEN);
            break;
        default:
            write_bin_error(c, ERR_UNKNOWN_CMD, c->bin_header[2]);
    }
}

static void process_bin_update(conn *c) {
    char *key;
    int nkey;
    int vlen;
    int flags;
    int exptime;
    item *it;
    int comm;
    int hdrlen=BIN_SET_HDR_LEN;

    assert(c != NULL);

    key=c->rbuf + hdrlen;
    nkey=c->keylen;
    key[nkey]=0x00;

    flags = ntohl(*((int*)(c->rbuf)));
    exptime = ntohl(*((int*)(c->rbuf + 4)));
    vlen = c->bin_header[2] - (nkey + hdrlen);

    if(settings.verbose) {
        fprintf(stderr, "Value len is %d\n", vlen);
    }

    if (settings.detail_enabled) {
        stats_prefix_record_set(key);
    }

    /* Not sure what to do with this.
    if (settings.managed) {
        int bucket = c->bucket;
        if (bucket == -1) {
            out_string(c, "CLIENT_ERROR no BG data in managed mode");
            return;
        }
        c->bucket = -1;
        if (buckets[bucket] != c->gen) {
            out_string(c, "ERROR_NOT_OWNER");
            return;
        }
    }
    */

    it = item_alloc(key, nkey, flags, realtime(exptime), vlen+2);

    if (it == 0) {
        if (! item_size_ok(nkey, flags, vlen + 2)) {
            write_bin_error(c, ERR_TOO_LARGE, vlen);
        } else {
            write_bin_error(c, ERR_OUT_OF_MEMORY, vlen);
        }
        /* swallow the data line */
        c->write_and_go = conn_swallow;
        return;
    }

    it->cas_id = (uint64_t)swap64(*((int64_t*)(c->rbuf + 8)));

    switch(c->cmd) {
        case CMD_ADD:
            c->item_comm = NREAD_ADD;
            break;
        case CMD_SET:
            c->item_comm = NREAD_SET;
            break;
        case CMD_REPLACE:
            c->item_comm = NREAD_REPLACE;
            break;
        default:
            assert(0);
    }

    if(it->cas_id != 0) {
        c->item_comm = NREAD_CAS;
    }

    c->item = it;
    c->ritem = ITEM_data(it);
    c->rlbytes = vlen;
    conn_set_state(c, conn_nread);
    c->substate = bin_read_set_value;
}

static void process_bin_delete(conn *c) {
    char *key;
    size_t nkey;
    item *it;
    time_t exptime = 0;

    assert(c != NULL);

    /* XXX:  I don't know what to do with this yet
    if (settings.managed) {
        int bucket = c->bucket;
        if (bucket == -1) {
            out_string(c, "CLIENT_ERROR no BG data in managed mode");
            return;
        }
        c->bucket = -1;
        if (buckets[bucket] != c->gen) {
            out_string(c, "ERROR_NOT_OWNER");
            return;
        }
    }
    */

    exptime = ntohl(*((int*)(c->rbuf)));
    key = c->rbuf + 4;
    nkey = c->keylen;
    key[nkey]=0x00;

    if(settings.verbose) {
        fprintf(stderr, "Deleting %s with a timeout of %d\n", key, exptime);
    }

    if (settings.detail_enabled) {
        stats_prefix_record_delete(key);
    }

    it = item_get(key, nkey);
    if (it) {
        if (exptime == 0) {
            item_unlink(it);
            item_remove(it);      /* release our reference */
            write_bin_response(c, NULL, 0, 0);
        } else {
            /* XXX:  This is really lame, but defer_delete returns a string */
            char *res=defer_delete(it, exptime);
            if(res[0] == 'D') {
                write_bin_response(c, NULL, 0, 0);
            } else {
                write_bin_error(c, ERR_OUT_OF_MEMORY, 0);
            }
        }
    } else {
        write_bin_error(c, ERR_NOT_FOUND, 0);
    }
}

static void complete_nread_binary(conn *c) {
    assert(c != NULL);

    if(c->cmd < 0) {
        /* No command defined.  Figure out what they're trying to say. */
        int i=0;
        /* I did a bit of hard-coding around the packet sizes */
        assert(BIN_PKT_HDR_WORDS == 3);
        for(i=0; i<BIN_PKT_HDR_WORDS; i++) {
            c->bin_header[i] = ntohl(c->bin_header[i]);
        }
        if(settings.verbose) {
            fprintf(stderr, "Read binary protocol data:  %08x %08x %08x %08x\n",
                c->bin_header[0], c->bin_header[1], c->bin_header[2],
                c->bin_header[3]);
        }
        if((c->bin_header[0] >> 24) != BIN_REQ_MAGIC) {
            if(settings.verbose) {
                fprintf(stderr, "Invalid magic:  %x\n", c->bin_header[0] >> 24);
            }
            conn_set_state(c, conn_closing);
            return;
        }
    
        c->msgcurr = 0;
        c->msgused = 0;
        c->iovused = 0;
        if (add_msghdr(c) != 0) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }
    
        c->cmd = (c->bin_header[0] >> 16) & 0xff;
        c->keylen = c->bin_header[0] & 0xffff;
        c->opaque = c->bin_header[3];
        if(settings.verbose > 1) {
            fprintf(stderr,
                "Command: %d, opaque=%08x, keylen=%d, total_len=%d\n", c->cmd,
                c->opaque, c->keylen, c->bin_header[2]);
        }
        dispatch_bin_command(c);
    } else {
        switch(c->substate) {
            case bin_reading_set_header:
                process_bin_update(c);
                break;
            case bin_read_set_value:
                complete_update_bin(c);
                break;
            case bin_reading_get_key:
                process_bin_get(c);
                break;
            case bin_reading_del_header:
                process_bin_delete(c);
                break;
            case bin_reading_incr_header:
                complete_incr_bin(c);
                break;
            default:
                fprintf(stderr, "Not handling substate %d\n", c->substate);
                assert(0);
        }
    }
}

static void complete_nread(conn *c) {
    assert(c != NULL);

    if(c->protocol == ascii_prot) {
        complete_nread_ascii(c);
    } else if(c->protocol == binary_prot) {
        complete_nread_binary(c);
    } else {
        assert(0); /* XXX:  Invalid case.  Should probably do more here. */
    }
}

/*
 * Stores an item in the cache according to the semantics of one of the set
 * commands. In threaded mode, this is protected by the cache lock.
 *
 * Returns true if the item was stored.
 */
int do_store_item(item *it, int comm) {
    char *key = ITEM_key(it);
    bool delete_locked = false;
    item *old_it = do_item_get_notedeleted(key, it->nkey, &delete_locked);
    int stored = 0;

    item *new_it = NULL;
    int flags;

    if (old_it != NULL && comm == NREAD_ADD) {
        /* add only adds a nonexistent item, but promote to head of LRU */
        do_item_update(old_it);
    } else if (!old_it && (comm == NREAD_REPLACE
        || comm == NREAD_APPEND || comm == NREAD_PREPEND))
    {
        /* replace only replaces an existing value; don't store */
    } else if (delete_locked && (comm == NREAD_REPLACE || comm == NREAD_ADD
        || comm == NREAD_APPEND || comm == NREAD_PREPEND))
    {
        /* replace and add can't override delete locks; don't store */
    } else if (comm == NREAD_CAS) {
        /* validate cas operation */
        if (delete_locked)
            old_it = do_item_get_nocheck(key, it->nkey);

        if(old_it == NULL) {
          // LRU expired
          stored = 3;
        }
        else if(it->cas_id == old_it->cas_id) {
          // cas validates
          do_item_replace(old_it, it);
          stored = 1;
        } else {
          if(settings.verbose > 1) {
            fprintf(stderr, "CAS:  failure: expected %llu, got %llu\n",
                old_it->cas_id, it->cas_id);
          }
          stored = 2;
        }
    } else {
        /*
         * Append - combine new and old record into single one. Here it's
         * atomic and thread-safe.
         */

        if (comm == NREAD_APPEND || comm == NREAD_PREPEND) {

            /* we have it and old_it here - alloc memory to hold both */
            /* flags was already lost - so recover them from ITEM_suffix(it) */

            flags = (int) strtol(ITEM_suffix(old_it), (char **) NULL, 10);

            new_it = do_item_alloc(key, it->nkey, flags, old_it->exptime, it->nbytes + old_it->nbytes - 2 /* CRLF */);

            if (new_it == NULL) {
                /* SERVER_ERROR out of memory */
                return 0;
            }

            /* copy data from it and old_it to new_it */

            if (comm == NREAD_APPEND) {
                memcpy(ITEM_data(new_it), ITEM_data(old_it), old_it->nbytes);
                memcpy(ITEM_data(new_it) + old_it->nbytes - 2 /* CRLF */, ITEM_data(it), it->nbytes);
            } else {
                /* NREAD_PREPEND */
                memcpy(ITEM_data(new_it), ITEM_data(it), it->nbytes);
                memcpy(ITEM_data(new_it) + it->nbytes - 2 /* CRLF */, ITEM_data(old_it), old_it->nbytes);
            }

            it = new_it;
        }

        /* "set" commands can override the delete lock
           window... in which case we have to find the old hidden item
           that's in the namespace/LRU but wasn't returned by
           item_get.... because we need to replace it */
        if (delete_locked)
            old_it = do_item_get_nocheck(key, it->nkey);

        if (old_it != NULL)
            do_item_replace(old_it, it);
        else
            do_item_link(it);

        stored = 1;
    }

    if (old_it != NULL)
        do_item_remove(old_it);         /* release our reference */
    if (new_it != NULL)
        do_item_remove(new_it);

    return stored;
}

typedef struct token_s {
    char *value;
    size_t length;
} token_t;

#define COMMAND_TOKEN 0
#define SUBCOMMAND_TOKEN 1
#define KEY_TOKEN 1
#define KEY_MAX_LENGTH 250

#define MAX_TOKENS 7

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

/* set up a connection to write a buffer then free it, used for stats */
static void write_and_free(conn *c, char *buf, int bytes) {
    if (buf) {
        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        conn_set_state(c, conn_write);
        c->write_and_go = get_init_state(c);
    } else {
        out_string(c, "SERVER_ERROR out of memory");
    }
}

inline static void process_stats_detail(conn *c, const char *command) {
    assert(c != NULL);

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

static void process_stat(conn *c, token_t *tokens, const size_t ntokens) {
    rel_time_t now = current_time;
    char *command;
    char *subcommand;

    assert(c != NULL);

    if(ntokens < 2) {
        out_string(c, "CLIENT_ERROR bad command line");
        return;
    }

    command = tokens[COMMAND_TOKEN].value;

    if (ntokens == 2 && strcmp(command, "stats") == 0) {
        char temp[1024];
        pid_t pid = getpid();
        char *pos = temp;

#ifndef WIN32
        struct rusage usage;
        getrusage(RUSAGE_SELF, &usage);
#endif /* !WIN32 */

        STATS_LOCK();
        pos += sprintf(pos, "STAT pid %u\r\n", pid);
        pos += sprintf(pos, "STAT uptime %u\r\n", now);
        pos += sprintf(pos, "STAT time %ld\r\n", now + stats.started);
        pos += sprintf(pos, "STAT version " VERSION "\r\n");
        pos += sprintf(pos, "STAT pointer_size %d\r\n", 8 * sizeof(void *));
#ifndef WIN32
        pos += sprintf(pos, "STAT rusage_user %ld.%06ld\r\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        pos += sprintf(pos, "STAT rusage_system %ld.%06ld\r\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
#endif /* !WIN32 */
        pos += sprintf(pos, "STAT curr_items %u\r\n", stats.curr_items);
        pos += sprintf(pos, "STAT total_items %u\r\n", stats.total_items);
        pos += sprintf(pos, "STAT bytes %llu\r\n", stats.curr_bytes);
        pos += sprintf(pos, "STAT curr_connections %u\r\n", stats.curr_conns - 1); /* ignore listening conn */
        pos += sprintf(pos, "STAT total_connections %u\r\n", stats.total_conns);
        pos += sprintf(pos, "STAT connection_structures %u\r\n", stats.conn_structs);
        pos += sprintf(pos, "STAT cmd_get %llu\r\n", stats.get_cmds);
        pos += sprintf(pos, "STAT cmd_set %llu\r\n", stats.set_cmds);
        pos += sprintf(pos, "STAT get_hits %llu\r\n", stats.get_hits);
        pos += sprintf(pos, "STAT get_misses %llu\r\n", stats.get_misses);
        pos += sprintf(pos, "STAT evictions %llu\r\n", stats.evictions);
        pos += sprintf(pos, "STAT bytes_read %llu\r\n", stats.bytes_read);
        pos += sprintf(pos, "STAT bytes_written %llu\r\n", stats.bytes_written);
        pos += sprintf(pos, "STAT limit_maxbytes %llu\r\n", (uint64_t) settings.maxbytes);
        pos += sprintf(pos, "STAT threads %u\r\n", settings.num_threads);
        pos += sprintf(pos, "END");
        STATS_UNLOCK();
        out_string(c, temp);
        return;
    }

    subcommand = tokens[SUBCOMMAND_TOKEN].value;

    if (strcmp(subcommand, "reset") == 0) {
        stats_reset();
        out_string(c, "RESET");
        return;
    }

#ifdef HAVE_MALLOC_H
#ifdef HAVE_STRUCT_MALLINFO
    if (strcmp(subcommand, "malloc") == 0) {
        char temp[512];
        struct mallinfo info;
        char *pos = temp;

        info = mallinfo();
        pos += sprintf(pos, "STAT arena_size %d\r\n", info.arena);
        pos += sprintf(pos, "STAT free_chunks %d\r\n", info.ordblks);
        pos += sprintf(pos, "STAT fastbin_blocks %d\r\n", info.smblks);
        pos += sprintf(pos, "STAT mmapped_regions %d\r\n", info.hblks);
        pos += sprintf(pos, "STAT mmapped_space %d\r\n", info.hblkhd);
        pos += sprintf(pos, "STAT max_total_alloc %d\r\n", info.usmblks);
        pos += sprintf(pos, "STAT fastbin_space %d\r\n", info.fsmblks);
        pos += sprintf(pos, "STAT total_alloc %d\r\n", info.uordblks);
        pos += sprintf(pos, "STAT total_free %d\r\n", info.fordblks);
        pos += sprintf(pos, "STAT releasable_space %d\r\nEND", info.keepcost);
        out_string(c, temp);
        return;
    }
#endif /* HAVE_STRUCT_MALLINFO */
#endif /* HAVE_MALLOC_H */

#if !defined(WIN32) || !defined(__APPLE__)
    if (strcmp(subcommand, "maps") == 0) {
        char *wbuf;
        int wsize = 8192; /* should be enough */
        int fd;
        int res;

        if ((wbuf = (char *)malloc(wsize)) == NULL) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }

        fd = open("/proc/self/maps", O_RDONLY);
        if (fd == -1) {
            out_string(c, "SERVER_ERROR cannot open the maps file");
            free(wbuf);
            return;
        }

        res = read(fd, wbuf, wsize - 6);  /* 6 = END\r\n\0 */
        if (res == wsize - 6) {
            out_string(c, "SERVER_ERROR buffer overflow");
            free(wbuf); close(fd);
            return;
        }
        if (res == 0 || res == -1) {
            out_string(c, "SERVER_ERROR can't read the maps file");
            free(wbuf); close(fd);
            return;
        }
        memcpy(wbuf + res, "END\r\n", 5);
        write_and_free(c, wbuf, res + 5);
        close(fd);
        return;
    }
#endif

    if (strcmp(subcommand, "cachedump") == 0) {

        char *buf;
        unsigned int bytes, id, limit = 0;

        if(ntokens < 5) {
            out_string(c, "CLIENT_ERROR bad command line");
            return;
        }

        id = strtoul(tokens[2].value, NULL, 10);
        limit = strtoul(tokens[3].value, NULL, 10);

        if(errno == ERANGE) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        buf = item_cachedump(id, limit, &bytes);
        write_and_free(c, buf, bytes);
        return;
    }

    if (strcmp(subcommand, "slabs") == 0) {
        int bytes = 0;
        char *buf = slabs_stats(&bytes);
        write_and_free(c, buf, bytes);
        return;
    }

    if (strcmp(subcommand, "items") == 0) {
        int bytes = 0;
        char *buf = item_stats(&bytes);
        write_and_free(c, buf, bytes);
        return;
    }

    if (strcmp(subcommand, "detail") == 0) {
        if (ntokens < 4)
            process_stats_detail(c, "");  /* outputs the error message */
        else
            process_stats_detail(c, tokens[2].value);
        return;
    }

    if (strcmp(subcommand, "sizes") == 0) {
        int bytes = 0;
        char *buf = item_stats_sizes(&bytes);
        write_and_free(c, buf, bytes);
        return;
    }

    out_string(c, "ERROR");
}

/* ntokens is overwritten here... shrug.. */
static inline void process_get_command(conn *c, token_t *tokens, size_t ntokens, bool return_cas) {
    char *key;
    size_t nkey;
    int i = 0;
    item *it;
    token_t *key_token = &tokens[KEY_TOKEN];
    char *suffix;
    int stats_get_cmds   = 0;
    int stats_get_hits   = 0;
    int stats_get_misses = 0;
    assert(c != NULL);

    if (settings.managed) {
        int bucket = c->bucket;
        if (bucket == -1) {
            out_string(c, "CLIENT_ERROR no BG data in managed mode");
            return;
        }
        c->bucket = -1;
        if (buckets[bucket] != c->gen) {
            out_string(c, "ERROR_NOT_OWNER");
            return;
        }
    }

    do {
        while(key_token->length != 0) {

            key = key_token->value;
            nkey = key_token->length;

            if(nkey > KEY_MAX_LENGTH) {
                STATS_LOCK();
                stats.get_cmds   += stats_get_cmds;
                stats.get_hits   += stats_get_hits;
                stats.get_misses += stats_get_misses;
                STATS_UNLOCK();
                out_string(c, "CLIENT_ERROR bad command line format");
                return;
            }

            stats_get_cmds++;
            it = item_get(key, nkey);
            if (settings.detail_enabled) {
                stats_prefix_record_get(key, NULL != it);
            }
            if (it) {
                if (i >= c->isize) {
                    item **new_list = realloc(c->ilist, sizeof(item *) * c->isize * 2);
                    if (new_list) {
                        c->isize *= 2;
                        c->ilist = new_list;
                    } else break;
                }

                /*
                 * Construct the response. Each hit adds three elements to the
                 * outgoing data list:
                 *   "VALUE "
                 *   key
                 *   " " + flags + " " + data length + "\r\n" + data (with \r\n)
                 */

                if(return_cas == true)
                {
                  /* Goofy mid-flight realloc. */
                  if (i >= c->suffixsize) {
                    char **new_suffix_list = realloc(c->suffixlist,
                                           sizeof(char *) * c->suffixsize * 2);
                    if (new_suffix_list) {
                      c->suffixsize *= 2;
                      c->suffixlist  = new_suffix_list;
                    } else break;
                  }

                  suffix = suffix_from_freelist();
                  if (suffix == NULL) {
                    STATS_LOCK();
                    stats.get_cmds   += stats_get_cmds;
                    stats.get_hits   += stats_get_hits;
                    stats.get_misses += stats_get_misses;
                    STATS_UNLOCK();
                    out_string(c, "SERVER_ERROR out of memory");
                    return;
                  }
                  *(c->suffixlist + i) = suffix;
                  sprintf(suffix, " %llu\r\n", it->cas_id);
                  if (add_iov(c, "VALUE ", 6) != 0 ||
                      add_iov(c, ITEM_key(it), it->nkey) != 0 ||
                      add_iov(c, ITEM_suffix(it), it->nsuffix - 2) != 0 ||
                      add_iov(c, suffix, strlen(suffix)) != 0 ||
                      add_iov(c, ITEM_data(it), it->nbytes) != 0)
                      {
                          break;
                      }
                }
                else
                {
                  if (add_iov(c, "VALUE ", 6) != 0 ||
                      add_iov(c, ITEM_key(it), it->nkey) != 0 ||
                      add_iov(c, ITEM_suffix(it), it->nsuffix + it->nbytes) != 0)
                      {
                          break;
                      }
                }


                if (settings.verbose > 1)
                    fprintf(stderr, ">%d sending key %s\n", c->sfd, ITEM_key(it));

                /* item_get() has incremented it->refcount for us */
                stats_get_hits++;
                item_update(it);
                *(c->ilist + i) = it;
                i++;

            } else {
                stats_get_misses++;
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
    if (return_cas) {
        c->suffixcurr = c->suffixlist;
        c->suffixleft = i;
    }

    if (settings.verbose > 1)
        fprintf(stderr, ">%d END\n", c->sfd);

    /*
        If the loop was terminated because of out-of-memory, it is not
        reliable to add END\r\n to the buffer, because it might not end
        in \r\n. So we send SERVER_ERROR instead.
    */
    if (key_token->value != NULL || add_iov(c, "END\r\n", 5) != 0
        || (IS_UDP(c->protocol) && build_udp_headers(c) != 0)) {
        out_string(c, "SERVER_ERROR out of memory");
    }
    else {
        conn_set_state(c, conn_mwrite);
        c->msgcurr = 0;
    }

    STATS_LOCK();
    stats.get_cmds   += stats_get_cmds;
    stats.get_hits   += stats_get_hits;
    stats.get_misses += stats_get_misses;
    STATS_UNLOCK();

    return;
}

static void process_update_command(conn *c, token_t *tokens, const size_t ntokens, int comm, bool handle_cas) {
    char *key;
    size_t nkey;
    int flags;
    time_t exptime;
    int vlen, old_vlen;
    uint64_t req_cas_id;
    item *it, *old_it;

    assert(c != NULL);

    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    flags = strtoul(tokens[2].value, NULL, 10);
    exptime = strtol(tokens[3].value, NULL, 10);
    vlen = strtol(tokens[4].value, NULL, 10);

    // does cas value exist?
    if(handle_cas)
    {
      req_cas_id = strtoull(tokens[5].value, NULL, 10);
    }

    if(errno == ERANGE || ((flags == 0 || exptime == 0) && errno == EINVAL)) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if (settings.detail_enabled) {
        stats_prefix_record_set(key);
    }

    if (settings.managed) {
        int bucket = c->bucket;
        if (bucket == -1) {
            out_string(c, "CLIENT_ERROR no BG data in managed mode");
            return;
        }
        c->bucket = -1;
        if (buckets[bucket] != c->gen) {
            out_string(c, "ERROR_NOT_OWNER");
            return;
        }
    }

    it = item_alloc(key, nkey, flags, realtime(exptime), vlen+2);

    if (it == 0) {
        if (! item_size_ok(nkey, flags, vlen + 2))
            out_string(c, "SERVER_ERROR object too large for cache");
        else
            out_string(c, "SERVER_ERROR out of memory");
        /* swallow the data line */
        c->write_and_go = conn_swallow;
        c->sbytes = vlen + 2;
        return;
    }
    if(handle_cas)
      it->cas_id = req_cas_id;

    c->item = it;
    c->ritem = ITEM_data(it);
    c->rlbytes = it->nbytes;
    c->item_comm = comm;
    conn_set_state(c, conn_nread);
}

static void process_arithmetic_command(conn *c, token_t *tokens, const size_t ntokens, const bool incr) {
    char temp[sizeof("18446744073709551615")];
    item *it;
    int64_t delta;
    char *key;
    size_t nkey;

    assert(c != NULL);

    if(tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if (settings.managed) {
        int bucket = c->bucket;
        if (bucket == -1) {
            out_string(c, "CLIENT_ERROR no BG data in managed mode");
            return;
        }
        c->bucket = -1;
        if (buckets[bucket] != c->gen) {
            out_string(c, "ERROR_NOT_OWNER");
            return;
        }
    }

    delta = strtoll(tokens[2].value, NULL, 10);

    if(errno == ERANGE) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    it = item_get(key, nkey);
    if (!it) {
        out_string(c, "NOT_FOUND");
        return;
    }

    out_string(c, add_delta(it, incr, delta, temp));
    item_remove(it);         /* release our reference */
}

/*
 * adds a delta value to a numeric item.
 *
 * it    item to adjust
 * incr  true to increment value, false to decrement
 * delta amount to adjust value by
 * buf   buffer for response string
 *
 * returns a response string to send back to the client.
 */
char *do_add_delta(item *it, const bool incr, const int64_t delta, char *buf) {
    char *ptr;
    int64_t value;
    int res;

    ptr = ITEM_data(it);
    while ((*ptr != '\0') && (*ptr < '0' && *ptr > '9')) ptr++;    // BUG: can't be true

    value = strtoull(ptr, NULL, 10);

    if(errno == ERANGE) {
        return "CLIENT_ERROR cannot increment or decrement non-numeric value";
    }

    if (incr)
        value += delta;
    else {
        value -= delta;
    }
    if(value < 0) {
        value=0;
    }
    sprintf(buf, "%llu", value);
    res = strlen(buf);
    if (res + 2 > it->nbytes) { /* need to realloc */
        item *new_it;
        new_it = do_item_alloc(ITEM_key(it), it->nkey, atoi(ITEM_suffix(it) + 1), it->exptime, res + 2 );
        if (new_it == 0) {
            return "SERVER_ERROR out of memory";
        }
        memcpy(ITEM_data(new_it), buf, res);
        memcpy(ITEM_data(new_it) + res, "\r\n", 3);
        do_item_replace(it, new_it);
        do_item_remove(new_it);       /* release our reference */
    } else { /* replace in-place */
        memcpy(ITEM_data(it), buf, res);
        memset(ITEM_data(it) + res, ' ', it->nbytes - res - 2);
    }

    return buf;
}

static void process_delete_command(conn *c, token_t *tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    item *it;
    time_t exptime = 0;

    assert(c != NULL);

    if (settings.managed) {
        int bucket = c->bucket;
        if (bucket == -1) {
            out_string(c, "CLIENT_ERROR no BG data in managed mode");
            return;
        }
        c->bucket = -1;
        if (buckets[bucket] != c->gen) {
            out_string(c, "ERROR_NOT_OWNER");
            return;
        }
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    if(nkey > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    if(ntokens == 4) {
        exptime = strtol(tokens[2].value, NULL, 10);

        if(errno == ERANGE) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }
    }

    if (settings.detail_enabled) {
        stats_prefix_record_delete(key);
    }

    it = item_get(key, nkey);
    if (it) {
        if (exptime == 0) {
            item_unlink(it);
            item_remove(it);      /* release our reference */
            out_string(c, "DELETED");
        } else {
            /* our reference will be transfered to the delete queue */
            out_string(c, defer_delete(it, exptime));
        }
    } else {
        out_string(c, "NOT_FOUND");
    }
}

/*
 * Adds an item to the deferred-delete list so it can be reaped later.
 *
 * Returns the result to send to the client.
 */
char *do_defer_delete(item *it, time_t exptime)
{
    if (delcurr >= deltotal) {
        item **new_delete = realloc(todelete, sizeof(item *) * deltotal * 2);
        if (new_delete) {
            todelete = new_delete;
            deltotal *= 2;
        } else {
            /*
             * can't delete it immediately, user wants a delay,
             * but we ran out of memory for the delete queue
             */
            item_remove(it);    /* release reference */
            return "SERVER_ERROR out of memory";
        }
    }

    /* use its expiration time as its deletion time now */
    it->exptime = realtime(exptime);
    it->it_flags |= ITEM_DELETED;
    todelete[delcurr++] = it;

    return "DELETED";
}

static void process_verbosity_command(conn *c, token_t *tokens, const size_t ntokens) {
    unsigned int level;

    assert(c != NULL);

    level = strtoul(tokens[1].value, NULL, 10);
    settings.verbose = level > MAX_VERBOSITY_LEVEL ? MAX_VERBOSITY_LEVEL : level;
    out_string(c, "OK");
    return;
}

static void process_command(conn *c, char *command) {

    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    int comm;

    assert(c != NULL);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d %s\n", c->sfd, command);

    /*
     * for commands set/add/replace, we build an item and read the data
     * directly into it, then continue in nread_complete().
     */

    c->msgcurr = 0;
    c->msgused = 0;
    c->iovused = 0;
    if (add_msghdr(c) != 0) {
        out_string(c, "SERVER_ERROR out of memory");
        return;
    }

    ntokens = tokenize_command(command, tokens, MAX_TOKENS);
    if (ntokens >= 3 &&
        ((strcmp(tokens[COMMAND_TOKEN].value, "get") == 0) ||
         (strcmp(tokens[COMMAND_TOKEN].value, "bget") == 0))) {

        process_get_command(c, tokens, ntokens, false);

    } else if (ntokens == 6 &&
               ((strcmp(tokens[COMMAND_TOKEN].value, "add") == 0 && (comm = NREAD_ADD)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "set") == 0 && (comm = NREAD_SET)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "replace") == 0 && (comm = NREAD_REPLACE)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "prepend") == 0 && (comm = NREAD_PREPEND)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "append") == 0 && (comm = NREAD_APPEND)) )) {

        process_update_command(c, tokens, ntokens, comm, false);

    } else if (ntokens == 7 && (strcmp(tokens[COMMAND_TOKEN].value, "cas") == 0 && (comm = NREAD_CAS))) {

        process_update_command(c, tokens, ntokens, comm, true);

    } else if (ntokens == 4 && (strcmp(tokens[COMMAND_TOKEN].value, "incr") == 0)) {

        process_arithmetic_command(c, tokens, ntokens, 1);

    } else if (ntokens >= 3 && (strcmp(tokens[COMMAND_TOKEN].value, "gets") == 0)) {

        process_get_command(c, tokens, ntokens, true);

    } else if (ntokens == 4 && (strcmp(tokens[COMMAND_TOKEN].value, "decr") == 0)) {

        process_arithmetic_command(c, tokens, ntokens, 0);

    } else if (ntokens >= 3 && ntokens <= 4 && (strcmp(tokens[COMMAND_TOKEN].value, "delete") == 0)) {

        process_delete_command(c, tokens, ntokens);

    } else if (ntokens == 3 && strcmp(tokens[COMMAND_TOKEN].value, "own") == 0) {
        unsigned int bucket, gen;
        if (!settings.managed) {
            out_string(c, "CLIENT_ERROR not a managed instance");
            return;
        }

        if (sscanf(tokens[1].value, "%u:%u", &bucket,&gen) == 2) {
            if ((bucket < 0) || (bucket >= MAX_BUCKETS)) {
                out_string(c, "CLIENT_ERROR bucket number out of range");
                return;
            }
            buckets[bucket] = gen;
            out_string(c, "OWNED");
            return;
        } else {
            out_string(c, "CLIENT_ERROR bad format");
            return;
        }

    } else if (ntokens == 3 && (strcmp(tokens[COMMAND_TOKEN].value, "disown")) == 0) {

        int bucket;
        if (!settings.managed) {
            out_string(c, "CLIENT_ERROR not a managed instance");
            return;
        }
        if (sscanf(tokens[1].value, "%u", &bucket) == 1) {
            if ((bucket < 0) || (bucket >= MAX_BUCKETS)) {
                out_string(c, "CLIENT_ERROR bucket number out of range");
                return;
            }
            buckets[bucket] = 0;
            out_string(c, "DISOWNED");
            return;
        } else {
            out_string(c, "CLIENT_ERROR bad format");
            return;
        }

    } else if (ntokens == 3 && (strcmp(tokens[COMMAND_TOKEN].value, "bg")) == 0) {
        int bucket, gen;
        if (!settings.managed) {
            out_string(c, "CLIENT_ERROR not a managed instance");
            return;
        }
        if (sscanf(tokens[1].value, "%u:%u", &bucket, &gen) == 2) {
            /* we never write anything back, even if input's wrong */
            if ((bucket < 0) || (bucket >= MAX_BUCKETS) || (gen <= 0)) {
                /* do nothing, bad input */
            } else {
                c->bucket = bucket;
                c->gen = gen;
            }
            conn_set_init_state(c);
            return;
        } else {
            out_string(c, "CLIENT_ERROR bad format");
            return;
        }

    } else if (ntokens >= 2 && (strcmp(tokens[COMMAND_TOKEN].value, "stats") == 0)) {

        process_stat(c, tokens, ntokens);

    } else if (ntokens >= 2 && ntokens <= 3 && (strcmp(tokens[COMMAND_TOKEN].value, "flush_all") == 0)) {
        time_t exptime = 0;
        set_current_time();

        if(ntokens == 2) {
            settings.oldest_live = current_time - 1;
            item_flush_expired();
            out_string(c, "OK");
            return;
        }

        exptime = strtol(tokens[1].value, NULL, 10);
        if(errno == ERANGE) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        /*
          If exptime is zero realtime() would return zero too, and
          realtime(exptime) - 1 would overflow to the max unsigned
          value.  So we process exptime == 0 the same way we do when
          no delay is given at all.
        */
        if (exptime > 0)
            settings.oldest_live = realtime(exptime) - 1;
        else /* exptime == 0 */
            settings.oldest_live = current_time - 1;
        item_flush_expired();
        out_string(c, "OK");
        return;

    } else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "version") == 0)) {

        out_string(c, "VERSION " VERSION);

    } else if (ntokens == 2 && (strcmp(tokens[COMMAND_TOKEN].value, "quit") == 0)) {

        conn_set_state(c, conn_closing);

    } else if (ntokens == 5 && (strcmp(tokens[COMMAND_TOKEN].value, "slabs") == 0 &&
                                strcmp(tokens[COMMAND_TOKEN + 1].value, "reassign") == 0)) {
#ifdef ALLOW_SLABS_REASSIGN

        int src, dst, rv;

        src = strtol(tokens[2].value, NULL, 10);
        dst  = strtol(tokens[3].value, NULL, 10);

        if(errno == ERANGE) {
            out_string(c, "CLIENT_ERROR bad command line format");
            return;
        }

        rv = slabs_reassign(src, dst);
        if (rv == 1) {
            out_string(c, "DONE");
            return;
        }
        if (rv == 0) {
            out_string(c, "CANT");
            return;
        }
        if (rv == -1) {
            out_string(c, "BUSY");
            return;
        }
#else
        out_string(c, "CLIENT_ERROR Slab reassignment not supported");
#endif
    } else if (ntokens == 3 && (strcmp(tokens[COMMAND_TOKEN].value, "verbosity") == 0)) {
        process_verbosity_command(c, tokens, ntokens);
    } else {
        out_string(c, "ERROR");
    }
    return;
}

/*
 * if we have a complete line in the buffer, process it.
 */
static int try_read_command(conn *c) {
    char *el, *cont;

    assert(c != NULL);
    assert(c->rcurr <= (c->rbuf + c->rsize));

    if (c->rbytes == 0)
        return 0;
    el = memchr(c->rcurr, '\n', c->rbytes);
    if (!el)
        return 0;
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

    return 1;
}

/*
 * read a UDP request.
 * return 0 if there's nothing to read.
 */
static int try_read_udp(conn *c) {
    int res;

    assert(c != NULL);

    c->request_addr_size = sizeof(c->request_addr);
    res = recvfrom(c->sfd, c->rbuf, c->rsize,
                   0, &c->request_addr, &c->request_addr_size);
    if (res > 8) {
        unsigned char *buf = (unsigned char *)c->rbuf;
        STATS_LOCK();
        stats.bytes_read += res;
        STATS_UNLOCK();

        /* Beginning of UDP packet is the request ID; save it. */
        c->request_id = buf[0] * 256 + buf[1];

        /* If this is a multi-packet request, drop it. */
        if (buf[4] != 0 || buf[5] != 1) {
            out_string(c, "SERVER_ERROR multi-packet request not supported");
            return 0;
        }

        /* Don't care about any of the rest of the header. */
        res -= 8;
        memmove(c->rbuf, c->rbuf + 8, res);

        c->rbytes += res;
        c->rcurr = c->rbuf;
        return 1;
    }
    return 0;
}

/*
 * read from network as much as we can, handle buffer overflow and connection
 * close.
 * before reading, move the remaining incomplete fragment of a command
 * (if any) to the beginning of the buffer.
 * return 0 if there's nothing to read on the first read.
 */
static int try_read_network(conn *c) {
    int gotdata = 0;
    int res;

    assert(c != NULL);

    if (c->rcurr != c->rbuf) {
        if (c->rbytes != 0) /* otherwise there's nothing to copy */
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1) {
        if (c->rbytes >= c->rsize) {
            char *new_rbuf = realloc(c->rbuf, c->rsize * 2);
            if (!new_rbuf) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't realloc input buffer\n");
                c->rbytes = 0; /* ignore what we read */
                out_string(c, "SERVER_ERROR out of memory");
                c->write_and_go = conn_closing;
                return 1;
            }
            c->rcurr = c->rbuf = new_rbuf;
            c->rsize *= 2;
        }

        int avail = c->rsize - c->rbytes;
        res = read(c->sfd, c->rbuf + c->rbytes, avail);
        if (res > 0) {
            STATS_LOCK();
            stats.bytes_read += res;
            STATS_UNLOCK();
            gotdata = 1;
            c->rbytes += res;
            if (res == avail) {
                continue;
            } else {
                break;
            }
        }
        if (res == 0) {
            /* connection closed */
            conn_set_state(c, conn_closing);
            return 1;
        }
        if (res == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            else return 0;
        }
    }
    return gotdata;
}

static bool update_event(conn *c, const int new_flags) {
    assert(c != NULL);

    struct event_base *base = c->event.ev_base;
    if (c->ev_flags == new_flags)
        return true;
    if (event_del(&c->event) == -1) return false;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    event_base_set(base, &c->event);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return false;
    return true;
}

/*
 * Sets whether we are listening for new connections or not.
 */
void accept_new_conns(const bool do_accept) {
    conn *next;

    if (! is_listen_thread())
        return;

    for (next = listen_conn; next; next = next->next) {
        if (do_accept) {
            update_event(next, EV_READ | EV_PERSIST);
            if (listen(next->sfd, 1024) != 0) {
                perror("listen");
            }
        }
        else {
            update_event(next, 0);
            if (listen(next->sfd, 0) != 0) {
                perror("listen");
            }
        }
  }
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
static int transmit(conn *c) {
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
            STATS_LOCK();
            stats.bytes_written += res;
            STATS_UNLOCK();

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
                m->msg_iov->iov_base += res;
                m->msg_iov->iov_len -= res;
            }
            return TRANSMIT_INCOMPLETE;
        }
        if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!update_event(c, EV_WRITE | EV_PERSIST)) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                conn_set_state(c, conn_closing);
                return TRANSMIT_HARD_ERROR;
            }
            return TRANSMIT_SOFT_ERROR;
        }
        /* if res==0 or res==-1 and error is not EAGAIN or EWOULDBLOCK,
           we have a real error, on which we close the connection */
        if (settings.verbose > 0)
            perror("Failed to write, and not due to blocking");

        if (IS_UDP(c->protocol))
            conn_set_state(c, conn_read);
        else
            conn_set_state(c, conn_closing);
        return TRANSMIT_HARD_ERROR;
    } else {
        return TRANSMIT_COMPLETE;
    }
}

static void drive_machine(conn *c) {
    bool stop = false;
    int sfd, flags = 1;
    int init_state; /* initial state for a new connection */
    socklen_t addrlen;
    struct sockaddr_storage addr;
    int res;

    assert(c != NULL);

    while (!stop) {

        switch(c->state) {
        case conn_listening:
            addrlen = sizeof(addr);
            if ((sfd = accept(c->sfd, (struct sockaddr *)&addr, &addrlen)) == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    /* these are transient, so don't log anything */
                    stop = true;
                } else if (errno == EMFILE) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Too many open connections\n");
                    accept_new_conns(false);
                    stop = true;
                } else {
                    perror("accept()");
                    stop = true;
                }
                break;
            }
            if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
                fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                perror("setting O_NONBLOCK");
                close(sfd);
                break;
            }
            init_state = get_init_state(c);

            dispatch_conn_new(sfd, init_state, EV_READ | EV_PERSIST,
                                     DATA_BUFFER_SIZE, c->protocol);

            break;

        case conn_read:
            if (try_read_command(c) != 0) {
                continue;
            }
            if ((IS_UDP(c->protocol) ? try_read_udp(c) : try_read_network(c)) != 0) {
                continue;
            }
            /* we have no command line and no data to read from network */
            if (!update_event(c, EV_READ | EV_PERSIST)) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't update event\n");
                conn_set_state(c, conn_closing);
                break;
            }
            stop = true;
            break;

        case conn_bin_init: /* Reinitialize a binary connection */
            c->rlbytes = MIN_BIN_PKT_LENGTH;
            c->write_and_go = conn_bin_init;
            c->cmd = -1;
            c->substate = bin_no_state;
            c->rbytes = c->wbytes = 0;
            c->wcurr = c->wbuf;
            c->rcurr = c->rbuf;
            c->ritem = (char*)c->bin_header;
            conn_set_state(c, conn_nread);
            conn_shrink(c);
            break;

        case conn_nread:
            if (c->rlbytes == 0) {
                complete_nread(c);
                break;
            }
            /* first check if we have leftovers in the conn_read buffer */
            if (c->rbytes > 0) {
                int tocopy = c->rbytes > c->rlbytes ? c->rlbytes : c->rbytes;
                memcpy(c->ritem, c->rcurr, tocopy);
                c->ritem += tocopy;
                c->rlbytes -= tocopy;
                c->rcurr += tocopy;
                c->rbytes -= tocopy;
                break;
            }

            /*  now try reading from the socket */
            res = read(c->sfd, c->ritem, c->rlbytes);
            if (res > 0) {
                STATS_LOCK();
                stats.bytes_read += res;
                STATS_UNLOCK();
                c->ritem += res;
                c->rlbytes -= res;
                break;
            }
            if (res == 0) { /* end of stream */
                conn_set_state(c, conn_closing);
                break;
            }
            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!update_event(c, EV_READ | EV_PERSIST)) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't update event\n");
                    conn_set_state(c, conn_closing);
                    break;
                }
                stop = true;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if (settings.verbose > 0)
                fprintf(stderr, "Failed to read, and not due to blocking\n");
            conn_set_state(c, conn_closing);
            break;

        case conn_swallow:
            /* we are reading sbytes and throwing them away */
            if (c->sbytes == 0) {
                conn_set_init_state(c);
                break;
            }

            /* first check if we have leftovers in the conn_read buffer */
            if (c->rbytes > 0) {
                int tocopy = c->rbytes > c->sbytes ? c->sbytes : c->rbytes;
                c->sbytes -= tocopy;
                c->rcurr += tocopy;
                c->rbytes -= tocopy;
                break;
            }

            /*  now try reading from the socket */
            res = read(c->sfd, c->rbuf, c->rsize > c->sbytes ? c->sbytes : c->rsize);
            if (res > 0) {
                STATS_LOCK();
                stats.bytes_read += res;
                STATS_UNLOCK();
                c->sbytes -= res;
                break;
            }
            if (res == 0) { /* end of stream */
                conn_set_state(c, conn_closing);
                break;
            }
            if (res == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                if (!update_event(c, EV_READ | EV_PERSIST)) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't update event\n");
                    conn_set_state(c, conn_closing);
                    break;
                }
                stop = true;
                break;
            }
            /* otherwise we have a real error, on which we close the connection */
            if (settings.verbose > 0)
                fprintf(stderr, "Failed to read, and not due to blocking\n");
            conn_set_state(c, conn_closing);
            break;

        case conn_write:
            /*
             * We want to write out a simple response. If we haven't already,
             * assemble it into a msgbuf list (this will be a single-entry
             * list for TCP or a two-entry list for UDP).
             */
            if (c->iovused == 0 || (IS_UDP(c->protocol) && c->iovused == 1)) {
                if (add_iov(c, c->wcurr, c->wbytes) != 0 ||
                    (IS_UDP(c->protocol) && build_udp_headers(c) != 0)) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Couldn't build response\n");
                    conn_set_state(c, conn_closing);
                    break;
                }
            }

            /* fall through... */

        case conn_mwrite:
            switch (transmit(c)) {
            case TRANSMIT_COMPLETE:
                if (c->state == conn_mwrite) {
                    while (c->ileft > 0) {
                        item *it = *(c->icurr);
                        assert((it->it_flags & ITEM_SLABBED) == 0);
                        item_remove(it);
                        c->icurr++;
                        c->ileft--;
                    }
                    while (c->suffixleft > 0) {
                        char *suffix = *(c->suffixcurr);
                        if(suffix_add_to_freelist(suffix)) {
                            /* Failed to add to freelist, don't leak */
                            free(suffix);
                        }
                        c->suffixcurr++;
                        c->suffixleft--;
                    }
                    /* XXX:  I don't know why this wasn't the general case */
                    if(c->protocol == binary_prot) {
                        conn_set_state(c, c->write_and_go);
                    } else {
                        conn_set_init_state(c);
                    }
                } else if (c->state == conn_write) {
                    if (c->write_and_free) {
                        free(c->write_and_free);
                        c->write_and_free = 0;
                    }
                    conn_set_state(c, c->write_and_go);
                } else {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Unexpected state %d\n", c->state);
                    conn_set_state(c, conn_closing);
                }
                break;

            case TRANSMIT_INCOMPLETE:
            case TRANSMIT_HARD_ERROR:
                break;                   /* Continue in state machine. */

            case TRANSMIT_SOFT_ERROR:
                stop = true;
                break;
            }
            break;

        case conn_closing:
            if (IS_UDP(c->protocol))
                conn_cleanup(c);
            else
                conn_close(c);
            stop = true;
            break;
        }
    }

    return;
}

void event_handler(const int fd, const short which, void *arg) {
    conn *c;

    c = (conn *)arg;
    assert(c != NULL);

    c->which = which;

    /* sanity */
    if (fd != c->sfd) {
        if (settings.verbose > 0)
            fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
        conn_close(c);
        return;
    }

    drive_machine(c);

    /* wait for next event */
    return;
}

static int new_socket(struct addrinfo *ai) {
    int sfd;
    int flags;

    if ((sfd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol)) == -1) {
        perror("socket()");
        return -1;
    }

    if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
        fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
        perror("setting O_NONBLOCK");
        close(sfd);
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
    if (getsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &old_size, &intsize) != 0) {
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

    if (settings.verbose > 1)
        fprintf(stderr, "<%d send buffer was %d, now %d\n", sfd, old_size, last_good);
}


static int *server_socket(const int port, const int prot, int *count) {
    int sfd;
    int *sfd_list;
    int *sfd_ptr;
    struct linger ling = {0, 0};
    struct addrinfo *ai;
    struct addrinfo *next;
    struct addrinfo hints;
    char port_buf[NI_MAXSERV];
    int error;
    int success = 0;

    int flags =1;

    /*
     * the memset call clears nonstandard fields in some impementations
     * that otherwise mess things up.
     */
    memset(&hints, 0, sizeof (hints));
    hints.ai_flags = AI_PASSIVE|AI_ADDRCONFIG;
    if (IS_UDP(prot))
    {
        hints.ai_protocol = IPPROTO_UDP;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_family = AF_INET; /* This left here because of issues with OSX 10.5 */
    } else {
        hints.ai_family = AF_UNSPEC;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_socktype = SOCK_STREAM;
    }

    snprintf(port_buf, NI_MAXSERV, "%d", port);
    error= getaddrinfo(settings.inter, port_buf, &hints, &ai);
    if (error != 0) {
      if (error != EAI_SYSTEM)
        fprintf(stderr, "getaddrinfo(): %s\n", gai_strerror(error));
      else
        perror("getaddrinfo()");

      return NULL;
    }

    for (*count= 1, next= ai; next->ai_next; next= next->ai_next, (*count)++);

    sfd_list= (int *)calloc(*count, sizeof(int));
    if (sfd_list == NULL) {
        fprintf(stderr, "calloc()\n");
        return NULL;
    }
    memset(sfd_list, -1, sizeof(int) * (*count));

    for (sfd_ptr= sfd_list, next= ai; next; next= next->ai_next, sfd_ptr++) {
        if ((sfd = new_socket(next)) == -1) {
            free(sfd_list);
            freeaddrinfo(ai);
            return NULL;
        }

        setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (void *)&flags, sizeof(flags));
        if (IS_UDP(prot)) {
            maximize_sndbuf(sfd);
        } else {
            setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, (void *)&flags, sizeof(flags));
            setsockopt(sfd, SOL_SOCKET, SO_LINGER, (void *)&ling, sizeof(ling));
            setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, (void *)&flags, sizeof(flags));
        }

        if (bind(sfd, next->ai_addr, next->ai_addrlen) == -1) {
            if (errno != EADDRINUSE) {
                perror("bind()");
                /* If we are not at the first element, loop back and close all sockets */
                if (sfd_ptr != sfd_list) {
                    do {
                        --sfd_ptr;
                        close(*sfd_ptr);
                    } while (sfd_ptr != sfd_list);
                }
                close(sfd);
                freeaddrinfo(ai);
                free(sfd_list);
                return NULL;
            }
            close(sfd);
            *sfd_ptr= -1;
        } else {
          success++;
          *sfd_ptr= sfd;
          if (!IS_UDP(prot) && listen(sfd, 1024) == -1) {
              perror("listen()");
                if (sfd_ptr != sfd_list) {
                    do {
                        --sfd_ptr;
                        close(*sfd_ptr);
                    } while (sfd_ptr != sfd_list);
                }
              close(sfd);
              freeaddrinfo(ai);
              free(sfd_list);
              return NULL;
          }
      }
    }

    freeaddrinfo(ai);

    if (success == 0) {
        free(sfd_list);
        return NULL;
    }

    return sfd_list;
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
        close(sfd);
        return -1;
    }
    return sfd;
}

static int *server_socket_unix(const char *path, int access_mask) {
    int sfd;
    int *sfd_list;
    struct linger ling = {0, 0};
    struct sockaddr_un addr;
    struct stat tstat;
    int flags =1;
    int old_umask;

    if (!path) {
        return NULL;
    }

    if ((sfd = new_socket_unix()) == -1) {
        return NULL;
    }

    /*
      When UNIX domain sockets get refactored, this will go away.
      For now we know there is just one socket.
    */
    sfd_list= (int *)calloc(1, sizeof(int));
    if (sfd_list == NULL) {
        fprintf(stderr, "calloc()\n");
        return NULL;
    }
    memset(sfd_list, -1, sizeof(int) * 1);

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
    strcpy(addr.sun_path, path);
    old_umask=umask( ~(access_mask&0777));
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        perror("bind()");
        close(sfd);
        free(sfd_list);
        umask(old_umask);
        return NULL;
    }
    umask(old_umask);
    if (listen(sfd, 1024) == -1) {
        perror("listen()");
        close(sfd);
        free(sfd_list);
        return NULL;
    }

    *sfd_list= sfd;

    return sfd_list;
}

/*
 * We keep the current time of day in a global variable that's updated by a
 * timer event. This saves us a bunch of time() system calls (we really only
 * need to get the time once a second, whereas there can be tens of thousands
 * of requests a second) and allows us to use server-start-relative timestamps
 * rather than absolute UNIX timestamps, a space savings on systems where
 * sizeof(time_t) > sizeof(unsigned int).
 */
volatile rel_time_t current_time;
static struct event clockevent;

/* time-sensitive callers can call it by hand with this, outside the normal ever-1-second timer */
static void set_current_time(void) {
    struct timeval timer;

    gettimeofday(&timer, NULL);
    current_time = (rel_time_t) (timer.tv_sec - stats.started);
}

static void clock_handler(const int fd, const short which, void *arg) {
    struct timeval t = {.tv_sec = 1, .tv_usec = 0};
    static bool initialized = false;

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

static struct event deleteevent;

static void delete_handler(const int fd, const short which, void *arg) {
    struct timeval t = {.tv_sec = 5, .tv_usec = 0};
    static bool initialized = false;

    if (initialized) {
        /* some versions of libevent don't like deleting events that don't exist,
           so only delete once we know this event has been added. */
        evtimer_del(&deleteevent);
    } else {
        initialized = true;
    }

    evtimer_set(&deleteevent, delete_handler, 0);
    event_base_set(main_base, &deleteevent);
    evtimer_add(&deleteevent, &t);
    run_deferred_deletes();
}

/* Call run_deferred_deletes instead of this. */
void do_run_deferred_deletes(void)
{
    int i, j = 0;

    for (i = 0; i < delcurr; i++) {
        item *it = todelete[i];
        if (item_delete_lock_over(it)) {
            assert(it->refcount > 0);
            it->it_flags &= ~ITEM_DELETED;
            do_item_unlink(it);
            do_item_remove(it);
        } else {
            todelete[j++] = it;
        }
    }
    delcurr = j;
}

static void usage(void) {
    printf(PACKAGE " " VERSION "\n");
    printf("-p <num>      TCP port number to listen on (default: 11211)\n"
           "-U <num>      UDP port number to listen on (default: 0, off)\n"
           "-B <num>      binary protocol TCP port number to listen on (default: 0, off)\n"
           "-s <file>     unix socket path to listen on (disables network support)\n"
           "-a <mask>     access mask for unix socket, in octal (default 0700)\n"
           "-l <ip_addr>  interface to listen on, default is INDRR_ANY\n"
           "-d            run as a daemon\n"
           "-r            maximize core file limit\n"
           "-u <username> assume identity of <username> (only when run as root)\n"
           "-m <num>      max memory to use for items in megabytes, default is 64 MB\n"
           "-M            return error on memory exhausted (rather than removing items)\n"
           "-c <num>      max simultaneous connections, default is 1024\n"
           "-k            lock down all paged memory.  Note that there is a\n"
           "              limit on how much memory you may lock.  Trying to\n"
           "              allocate more than that would fail, so be sure you\n"
           "              set the limit correctly for the user you started\n"
           "              the daemon with (not for -u <username> user;\n"
           "              under sh this is done with 'ulimit -S -l NUM_KB').\n"
           "-v            verbose (print errors/warnings while in event loop)\n"
           "-vv           very verbose (also print client commands/reponses)\n"
           "-h            print this help and exit\n"
           "-i            print memcached and libevent license\n"
           "-b            run a managed instanced (mnemonic: buckets)\n"
           "-P <file>     save PID in <file>, only used with -d option\n"
           "-f <factor>   chunk size growth factor, default 1.25\n"
           "-n <bytes>    minimum space allocated for key+value+flags, default 48\n");
#ifdef USE_THREADS
    printf("-t <num>      number of threads to use, default 4\n");
#endif
    return;
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
    if (pid_file == NULL)
        return;

    if ((fp = fopen(pid_file, "w")) == NULL) {
        fprintf(stderr, "Could not open the pid file %s for writing\n", pid_file);
        return;
    }

    fprintf(fp,"%ld\n", (long)pid);
    if (fclose(fp) == -1) {
        fprintf(stderr, "Could not close the pid file %s.\n", pid_file);
        return;
    }
}

static void remove_pidfile(const char *pid_file) {
  if (pid_file == NULL)
      return;

  if (unlink(pid_file) != 0) {
      fprintf(stderr, "Could not remove the pid file %s.\n", pid_file);
  }

}

static void setup_listening_conns(int *l_socket, int count, const int prot) {
    /* create the initial listening connection */
    int x;
    int *l_socket_ptr;
    conn *next = listen_conn;
    for (l_socket_ptr= l_socket, x = 0; x < count; l_socket_ptr++, x++) {
        conn *listen_conn_add;
        if (*l_socket_ptr > -1 ) {
            if (!(listen_conn_add = conn_new(*l_socket_ptr, conn_listening,
                                             EV_READ | EV_PERSIST,
                                             1, prot, main_base))) {
                fprintf(stderr, "failed to create listening connection\n");
                exit(EXIT_FAILURE);
            }

            if (listen_conn == NULL) {
                next = listen_conn = listen_conn_add;
            } else {
                next->next= listen_conn_add;
            }
        }
    }
}

static void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    exit(EXIT_SUCCESS);
}

int main (int argc, char **argv) {
    int c;
    bool lock_memory = false;
    bool daemonize = false;
    int maxcore = 0;
    char *username = NULL;
    char *pid_file = NULL;
    struct passwd *pw;
    struct sigaction sa;
    struct rlimit rlim;
    /* listening sockets */
    static int *l_socket = NULL;
    static int *bl_socket = NULL;
    static int l_socket_count = 0;
    static int bl_socket_count = 0;

    /* udp socket */
    static int *u_socket = NULL;
    static int u_socket_count = 0;

    /* handle SIGINT */
    signal(SIGINT, sig_handler);

    /* init settings */
    settings_init();

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    /* process arguments */
    while ((c = getopt(argc, argv, "a:bp:B:s:U:m:Mc:khirvdl:u:P:f:s:n:t:D:")) != -1) {
        switch (c) {
        case 'a':
            /* access for unix domain socket, as octal mask (like chmod)*/
            settings.access= strtol(optarg,NULL,8);
            break;

        case 'U':
            settings.udpport = atoi(optarg);
            break;
        case 'b':
            settings.managed = true;
            break;
        case 'p':
            settings.port = atoi(optarg);
            break;
        case 'B':
            settings.binport = atoi(optarg);
            break;
        case 's':
            settings.socketpath = optarg;
            break;
        case 'm':
            settings.maxbytes = ((size_t)atoi(optarg)) * 1024 * 1024;
            break;
        case 'M':
            settings.evict_to_free = 0;
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
            break;
        case 'l':
            settings.inter= strdup(optarg);
            break;
        case 'd':
            daemonize = true;
            break;
        case 'r':
            maxcore = 1;
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
                fprintf(stderr, "Factor must be greater than 1\n");
                return 1;
            }
            break;
        case 'n':
            settings.chunk_size = atoi(optarg);
            if (settings.chunk_size == 0) {
                fprintf(stderr, "Chunk size must be greater than 0\n");
                return 1;
            }
            break;
        case 't':
            settings.num_threads = atoi(optarg);
            if (settings.num_threads == 0) {
                fprintf(stderr, "Number of threads must be greater than 0\n");
                return 1;
            }
            break;
        case 'D':
            if (! optarg || ! optarg[0]) {
                fprintf(stderr, "No delimiter specified\n");
                return 1;
            }
            settings.prefix_delimiter = optarg[0];
            settings.detail_enabled = 1;
            break;
        default:
            fprintf(stderr, "Illegal argument \"%c\"\n", c);
            return 1;
        }
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
            fprintf(stderr, "failed to ensure corefile creation\n");
            exit(EXIT_FAILURE);
        }
    }

    /*
     * If needed, increase rlimits to allow as many connections
     * as needed.
     */

    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        fprintf(stderr, "failed to getrlimit number of files\n");
        exit(EXIT_FAILURE);
    } else {
        int maxfiles = settings.maxconns;
        if (rlim.rlim_cur < maxfiles)
            rlim.rlim_cur = maxfiles + 3;
        if (rlim.rlim_max < rlim.rlim_cur)
            rlim.rlim_max = rlim.rlim_cur;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            fprintf(stderr, "failed to set rlimit for open files. Try running as root or requesting smaller maxconns value.\n");
            exit(EXIT_FAILURE);
        }
    }

    /*
     * initialization order: first create the listening sockets
     * (may need root on low ports), then drop root if needed,
     * then daemonise if needed, then init libevent (in some cases
     * descriptors created by libevent wouldn't survive forking).
     */

    /* create the listening socket and bind it */
    if (settings.socketpath == NULL) {
        l_socket = server_socket(settings.port, 0, &l_socket_count);
        if (l_socket == NULL) {
            fprintf(stderr, "failed to listen\n");
            exit(EXIT_FAILURE);
        }
        /* Try the binary port. */
        if(settings.binport > 0) {
            bl_socket = server_socket(settings.binport, 0, &bl_socket_count);
            if (bl_socket == NULL) {
                 fprintf(stderr, "failed to listen to binary protocol\n");
                    exit(EXIT_FAILURE);
            }
        }
    }

    if (settings.udpport > 0 && settings.socketpath == NULL) {
        /* create the UDP listening socket and bind it */
        u_socket = server_socket(settings.udpport, 1, &u_socket_count);
        if (u_socket == NULL) {
            fprintf(stderr, "failed to listen on UDP port %d\n", settings.udpport);
            exit(EXIT_FAILURE);
        }
    }

    /* lock paged memory if needed */
    if (lock_memory) {
#ifdef HAVE_MLOCKALL
        int res = mlockall(MCL_CURRENT | MCL_FUTURE);
        if (res != 0) {
            fprintf(stderr, "warning: -k invalid, mlockall() failed: %s\n",
                    strerror(errno));
        }
#else
        fprintf(stderr, "warning: -k invalid, mlockall() not supported on this platform.  proceeding without.\n");
#endif
    }

    /* lose root privileges if we have them */
    if (getuid() == 0 || geteuid() == 0) {
        if (username == 0 || *username == '\0') {
            fprintf(stderr, "can't run as root without the -u switch\n");
            return 1;
        }
        if ((pw = getpwnam(username)) == 0) {
            fprintf(stderr, "can't find the user %s to switch to\n", username);
            return 1;
        }
        if (setgid(pw->pw_gid) < 0 || setuid(pw->pw_uid) < 0) {
            fprintf(stderr, "failed to assume identity of user %s\n", username);
            return 1;
        }
    }

    /* create unix mode sockets after dropping privileges */
    if (settings.socketpath != NULL) {
        l_socket = server_socket_unix(settings.socketpath,settings.access);
        if (l_socket == NULL) {
          fprintf(stderr, "failed to listen\n");
          exit(EXIT_FAILURE);
        }
        /* We only support one of these, so whe know the count */
        l_socket_count = 1;
    }

    /* daemonize if requested */
    /* if we want to ensure our ability to dump core, don't chdir to / */
    if (daemonize) {
        int res;
        res = daemon(maxcore, settings.verbose);
        if (res == -1) {
            fprintf(stderr, "failed to daemon() in order to daemonize\n");
            return 1;
        }
    }


    /* initialize main thread libevent instance */
    main_base = event_init();

    /* initialize other stuff */
    item_init();
    stats_init();
    assoc_init();
    conn_init();
    /* Hacky suffix buffers. */
    suffix_init();
    slabs_init(settings.maxbytes, settings.factor);

    /* managed instance? alloc and zero a bucket array */
    if (settings.managed) {
        buckets = malloc(sizeof(int) * MAX_BUCKETS);
        if (buckets == 0) {
            fprintf(stderr, "failed to allocate the bucket array");
            exit(EXIT_FAILURE);
        }
        memset(buckets, 0, sizeof(int) * MAX_BUCKETS);
    }

    /*
     * ignore SIGPIPE signals; we can use errno==EPIPE if we
     * need that information
     */
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = 0;
    if (sigemptyset(&sa.sa_mask) == -1 ||
        sigaction(SIGPIPE, &sa, 0) == -1) {
        perror("failed to ignore SIGPIPE; sigaction");
        exit(EXIT_FAILURE);
    }
    /* Set up all of the listening connections */
    setup_listening_conns(l_socket, l_socket_count, ascii_prot);
    setup_listening_conns(bl_socket, bl_socket_count, binary_prot);

    /* start up worker threads if MT mode */
    thread_init(settings.num_threads, main_base);
    /* save the PID in if we're a daemon, do this after thread_init due to
       a file descriptor handling bug somewhere in libevent */
    if (daemonize)
        save_pid(getpid(), pid_file);
    /* initialise clock event */
    clock_handler(0, 0, 0);
    /* initialise deletion array and timer event */
    deltotal = 200;
    delcurr = 0;
    if ((todelete = malloc(sizeof(item *) * deltotal)) == NULL) {
        perror("failed to allocate memory for deletion array");
        exit(EXIT_FAILURE);
    }
    delete_handler(0, 0, 0); /* sets up the event */
    /* create the initial listening udp connection, monitored on all threads */
    if (u_socket) {
        for (c = 0; c < settings.num_threads; c++) {
            /* this is guaranteed to hit all threads because we round-robin */
            dispatch_conn_new(*u_socket, conn_read, EV_READ | EV_PERSIST,
                              UDP_READ_BUFFER_SIZE, ascii_udp_prot);
        }
    }
    /* enter the event loop */
    event_base_loop(main_base, 0);
    /* remove the PID file if we're a daemon */
    if (daemonize)
        remove_pidfile(pid_file);
    /* Clean up strdup() call for bind() address */
    if (settings.inter)
      free(settings.inter);
    if (l_socket)
      free(l_socket);
    if (u_socket)
      free(u_socket);

    return 0;
}

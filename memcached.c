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
 *
 *  $Id$
 */
#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signal.h>
#include <sys/resource.h>
#include <sys/uio.h>

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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <time.h>
#include <event.h>
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
#if defined(__FreeBSD__)
# define IOV_MAX 1024
#endif
#endif

#include "memcached.h"

/*
 * forward declarations 
 */
static void drive_machine(conn *c);
static int new_socket(const bool is_udp);
static int server_socket(const int port, const bool is_udp);
static int try_read_command(conn *c);
static int try_read_network(conn *c);
static int try_read_udp(conn *c);

/* stats */
static void stats_reset(void);
static void stats_init(void);

/* defaults */
static void settings_init(void);

/* event handling, network IO */
static void event_handler(const int fd, const short which, void *arg);
static conn *conn_new(const int sfd, const int init_state, const int event_flags, const int read_buffer_size, const bool is_udp);
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

void pre_gdb(void);

/** exported globals **/
struct stats stats;
struct settings settings;

/** file scope variables **/
static item **todelete = 0;
static int delcurr;
static int deltotal;
static conn *listen_conn;

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
            return (rel_time_t) 1;
        return (rel_time_t) (exptime - stats.started);
    } else {
        return (rel_time_t) (exptime + current_time);
    }
}

static void stats_init(void) {
    stats.curr_items = stats.total_items = stats.curr_conns = stats.total_conns = stats.conn_structs = 0;
    stats.get_cmds = stats.set_cmds = stats.get_hits = stats.get_misses = 0;
    stats.curr_bytes = stats.bytes_read = stats.bytes_written = 0;

    /* make the time we started always be 2 seconds before we really
       did, so time(0) - time.started is never zero.  if so, things
       like 'settings.oldest_live' which act as booleans as well as
       values are now false in boolean context... */
    stats.started = time(0) - 2;
}

static void stats_reset(void) {
    stats.total_items = stats.total_conns = 0;
    stats.get_cmds = stats.set_cmds = stats.get_hits = stats.get_misses = 0;
    stats.bytes_read = stats.bytes_written = 0;
}

static void settings_init(void) {
    settings.port = 11211;
    settings.udpport = 0;
    settings.interface.s_addr = htonl(INADDR_ANY);
    settings.maxbytes = 64*1024*1024; /* default is 64MB */
    settings.maxconns = 1024;         /* to limit connections-related memory to about 5MB */
    settings.verbose = 0;
    settings.oldest_live = 0;
    settings.evict_to_free = 1;       /* push old items out of cache when memory runs out */
    settings.socketpath = NULL;       /* by default, not using a unix socket */
    settings.managed = false;
    settings.factor = 1.25;
    settings.chunk_size = 48;         /* space for a modest key and value */
}

/* returns true if a deleted item's delete-locked-time is over, and it
   should be removed from the namespace */
static bool item_delete_lock_over (item *it) {
    assert(it->it_flags & ITEM_DELETED);
    return (current_time >= it->exptime);
}

/* wrapper around assoc_find which does the lazy expiration/deletion logic */
static item *get_item_notedeleted(const char *key, const size_t nkey, int *delete_locked) {
    item *it = assoc_find(key, nkey);

    if (delete_locked) *delete_locked = 0;

    if (it != NULL && (it->it_flags & ITEM_DELETED)) {
        /* it's flagged as delete-locked.  let's see if that condition
           is past due, and the 5-second delete_timer just hasn't
           gotten to it yet... */
        if (! item_delete_lock_over(it)) {
            if (delete_locked) *delete_locked = 1;
            it = 0;
        }
    }
    if (it != NULL && settings.oldest_live != 0 && settings.oldest_live <= current_time &&
        it->time <= settings.oldest_live) {
        item_unlink(it);
        it = 0;
    }
    if (it != NULL && it->exptime != 0 && it->exptime <= current_time) {
        item_unlink(it);
        it = 0;
    }
    return it;
}

static item *get_item(const char *key, const size_t nkey) {
    return get_item_notedeleted(key, nkey, 0);
}

/*
 * Adds a message header to a connection.
 *
 * Returns 0 on success, -1 on out-of-memory.
 */
static int add_msghdr(conn *c)
{
    struct msghdr *msg;

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
    msg->msg_name = &c->request_addr;
    msg->msg_namelen = c->request_addr_size;

    c->msgbytes = 0;
    c->msgused++;

    if (c->udp) {
        /* Leave room for the UDP header, which we'll fill in later. */
        return add_iov(c, NULL, UDP_HEADER_SIZE);
    }

    return 0;
}

static conn **freeconns;
static int freetotal;
static int freecurr;

static void conn_init(void) {
    freetotal = 200;
    freecurr = 0;
    freeconns = (conn **)malloc(sizeof (conn *)*freetotal);
    /** TODO check for NULL **/
    return;
}

/*@null@*/
static conn *conn_new(const int sfd, const int init_state, const int event_flags, 
                      const int read_buffer_size, const bool is_udp) {
    conn *c;

    /* do we have a free conn structure from a previous close? */
    if (freecurr > 0) {
        c = freeconns[--freecurr];
    } else { /* allocate a new one */
        if (!(c = (conn *)malloc(sizeof(conn)))) {
            perror("malloc()");
            return NULL;
        }
        c->rbuf = c->wbuf = 0;
        c->ilist = 0;
        c->iov = 0;
        c->msglist = 0;
        c->hdrbuf = 0;

        c->rsize = read_buffer_size;
        c->wsize = DATA_BUFFER_SIZE;
        c->isize = ITEM_LIST_INITIAL;
        c->iovsize = IOV_LIST_INITIAL;
        c->msgsize = MSG_LIST_INITIAL;
        c->hdrsize = 0;

        c->rbuf = (char *) malloc((size_t)c->rsize);
        c->wbuf = (char *) malloc((size_t)c->wsize);
        c->ilist = (item **) malloc(sizeof(item *) * c->isize);
        c->iov = (struct iovec *) malloc(sizeof(struct iovec) * c->iovsize);
        c->msglist = (struct msghdr *) malloc(sizeof(struct msghdr) * c->msgsize);

        if (c->rbuf == 0 || c->wbuf == 0 || c->ilist == 0 || c->iov == 0 ||
                c->msglist == 0) {
            if (c->rbuf != 0) free(c->rbuf);
            if (c->wbuf != 0) free(c->wbuf);
            if (c->ilist !=0) free(c->ilist);
            if (c->iov != 0) free(c->iov);
            if (c->msglist != 0) free(c->msglist);
            free(c);
            perror("malloc()");
            return NULL;
        }

        stats.conn_structs++;
    }

    if (settings.verbose > 1) {
        if (init_state == conn_listening)
            fprintf(stderr, "<%d server listening\n", sfd);
        else if (is_udp)
            fprintf(stderr, "<%d server listening (udp)\n", sfd);
        else
            fprintf(stderr, "<%d new client connection\n", sfd);
    }

    c->sfd = sfd;
    c->udp = is_udp;
    c->state = init_state;
    c->rlbytes = 0;
    c->rbytes = c->wbytes = 0;
    c->wcurr = c->wbuf;
    c->rcurr = c->rbuf;
    c->ritem = 0;
    c->icurr = c->ilist;
    c->ileft = 0;
    c->iovused = 0;
    c->msgcurr = 0;
    c->msgused = 0;

    c->write_and_go = conn_read;
    c->write_and_free = 0;
    c->item = 0;
    c->bucket = -1;
    c->gen = 0;

    event_set(&c->event, sfd, event_flags, event_handler, (void *)c);
    c->ev_flags = event_flags;

    if (event_add(&c->event, 0) == -1) {
        if (freecurr < freetotal) {
            freeconns[freecurr++] = c;
        } else {
            if (c->hdrbuf)
                free (c->hdrbuf);
            free (c->msglist);
            free (c->rbuf);
            free (c->wbuf);
            free (c->ilist);
            free (c->iov);
            free (c);
        }
        return NULL;
    }

    stats.curr_conns++;
    stats.total_conns++;

    return c;
}

static void conn_cleanup(conn *c) {
    if (c->item) {
        item_free(c->item);
        c->item = 0;
    }

    if (c->ileft != 0) {
        for (; c->ileft > 0; c->ileft--,c->icurr++) {
            item_remove(*(c->icurr));
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
static void conn_free(conn *c) {
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
        if (c->iov)
            free(c->iov);
        free(c);
    }
}

static void conn_close(conn *c) {
    /* delete the event, the socket and the conn */
    event_del(&c->event);

    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closed.\n", c->sfd);

    close(c->sfd);
    accept_new_conns(true);
    conn_cleanup(c);

    /* if the connection has big buffers, just free it */
    if (c->rsize > READ_BUFFER_HIGHWAT) {
        conn_free(c);
    } else if (freecurr < freetotal) {
        /* if we have enough space in the free connections array, put the structure there */
        freeconns[freecurr++] = c;
    } else {
        /* try to enlarge free connections array */
        conn **new_freeconns = realloc((void*)freeconns, sizeof(conn *)*freetotal*2);
        if (new_freeconns) {
            freetotal *= 2;
            freeconns = new_freeconns;
            freeconns[freecurr++] = c;
        } else {
            conn_free(c);
        }
    }

    stats.curr_conns--;

    return;
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
    if (c->udp)
        return;

    if (c->rsize > READ_BUFFER_HIGHWAT && c->rbytes < DATA_BUFFER_SIZE) {
        if (c->rcurr != c->rbuf)
            memmove(c->rbuf, c->rcurr, (size_t) c->rbytes);

        char *newbuf = (char*) realloc((void*)c->rbuf, DATA_BUFFER_SIZE);

        if (newbuf) {
            c->rbuf = newbuf;
            c->rsize = DATA_BUFFER_SIZE;
        }
        /* TODO check other branch... */
        c->rcurr = c->rbuf;
    }

    if (c->isize > ITEM_LIST_HIGHWAT) {
        item **newbuf = (item**) realloc((void*)c->ilist, ITEM_LIST_INITIAL * sizeof(c->ilist[0]));
        if (newbuf) {
            c->ilist = newbuf;
            c->isize = ITEM_LIST_INITIAL;
        }
	/* TODO check error condition? */
    }

    if (c->msgsize > MSG_LIST_HIGHWAT) {
        struct msghdr *newbuf = (struct msghdr*) realloc((void*)c->msglist, MSG_LIST_INITIAL * sizeof(c->msglist[0]));
        if (newbuf) {
            c->msglist = newbuf;
            c->msgsize = MSG_LIST_INITIAL;
        }
	/* TODO check error condition? */
    }

    if (c->iovsize > IOV_LIST_HIGHWAT) {
        struct iovec* newbuf = (struct iovec *) realloc((void*)c->iov, IOV_LIST_INITIAL * sizeof(c->iov[0]));
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
    if (state != c->state) {
        if (state == conn_read) {
            conn_shrink(c);
            assoc_move_next_bucket();
        }
        c->state = state;
    }
}


/*
 * Ensures that there is room for another struct iovec in a connection's
 * iov list.
 *
 * Returns 0 on success, -1 on out-of-memory.
 */
static int ensure_iov_space(conn *c) {
    if (c->iovused >= c->iovsize) {
        int i, iovnum;
        struct iovec *new_iov = (struct iovec *) realloc(c->iov,
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

    do {
        m = &c->msglist[c->msgused - 1];

        /*
         * Limit UDP packets, and the first payloads of TCP replies, to
         * UDP_MAX_PAYLOAD_SIZE bytes.
         */
        limit_to_mtu = c->udp || (1 == c->msgused);

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
        m->msg_iov[m->msg_iovlen].iov_base = (void*) buf;
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

    if (c->msgused > c->hdrsize) {
        void *new_hdrbuf;
        if (c->hdrbuf)
            new_hdrbuf = realloc(c->hdrbuf, c->msgused * 2 * UDP_HEADER_SIZE);
        else
            new_hdrbuf = malloc(c->msgused * 2 * UDP_HEADER_SIZE);
        if (! new_hdrbuf)
            return -1;
        c->hdrbuf = (unsigned char *) new_hdrbuf;
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
        assert((void*) hdr == (void*) c->msglist[i].msg_iov[0].iov_base + UDP_HEADER_SIZE);
    }

    return 0;
}


static void out_string(conn *c, const char *str) {
    int len;

    if (settings.verbose > 1)
        fprintf(stderr, ">%d %s\n", c->sfd, str);

    len = strlen(str);
    if (len + 2 > c->wsize) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    strcpy(c->wbuf, str);
    strcpy(c->wbuf + len, "\r\n");
    c->wbytes = len + 2;
    c->wcurr = c->wbuf;

    conn_set_state(c, conn_write);
    c->write_and_go = conn_read;
    return;
}

/*
 * we get here after reading the value in set/add/replace commands. The command
 * has been stored in c->item_comm, and the item is ready in c->item.
 */

static void complete_nread(conn *c) {
    item *it = c->item;
    int comm = c->item_comm;
    item *old_it;
    int delete_locked = 0;
    char *key = ITEM_key(it);

    stats.set_cmds++;

    if (strncmp(ITEM_data(it) + it->nbytes - 2, "\r\n", 2) != 0) {
        out_string(c, "CLIENT_ERROR bad data chunk");
        goto err;
    }

    old_it = get_item_notedeleted(key, it->nkey, &delete_locked);

    if (old_it != NULL && comm == NREAD_ADD) {
        item_update(old_it);  /* touches item, promotes to head of LRU */
        out_string(c, "NOT_STORED");
        goto err;
    }

    if (old_it == NULL && comm == NREAD_REPLACE) {
        out_string(c, "NOT_STORED");
        goto err;
    }

    if (delete_locked != 0) {
        if (comm == NREAD_REPLACE || comm == NREAD_ADD) {
            out_string(c, "NOT_STORED");
            goto err;
        }

        /* but "set" commands can override the delete lock
         window... in which case we have to find the old hidden item
         that's in the namespace/LRU but wasn't returned by
         get_item.... because we need to replace it (below) */
        old_it = assoc_find(key, it->nkey);
    }

    if (old_it)
        item_replace(old_it, it);
    else
        item_link(it);

    c->item = 0;
    out_string(c, "STORED");
    return;

err:
     item_free(it);
     c->item = 0;
     return;
}

typedef struct token_s {
    char* value;
    size_t length;
} token_t;

#define COMMAND_TOKEN 0
#define SUBCOMMAND_TOKEN 1
#define KEY_TOKEN 1
#define KEY_MAX_LENGTH 250

#define MAX_TOKENS 6 

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
static size_t tokenize_command(char* command, token_t* tokens, const size_t max_tokens)  {
    char* cp;
    char* value = NULL;
    size_t length = 0;
    size_t ntokens = 0;

    assert(command != NULL && tokens != NULL && max_tokens > 1); 

    cp = command;
    while(*cp != '\0' && ntokens < max_tokens - 1) {
        if(*cp == ' ') {
            // If we've accumulated a token, this is the end of it. 
            if(length > 0) {
                tokens[ntokens].value = value;
                tokens[ntokens].length = length;
                ntokens++;
                length = 0;
                value = NULL;
            }
            *cp = '\0';
        } else {
            if(length == 0) {
                value = cp;
            }
            length++;
        }
        cp++;
    }

    if(ntokens < max_tokens - 1 && length > 0) {
        tokens[ntokens].value = value;
        tokens[ntokens].length = length;
        ntokens++;
    }

    /*
     * If we scanned the whole string, the terminal value pointer is null,
     * otherwise it is the first unprocessed character.
     */
    tokens[ntokens].value =  *cp == '\0' ? NULL : cp;
    tokens[ntokens].length = 0;
    ntokens++;

    return ntokens;
}

static void process_stat(conn *c, token_t* tokens, const size_t ntokens) {
    rel_time_t now = current_time;
    char* command;
    char* subcommand;

    if(ntokens < 2) {
        out_string(c, "CLIENT_ERROR bad command line");
        return;
    }

    command = tokens[COMMAND_TOKEN].value;

    if (ntokens == 2 && strcmp(command, "stats") == 0) {
        char temp[1024];
        pid_t pid = getpid();
        char *pos = temp;
        struct rusage usage;

        getrusage(RUSAGE_SELF, &usage);

        pos += sprintf(pos, "STAT pid %u\r\n", pid);
        pos += sprintf(pos, "STAT uptime %u\r\n", now);
        pos += sprintf(pos, "STAT time %ld\r\n", now + stats.started);
        pos += sprintf(pos, "STAT version " VERSION "\r\n");
        pos += sprintf(pos, "STAT pointer_size %d\r\n", 8 * sizeof(void*));
        pos += sprintf(pos, "STAT rusage_user %ld.%06ld\r\n", usage.ru_utime.tv_sec, usage.ru_utime.tv_usec);
        pos += sprintf(pos, "STAT rusage_system %ld.%06ld\r\n", usage.ru_stime.tv_sec, usage.ru_stime.tv_usec);
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
        pos += sprintf(pos, "STAT bytes_read %llu\r\n", stats.bytes_read);
        pos += sprintf(pos, "STAT bytes_written %llu\r\n", stats.bytes_written);
        pos += sprintf(pos, "STAT limit_maxbytes %llu\r\n", (unsigned long long) settings.maxbytes);
        pos += sprintf(pos, "END");
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

    if (strcmp(subcommand, "maps") == 0) {
        char *wbuf;
        int wsize = 8192; /* should be enough */
        int fd;
        int res;

        wbuf = (char *)malloc(wsize);
        if (wbuf == 0) {
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
        strcpy(wbuf + res, "END\r\n");
        c->write_and_free=wbuf;
        c->wcurr=wbuf;
        c->wbytes = res + 5; // Don't write the terminal '\0' 
        conn_set_state(c, conn_write);
        c->write_and_go = conn_read;
        close(fd);
        return;
    }

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
        if (buf == 0) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }

        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        conn_set_state(c, conn_write);
        c->write_and_go = conn_read;
        return;
    }

    if (strcmp(subcommand, "slabs")==0) {
        int bytes = 0;
        char *buf = slabs_stats(&bytes);
        if (!buf) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }
        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        conn_set_state(c, conn_write);
        c->write_and_go = conn_read;
        return;
    }

    if (strcmp(subcommand, "items")==0) {
        char buffer[4096];
        item_stats(buffer, 4096);
        out_string(c, buffer);
        return;
    }

    if (strcmp(subcommand, "sizes")==0) {
        int bytes = 0;
        char *buf = item_stats_sizes(&bytes);
        if (! buf) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }

        c->write_and_free = buf;
        c->wcurr = buf;
        c->wbytes = bytes;
        conn_set_state(c, conn_write);
        c->write_and_go = conn_read;
        return;
    }

    out_string(c, "ERROR");
}

/* ntokens is overwritten here... shrug.. */
static inline void process_get_command(conn *c, token_t* tokens, size_t ntokens) {
    char *key;
    size_t nkey;
    int i = 0;
    item *it;
    token_t* key_token = &tokens[KEY_TOKEN];

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
                out_string(c, "CLIENT_ERROR bad command line format");
                return;
            }
                
            stats.get_cmds++;
            it = get_item(key, nkey);
            if (it) {
                if (i >= c->isize) {
                    item **new_list = realloc(c->ilist, sizeof(item *)*c->isize*2);
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
                if (add_iov(c, "VALUE ", 6) != 0 ||
                    add_iov(c, ITEM_key(it), it->nkey) != 0 ||
                    add_iov(c, ITEM_suffix(it), it->nsuffix + it->nbytes) != 0)
                    {
                        break;
                    }
                if (settings.verbose > 1)
                    fprintf(stderr, ">%d sending key %s\n", c->sfd, ITEM_key(it));

                stats.get_hits++;
                it->refcount++;
                item_update(it);
                *(c->ilist + i) = it;
                i++;
                
            } else stats.get_misses++;
            
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
            
    if (settings.verbose > 1)
        fprintf(stderr, ">%d END\n", c->sfd);
    add_iov(c, "END\r\n", 5);
        
    if (c->udp && build_udp_headers(c) != 0) {
        out_string(c, "SERVER_ERROR out of memory");
    }
    else {
        conn_set_state(c, conn_mwrite);
        c->msgcurr = 0;
    }
    return;
}

static void process_update_command(conn *c, token_t* tokens, const size_t ntokens, int comm) {
    char *key;
    size_t nkey;
    int flags;
    time_t exptime;
    int vlen;
    item *it;

    if (tokens[KEY_TOKEN].length > KEY_MAX_LENGTH) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    key = tokens[KEY_TOKEN].value;
    nkey = tokens[KEY_TOKEN].length;

    flags = strtoul(tokens[2].value, NULL, 10);
    exptime = strtol(tokens[3].value, NULL, 10);
    vlen = strtol(tokens[4].value, NULL, 10);
    
    if(errno == ERANGE || ((flags == 0 || exptime == 0) && errno == EINVAL)) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
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
        if (! item_size_ok(key, nkey, flags, vlen + 2))
            out_string(c, "SERVER_ERROR object too large for cache");
        else
            out_string(c, "SERVER_ERROR out of memory");
        /* swallow the data line */
        c->write_and_go = conn_swallow;
        c->sbytes = vlen+2;
        return;
    }
    
    c->item_comm = comm;
    c->item = it;
    c->ritem = ITEM_data(it);
    c->rlbytes = it->nbytes;
    conn_set_state(c, conn_nread);
    return;
}

static void process_arithmetic_command(conn *c, token_t* tokens, const size_t ntokens, const int incr) {
    char temp[32];
    unsigned int value;
    item *it;
    unsigned int delta;
    char *key;
    size_t nkey;
    int res;
    char *ptr;
    
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

    it = get_item(key, nkey);
    if (!it) {
        out_string(c, "NOT_FOUND");
        return;
    }

    delta = strtoul(tokens[2].value, NULL, 10);
        
    if(errno == ERANGE) {
        out_string(c, "CLIENT_ERROR bad command line format");
        return;
    }

    ptr = ITEM_data(it);
    while ((*ptr != '\0') && (*ptr<'0' && *ptr>'9')) ptr++;    // BUG: can't be true
        
    value = strtol(ptr, NULL, 10);

    if(errno == ERANGE) {
        out_string(c, "CLIENT_ERROR cannot increment or decrement non-numeric value");
        return;
    }
    
    if (incr != 0)
        value+=delta;
    else {
        if (delta >= value) value = 0;
        else value-=delta;
    }
    snprintf(temp, 32, "%u", value);
    res = strlen(temp);
    if (res + 2 > it->nbytes) { /* need to realloc */
        item *new_it;
        new_it = item_alloc(ITEM_key(it), it->nkey, atoi(ITEM_suffix(it) + 1), it->exptime, res + 2 );
        if (new_it == 0) {
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }
        memcpy(ITEM_data(new_it), temp, res);
        memcpy(ITEM_data(new_it) + res, "\r\n", 2);
        item_replace(it, new_it);
    } else { /* replace in-place */
        memcpy(ITEM_data(it), temp, res);
        memset(ITEM_data(it) + res, ' ', it->nbytes-res-2);
    }
    out_string(c, temp);
    return;
}

static void process_delete_command(conn *c, token_t* tokens, const size_t ntokens) {
    char *key;
    size_t nkey;
    item *it;
    time_t exptime = 0;
    
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

    it = get_item(key, nkey);
    if (!it) {
        out_string(c, "NOT_FOUND");
        return;
    }
    
    if (exptime == 0) {
        item_unlink(it);
        out_string(c, "DELETED");
        return;
    }
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
            out_string(c, "SERVER_ERROR out of memory");
            return;
        }
    }
    
    it->refcount++;
    /* use its expiration time as its deletion time now */
    it->exptime = realtime(exptime);
    it->it_flags |= ITEM_DELETED;
    todelete[delcurr++] = it;
    out_string(c, "DELETED");
    return;
}

static void process_command(conn *c, char *command) {
    
    token_t tokens[MAX_TOKENS];
    size_t ntokens;
    int comm;

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
        
        process_get_command(c, tokens, ntokens);

    } else if (ntokens == 6 && 
               ((strcmp(tokens[COMMAND_TOKEN].value, "add") == 0 && (comm = NREAD_ADD)) || 
                (strcmp(tokens[COMMAND_TOKEN].value, "set") == 0 && (comm = NREAD_SET)) ||
                (strcmp(tokens[COMMAND_TOKEN].value, "replace") == 0 && (comm = NREAD_REPLACE)))) {
        
        process_update_command(c, tokens, ntokens, comm);

    } else if (ntokens == 4 && (strcmp(tokens[COMMAND_TOKEN].value, "incr") == 0)) {

        process_arithmetic_command(c, tokens, ntokens, 1);

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
        if (sscanf(tokens[1].value, "%u:%u", &bucket,&gen) == 2) {
            /* we never write anything back, even if input's wrong */
            if ((bucket < 0) || (bucket >= MAX_BUCKETS) || (gen<=0)) {
                /* do nothing, bad input */
            } else {
                c->bucket = bucket;
                c->gen = gen;
            }
            conn_set_state(c, conn_read);
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

        settings.oldest_live = realtime(exptime) - 1;
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

    assert(c->rcurr <= c->rbuf + c->rsize);

    if (c->rbytes == 0)
        return 0;
    el = memchr(c->rcurr, '\n', c->rbytes);
    if (!el)
        return 0;
    cont = el + 1;
    if (el - c->rcurr > 1 && *(el - 1) == '\r') {
        el--;
    }
    *el = '\0';

    assert(cont <= c->rcurr + c->rbytes);

    process_command(c, c->rcurr);

    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    assert(c->rcurr <= c->rbuf + c->rsize);

    return 1;
}

/*
 * read a UDP request.
 * return 0 if there's nothing to read.
 */
static int try_read_udp(conn *c) {
    int res;

    c->request_addr_size = sizeof(c->request_addr);
    res = recvfrom(c->sfd, c->rbuf, c->rsize,
                   0, &c->request_addr, &c->request_addr_size);
    if (res > 8) {
        unsigned char *buf = (unsigned char *)c->rbuf;
        stats.bytes_read += res;

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

    if (c->rcurr != c->rbuf) {
        if (c->rbytes != 0) /* otherwise there's nothing to copy */
            memmove(c->rbuf, c->rcurr, c->rbytes);
        c->rcurr = c->rbuf;
    }

    while (1) {
        if (c->rbytes >= c->rsize) {
            char *new_rbuf = realloc(c->rbuf, c->rsize*2);
            if (!new_rbuf) {
                if (settings.verbose > 0)
                    fprintf(stderr, "Couldn't realloc input buffer\n");
                c->rbytes = 0; /* ignore what we read */
                out_string(c, "SERVER_ERROR out of memory");
                c->write_and_go = conn_closing;
                return 1;
            }
            c->rcurr  = c->rbuf = new_rbuf;
            c->rsize *= 2;
        }

        /* unix socket mode doesn't need this, so zeroed out.  but why
         * is this done for every command?  presumably for UDP
         * mode.  */
        if (!settings.socketpath) {
            c->request_addr_size = sizeof(c->request_addr);
        } else {
            c->request_addr_size = 0;
        }

        res = read(c->sfd, c->rbuf + c->rbytes, c->rsize - c->rbytes);
        if (res > 0) {
            stats.bytes_read += res;
            gotdata = 1;
            c->rbytes += res;
            continue;
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
    if (c->ev_flags == new_flags)
        return true;
    if (event_del(&c->event) == -1) return false;
    event_set(&c->event, c->sfd, new_flags, event_handler, (void *)c);
    c->ev_flags = new_flags;
    if (event_add(&c->event, 0) == -1) return false;
    return true;
}

/*
 * Sets whether we are listening for new connections or not.
 */
void accept_new_conns(const bool do_accept) {
    if (do_accept) {
        update_event(listen_conn, EV_READ | EV_PERSIST);
        if (listen(listen_conn->sfd, 1024) != 0) {
            perror("listen");
        }
    }
    else {
        update_event(listen_conn, 0);
        if (listen(listen_conn->sfd, 0) != 0) {
            perror("listen");
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
    int res;

    if (c->msgcurr < c->msgused &&
            c->msglist[c->msgcurr].msg_iovlen == 0) {
        /* Finished writing the current msg; advance to the next. */
        c->msgcurr++;
    }
    if (c->msgcurr < c->msgused) {
        struct msghdr *m = &c->msglist[c->msgcurr];
        res = sendmsg(c->sfd, m, 0);
        if (res > 0) {
            stats.bytes_written += res;

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

        if (c->udp)
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
    socklen_t addrlen;
    struct sockaddr addr;
    conn *newc;
    int res;

    while (!stop) {
        switch(c->state) {
        case conn_listening:
            addrlen = sizeof(addr);
            if ((sfd = accept(c->sfd, &addr, &addrlen)) == -1) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    stop = true;
                    break;
                } else if (errno == EMFILE) {
                    if (settings.verbose > 0)
                        fprintf(stderr, "Too many open connections\n");
                    accept_new_conns(false);
                } else {
                    perror("accept()");
                }
                break;
            }
            if ((flags = fcntl(sfd, F_GETFL, 0)) < 0 ||
                fcntl(sfd, F_SETFL, flags | O_NONBLOCK) < 0) {
                perror("setting O_NONBLOCK");
                close(sfd);
                break;
            }
            newc = conn_new(sfd, conn_read, EV_READ | EV_PERSIST,
                            DATA_BUFFER_SIZE, false);
            if (!newc) {
                if (settings.verbose > 0)
                    fprintf(stderr, "couldn't create new connection\n");
                close(sfd);
                break;
            }

            break;

        case conn_read:
            if (try_read_command(c) != 0) {
                continue;
            }
            if ((c->udp ? try_read_udp(c) : try_read_network(c)) != 0) {
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

        case conn_nread:
            /* we are reading rlbytes into ritem; */
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
                stats.bytes_read += res;
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
                conn_set_state(c, conn_read);
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
                stats.bytes_read += res;
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
            if (c->iovused == 0 || (c->udp && c->iovused == 1)) {
                if (add_iov(c, c->wcurr, c->wbytes) != 0 ||
                    (c->udp && build_udp_headers(c) != 0)) {
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
                    conn_set_state(c, conn_read);
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
            if (c->udp)
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
    c->which = which;

    /* sanity */
    if (fd != c->sfd) {
        if (settings.verbose > 0)
            fprintf(stderr, "Catastrophic: event fd doesn't match conn fd!\n");
        conn_close(c);
        return;
    }

    /* do as much I/O as possible until we block */
    drive_machine(c);

    /* wait for next event */
    return;
}

static int new_socket(const bool is_udp) {
    int sfd;
    int flags;

    if ((sfd = socket(AF_INET, is_udp ? SOCK_DGRAM : SOCK_STREAM, 0)) == -1) {
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
        avg = ((unsigned int) min + max) / 2;
        if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, &avg, intsize) == 0) {
            last_good = avg;
            min = avg + 1;
        } else {
            max = avg - 1;
        }
    }

    if (settings.verbose > 1)
        fprintf(stderr, "<%d send buffer was %d, now %d\n", sfd, old_size, last_good);
}


static int server_socket(const int port, const bool is_udp) {
    int sfd;
    struct linger ling = {0, 0};
    struct sockaddr_in addr;
    int flags =1;

    if ((sfd = new_socket(is_udp)) == -1) {
        return -1;
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    if (is_udp) {
        maximize_sndbuf(sfd);
    } else {
        setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
        setsockopt(sfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));
        setsockopt(sfd, IPPROTO_TCP, TCP_NODELAY, &flags, sizeof(flags));
    }

    /*
     * the memset call clears nonstandard fields in some impementations
     * that otherwise mess things up.
     */
    memset(&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr = settings.interface;
    if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind()");
        close(sfd);
        return -1;
    }
    if (!is_udp && listen(sfd, 1024) == -1) {
        perror("listen()");
        close(sfd);
        return -1;
    }
    return sfd;
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

static int server_socket_unix(char *path) {
    int sfd;
    struct linger ling = {0, 0};
    struct sockaddr_un addr;
    struct stat tstat;
    int flags =1;

    if (!path) {
        return -1;
    }

    if ((sfd = new_socket_unix()) == -1) {
        return -1;
    }

    /*
     * Clean up a previous socket file if we left it around
     */
    if (lstat(path, &tstat) == 0) {
        if (S_ISSOCK(tstat.st_mode))
            unlink(path);
    }

    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_KEEPALIVE, &flags, sizeof(flags));
    setsockopt(sfd, SOL_SOCKET, SO_LINGER, &ling, sizeof(ling));

    /*
     * the memset call clears nonstandard fields in some impementations
     * that otherwise mess things up.
     */
    memset(&addr, 0, sizeof(addr));

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, path);
    if (bind(sfd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
        perror("bind()");
        close(sfd);
        return -1;
    }
    if (listen(sfd, 1024) == -1) {
        perror("listen()");
        close(sfd);
        return -1;
    }
    return sfd;
}

/* listening socket */
static int l_socket=0;

/* udp socket */
static int u_socket=-1;

/* invoke right before gdb is called, on assert */
void pre_gdb(void) {
    int i = 0;
    if (l_socket > -1) close(l_socket);
    if (u_socket > -1) close(u_socket);
    for (i=3; i<=500; i++) close(i); /* so lame */
    kill(getpid(), SIGABRT);
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
    current_time = (rel_time_t) (time(0) - stats.started);
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
    evtimer_add(&deleteevent, &t);
    {
        int i=0, j=0;
        for (i=0; i<delcurr; i++) {
            item *it = todelete[i];
            if (item_delete_lock_over(it)) {
                assert(it->refcount > 0);
                it->it_flags &= ~ITEM_DELETED;
                item_unlink(it);
                item_remove(it);
            } else {
                todelete[j++] = it;
            }
        }
        delcurr = j;
    }
}

static void usage(void) {
    printf(PACKAGE " " VERSION "\n");
    printf("-p <num>      TCP port number to listen on (default: 11211)\n");
    printf("-U <num>      UDP port number to listen on (default: 0, off)\n");
    printf("-s <file>     unix socket path to listen on (disables network support)\n");
    printf("-l <ip_addr>  interface to listen on, default is INDRR_ANY\n");
    printf("-d            run as a daemon\n");
    printf("-r            maximize core file limit\n");
    printf("-u <username> assume identity of <username> (only when run as root)\n");
    printf("-m <num>      max memory to use for items in megabytes, default is 64 MB\n");
    printf("-M            return error on memory exhausted (rather than removing items)\n");
    printf("-c <num>      max simultaneous connections, default is 1024\n");
    printf("-k            lock down all paged memory\n");
    printf("-v            verbose (print errors/warnings while in event loop)\n");
    printf("-vv           very verbose (also print client commands/reponses)\n");
    printf("-h            print this help and exit\n");
    printf("-i            print memcached and libevent license\n");
    printf("-b            run a managed instanced (mnemonic: buckets)\n");
    printf("-P <file>     save PID in <file>, only used with -d option\n");
    printf("-f <factor>   chunk size growth factor, default 1.25\n");
    printf("-n <bytes>    minimum space allocated for key+value+flags, default 48\n");
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
    if (!pid_file)
        return;

    if (!(fp = fopen(pid_file,"w"))) {
        fprintf(stderr,"Could not open the pid file %s for writing\n",pid_file);
        return;
    }

    fprintf(fp,"%ld\n",(long) pid);
    if (fclose(fp) == -1) {
        fprintf(stderr,"Could not close the pid file %s.\n",pid_file);
        return;
    }
}

static void remove_pidfile(const char *pid_file) {
  if (!pid_file)
      return;

  if (unlink(pid_file) != 0) {
      fprintf(stderr,"Could not remove the pid file %s.\n",pid_file);
  }

}


static void sig_handler(const int sig) {
    printf("SIGINT handled.\n");
    exit(EXIT_SUCCESS);
}

int main (int argc, char **argv) {
    int c;
    conn *u_conn;
    struct in_addr addr;
    bool lock_memory = false;
    bool daemonize = false;
    int maxcore = 0;
    char *username = NULL;
    struct passwd *pw;
    struct sigaction sa;
    struct rlimit rlim;
    char *pid_file = NULL;

    /* handle SIGINT */
    signal(SIGINT, sig_handler);

    /* init settings */
    settings_init();

    /* set stderr non-buffering (for running under, say, daemontools) */
    setbuf(stderr, NULL);

    /* process arguments */
    while ((c = getopt(argc, argv, "bp:s:U:m:Mc:khirvdl:u:P:f:s:")) != -1) {
        switch (c) {
        case 'U':
            settings.udpport = atoi(optarg);
            break;
        case 'b':
            settings.managed = true;
            break;
        case 'p':
            settings.port = atoi(optarg);
            break;
        case 's':
            settings.socketpath = optarg;
            break;
        case 'm':
            settings.maxbytes = ((size_t)atoi(optarg))*1024*1024;
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
            if (inet_pton(AF_INET, optarg, &addr) != 0) {
                fprintf(stderr, "Illegal address: %s\n", optarg);
                return 1;
            } else {
                settings.interface = addr;
            }
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
        if (getrlimit(RLIMIT_CORE, &rlim)==0) {
            rlim_new.rlim_cur = rlim_new.rlim_max = RLIM_INFINITY;
            if (setrlimit(RLIMIT_CORE, &rlim_new)!=0) {
                /* failed. try raising just to the old max */
                rlim_new.rlim_cur = rlim_new.rlim_max =
                    rlim.rlim_max;
                (void) setrlimit(RLIMIT_CORE, &rlim_new);
            }
        }
        /*
         * getrlimit again to see what we ended up with. Only fail if
         * the soft limit ends up 0, because then no core files will be
         * created at all.
         */

        if ((getrlimit(RLIMIT_CORE, &rlim)!=0) || rlim.rlim_cur==0) {
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
        l_socket = server_socket(settings.port, 0);
        if (l_socket == -1) {
            fprintf(stderr, "failed to listen\n");
            exit(EXIT_FAILURE);
        }
    }

    if (settings.udpport > 0 && settings.socketpath == NULL) {
        /* create the UDP listening socket and bind it */
        u_socket = server_socket(settings.udpport, 1);
        if (u_socket == -1) {
            fprintf(stderr, "failed to listen on UDP port %d\n", settings.udpport);
            exit(EXIT_FAILURE);
        }
    }

    /* lose root privileges if we have them */
    if (getuid()== 0 || geteuid()==0) {
        if (username==0 || *username=='\0') {
            fprintf(stderr, "can't run as root without the -u switch\n");
            return 1;
        }
        if ((pw = getpwnam(username)) == 0) {
            fprintf(stderr, "can't find the user %s to switch to\n", username);
            return 1;
        }
        if (setgid(pw->pw_gid)<0 || setuid(pw->pw_uid)<0) {
            fprintf(stderr, "failed to assume identity of user %s\n", username);
            return 1;
        }
    }

    /* create unix mode sockets after dropping privileges */
    if (settings.socketpath != NULL) {
        l_socket = server_socket_unix(settings.socketpath);
        if (l_socket == -1) {
            fprintf(stderr, "failed to listen\n");
            exit(EXIT_FAILURE);
        }
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


    /* initialize other stuff */
    item_init();
    event_init();
    stats_init();
    assoc_init();
    conn_init();
    slabs_init(settings.maxbytes, settings.factor);

    /* managed instance? alloc and zero a bucket array */
    if (settings.managed) {
        buckets = malloc(sizeof(int)*MAX_BUCKETS);
        if (buckets == 0) {
            fprintf(stderr, "failed to allocate the bucket array");
            exit(EXIT_FAILURE);
        }
        memset(buckets, 0, sizeof(int)*MAX_BUCKETS);
    }

    /* lock paged memory if needed */
    if (lock_memory) {
#ifdef HAVE_MLOCKALL
        mlockall(MCL_CURRENT | MCL_FUTURE);
#else
        fprintf(stderr, "warning: mlockall() not supported on this platform.  proceeding without.\n");
#endif
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
    /* create the initial listening connection */
    if (!(listen_conn = conn_new(l_socket, conn_listening, EV_READ | EV_PERSIST, 1, false))) {
        fprintf(stderr, "failed to create listening connection");
        exit(EXIT_FAILURE);
    }
    /* create the initial listening udp connection */
    if (u_socket > -1 &&
        !(u_conn = conn_new(u_socket, conn_read, EV_READ | EV_PERSIST, UDP_READ_BUFFER_SIZE, true))) {
        fprintf(stderr, "failed to create udp connection");
        exit(EXIT_FAILURE);
    }
    /* initialise clock event */
    clock_handler(0,0,0);
    /* initialise deletion array and timer event */
    deltotal = 200; delcurr = 0;
    todelete = malloc(sizeof(item *)*deltotal);
    delete_handler(0,0,0); /* sets up the event */
    /* save the PID in if we're a daemon */
    if (daemonize)
        save_pid(getpid(),pid_file);
    /* enter the loop */
    event_loop(0);
    /* remove the PID file if we're a daemon */
    if (daemonize)
        remove_pidfile(pid_file);
    return 0;
}

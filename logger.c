/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <ctype.h>
#include <stdarg.h>

#if defined(__sun)
#include <atomic.h>
#endif

#include "memcached.h"
#include "bipbuffer.h"

#ifdef LOGGER_DEBUG
#define L_DEBUG(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)
#else
#define L_DEBUG(...)
#endif


/* TODO: put this in a struct and ditch the global vars. */
static logger *logger_stack_head = NULL;
static logger *logger_stack_tail = NULL;
static unsigned int logger_count = 0;
static volatile int do_run_logger_thread = 1;
static pthread_t logger_tid;
pthread_mutex_t logger_stack_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t logger_stack_cond = PTHREAD_COND_INITIALIZER;

pthread_key_t logger_key;

#if !defined(HAVE_GCC_64ATOMICS) && !defined(__sun)
pthread_mutex_t logger_atomics_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define WATCHER_LIMIT 20
logger_watcher *watchers[20];
struct pollfd watchers_pollfds[20];
int watcher_count = 0;

#define WATCHER_ALL -1
static int logger_thread_poll_watchers(int force_poll, int watcher);

/* helpers for logger_log */

static void _logger_log_text(logentry *e, const entry_details *d, const void *entry, va_list ap) {
    int reqlen = d->reqlen;
    int total = vsnprintf((char *) e->data, reqlen, d->format, ap);
    if (total <= 0) {
        fprintf(stderr, "LOGGER: Failed to vsnprintf a text entry: (total) %d\n", total);
    }
    e->size = total + 1; // null byte
}

static void _logger_log_evictions(logentry *e, const entry_details *d, const void *entry, va_list ap) {
    item *it = (item *)entry;
    struct logentry_eviction *le = (struct logentry_eviction *) e->data;

    le->exptime = (it->exptime > 0) ? (long long int)(it->exptime - current_time) : (long long int) -1;
    le->latime = current_time - it->time;
    le->it_flags = it->it_flags;
    le->nkey = it->nkey;
    le->nbytes = it->nbytes;
    le->clsid = ITEM_clsid(it);
    memcpy(le->key, ITEM_key(it), it->nkey);
    e->size = sizeof(struct logentry_eviction) + le->nkey;
}
#ifdef EXTSTORE
static void _logger_log_ext_write(logentry *e, const entry_details *d, const void *entry, va_list ap) {
    item *it = (item *)entry;
    int ew_bucket = va_arg(ap, int);

    struct logentry_ext_write *le = (struct logentry_ext_write *) e->data;
    le->exptime = (it->exptime > 0) ? (long long int)(it->exptime - current_time) : (long long int) -1;
    le->latime = current_time - it->time;
    le->it_flags = it->it_flags;
    le->nkey = it->nkey;
    le->clsid = ITEM_clsid(it);
    le->bucket = (uint8_t)ew_bucket;
    memcpy(le->key, ITEM_key(it), it->nkey);
    e->size = sizeof(struct logentry_ext_write) + le->nkey;
}
#endif
// 0 == nf, 1 == found. 2 == flushed. 3 == expired.
// might be useful to store/print the flags an item has?
// could also collapse this and above code into an "item status" struct. wait
// for more endpoints to be written before making it generic, though.
static void _logger_log_item_get(logentry *e, const entry_details *d, const void *entry, va_list ap) {
    int was_found = va_arg(ap, int);
    char *key = va_arg(ap, char *);
    int nkey = va_arg(ap, int);
    int nbytes = va_arg(ap, int);
    uint8_t clsid = va_arg(ap, int);
    int sfd = va_arg(ap, int);

    struct logentry_item_get *le = (struct logentry_item_get *) e->data;
    le->was_found = was_found;
    le->nkey = nkey;
    le->nbytes = nbytes;
    le->clsid = clsid;
    memcpy(le->key, key, nkey);
    le->sfd = sfd;
    e->size = sizeof(struct logentry_item_get) + nkey;
}

static void _logger_log_item_store(logentry *e, const entry_details *d, const void *entry, va_list ap) {
    enum store_item_type status = va_arg(ap, enum store_item_type);
    int comm = va_arg(ap, int);
    char *key = va_arg(ap, char *);
    int nkey = va_arg(ap, int);
    int nbytes = va_arg(ap, int);
    rel_time_t ttl = va_arg(ap, rel_time_t);
    uint8_t clsid = va_arg(ap, int);
    int sfd = va_arg(ap, int);

    struct logentry_item_store *le = (struct logentry_item_store *) e->data;
    le->status = status;
    le->cmd = comm;
    le->nkey = nkey;
    le->nbytes = nbytes;
    le->clsid = clsid;
    if (ttl != 0) {
        le->ttl = ttl - current_time;
    } else {
        le->ttl = 0;
    }
    memcpy(le->key, key, nkey);
    le->sfd = sfd;
    e->size = sizeof(struct logentry_item_store) + nkey;
}

static void _logger_log_conn_event(logentry *e, const entry_details *d, const void *entry, va_list ap) {
    struct sockaddr_in6 *addr = va_arg(ap, struct sockaddr_in6 *);
    socklen_t addrlen = va_arg(ap, socklen_t);
    enum network_transport transport = va_arg(ap, enum network_transport);
    enum close_reasons reason = va_arg(ap, enum close_reasons);
    int sfd = va_arg(ap, int);

    struct logentry_conn_event *le = (struct logentry_conn_event *) e->data;

    memcpy(&le->addr, addr, addrlen);
    le->sfd = sfd;
    le->transport = transport;
    le->reason = reason;
    e->size = sizeof(struct logentry_conn_event);
}

/*************************
 * Util functions used by the logger background thread
 *************************/

static int _logger_util_addr_endpoint(struct sockaddr_in6 *addr, char *rip,
        size_t riplen, unsigned short *rport) {
    memset(rip, 0, riplen);

    switch (addr->sin6_family) {
        case AF_INET:
            inet_ntop(AF_INET, &((struct sockaddr_in *) addr)->sin_addr,
                    rip, riplen - 1);
            *rport = ntohs(((struct sockaddr_in *) addr)->sin_port);
            break;
        case AF_INET6:
            inet_ntop(AF_INET6, &((struct sockaddr_in6 *) addr)->sin6_addr,
                    rip, riplen - 1);
            *rport = ntohs(((struct sockaddr_in6 *) addr)->sin6_port);
            break;
#ifndef DISABLE_UNIX_SOCKET
        // Connections on Unix socket transports have c->request_addr zeroed out.
        case AF_UNSPEC:
        case AF_UNIX:
            strncpy(rip, "unix", strlen("unix") + 1);
            *rport = 0;
            break;
#endif // #ifndef DISABLE_UNIX_SOCKET
    }

    return 0;
}

/*************************
 * Logger background thread functions. Aggregates per-worker buffers and
 * writes to any watchers.
 *************************/

#define LOGGER_PARSE_SCRATCH 4096

static int _logger_parse_text(logentry *e, char *scratch) {
    return snprintf(scratch, LOGGER_PARSE_SCRATCH, "ts=%d.%d gid=%llu %s\n",
            (int)e->tv.tv_sec, (int)e->tv.tv_usec,
            (unsigned long long) e->gid, (char *) e->data);
}

static int _logger_parse_ise(logentry *e, char *scratch) {
    int total;
    const char *cmd = "na";
    char keybuf[KEY_MAX_URI_ENCODED_LENGTH];
    struct logentry_item_store *le = (struct logentry_item_store *) e->data;
    const char * const status_map[] = {
        "not_stored", "stored", "exists", "not_found", "too_large", "no_memory" };
    const char * const cmd_map[] = {
        "null", "add", "set", "replace", "append", "prepend", "cas" };

    if (le->cmd <= 6)
        cmd = cmd_map[le->cmd];

    uriencode(le->key, keybuf, le->nkey, KEY_MAX_URI_ENCODED_LENGTH);
    total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
            "ts=%d.%d gid=%llu type=item_store key=%s status=%s cmd=%s ttl=%u clsid=%u cfd=%d size=%d\n",
            (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid,
            keybuf, status_map[le->status], cmd, le->ttl, le->clsid, le->sfd,
            le->nbytes > 0 ? le->nbytes - 2 : 0); // CLRF
    return total;
}

static int _logger_parse_ige(logentry *e, char *scratch) {
    int total;
    struct logentry_item_get *le = (struct logentry_item_get *) e->data;
    char keybuf[KEY_MAX_URI_ENCODED_LENGTH];
    const char * const was_found_map[] = {
        "not_found", "found", "flushed", "expired" };

    uriencode(le->key, keybuf, le->nkey, KEY_MAX_URI_ENCODED_LENGTH);
    total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
            "ts=%d.%d gid=%llu type=item_get key=%s status=%s clsid=%u cfd=%d size=%d\n",
            (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid,
            keybuf, was_found_map[le->was_found], le->clsid, le->sfd,
            le->nbytes > 0 ? le->nbytes - 2 : 0); // CLRF
    return total;
}

static int _logger_parse_ee(logentry *e, char *scratch) {
    int total;
    char keybuf[KEY_MAX_URI_ENCODED_LENGTH];
    struct logentry_eviction *le = (struct logentry_eviction *) e->data;
    uriencode(le->key, keybuf, le->nkey, KEY_MAX_URI_ENCODED_LENGTH);
    total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
            "ts=%d.%d gid=%llu type=eviction key=%s fetch=%s ttl=%lld la=%d clsid=%u size=%d\n",
            (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid,
            keybuf, (le->it_flags & ITEM_FETCHED) ? "yes" : "no",
            (long long int)le->exptime, le->latime, le->clsid,
            le->nbytes > 0 ? le->nbytes - 2 : 0); // CLRF

    return total;
}

#ifdef EXTSTORE
static int _logger_parse_extw(logentry *e, char *scratch) {
    int total;
    char keybuf[KEY_MAX_URI_ENCODED_LENGTH];
    struct logentry_ext_write *le = (struct logentry_ext_write *) e->data;
    uriencode(le->key, keybuf, le->nkey, KEY_MAX_URI_ENCODED_LENGTH);
    total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
            "ts=%d.%d gid=%llu type=extwrite key=%s fetch=%s ttl=%lld la=%d clsid=%u bucket=%u\n",
            (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid,
            keybuf, (le->it_flags & ITEM_FETCHED) ? "yes" : "no",
            (long long int)le->exptime, le->latime, le->clsid, le->bucket);

    return total;
}
#endif

static int _logger_parse_cne(logentry *e, char *scratch) {
    int total;
    unsigned short rport;
    char rip[64];
    struct logentry_conn_event *le = (struct logentry_conn_event *) e->data;
    const char * const transport_map[] = { "local", "tcp", "udp" };

    _logger_util_addr_endpoint(&le->addr, rip, sizeof(rip), &rport);

    total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
            "ts=%d.%d gid=%llu type=conn_new rip=%s rport=%hu transport=%s cfd=%d\n",
            (int) e->tv.tv_sec, (int) e->tv.tv_usec, (unsigned long long) e->gid,
            rip, rport, transport_map[le->transport], le->sfd);

    return total;
}

static int _logger_parse_cce(logentry *e, char *scratch) {
    int total;
    unsigned short rport;
    char rip[64];
    struct logentry_conn_event *le = (struct logentry_conn_event *) e->data;
    const char * const transport_map[] = { "local", "tcp", "udp" };
    const char * const reason_map[] = { "error", "normal", "idle_timeout", "shutdown" };

    _logger_util_addr_endpoint(&le->addr, rip, sizeof(rip), &rport);

    total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
            "ts=%d.%d gid=%llu type=conn_close rip=%s rport=%hu transport=%s reason=%s cfd=%d\n",
            (int) e->tv.tv_sec, (int) e->tv.tv_usec, (unsigned long long) e->gid,
            rip, rport, transport_map[le->transport],
            reason_map[le->reason], le->sfd);

    return total;
}

#ifdef PROXY
// TODO (v2): the length caps here are all magic numbers. Haven't thought of
// something yet that I like better.
// Should at least make a define to the max log len (1024) and do some math
// here.
static void _logger_log_proxy_req(logentry *e, const entry_details *d, const void *entry, va_list ap) {
    char *req = va_arg(ap, char *);
    int reqlen = va_arg(ap, uint32_t);
    long elapsed = va_arg(ap, long);
    unsigned short type = va_arg(ap, int);
    unsigned short code = va_arg(ap, int);
    int status = va_arg(ap, int);
    char *detail = va_arg(ap, char *);
    int dlen = va_arg(ap, int);
    char *be_name = va_arg(ap, char *);
    char *be_port = va_arg(ap, char *);

    struct logentry_proxy_req *le = (void *)e->data;
    le->type = type;
    le->code = code;
    le->status = status;
    le->dlen = dlen;
    le->elapsed = elapsed;
    le->be_namelen = strlen(be_name);
    le->be_portlen = strlen(be_port);
    char *data = le->data;
    if (req[reqlen-2] == '\r') {
        reqlen -= 2;
    } else {
        reqlen--;
    }
    if (reqlen > 300) {
        reqlen = 300;
    }
    if (dlen > 150) {
        dlen = 150;
    }
    // be_namelen and be_portlen can't be longer than 255+6
    le->reqlen = reqlen;
    memcpy(data, req, reqlen);
    data += reqlen;
    memcpy(data, detail, dlen);
    data += dlen;
    memcpy(data, be_name, le->be_namelen);
    data += le->be_namelen;
    memcpy(data, be_port, le->be_portlen);
    e->size = sizeof(struct logentry_proxy_req) + reqlen + dlen + le->be_namelen + le->be_portlen;
}

static int _logger_parse_prx_req(logentry *e, char *scratch) {
    int total;
    struct logentry_proxy_req *le = (void *)e->data;

    total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
            "ts=%d.%d gid=%llu type=proxy_req elapsed=%lu type=%d code=%d status=%d be=%.*s:%.*s detail=%.*s req=%.*s\n",
            (int) e->tv.tv_sec, (int) e->tv.tv_usec, (unsigned long long) e->gid,
            le->elapsed, le->type, le->code, le->status,
            (int)le->be_namelen, le->data+le->reqlen+le->dlen,
            (int)le->be_portlen, le->data+le->reqlen+le->dlen+le->be_namelen, // fml.
            (int)le->dlen, le->data+le->reqlen, (int)le->reqlen, le->data
            );
    return total;
}
#endif

/* Should this go somewhere else? */
static const entry_details default_entries[] = {
    [LOGGER_ASCII_CMD] = {512, LOG_RAWCMDS, _logger_log_text, _logger_parse_text, "<%d %s"},
    [LOGGER_EVICTION] = {512, LOG_EVICTIONS, _logger_log_evictions, _logger_parse_ee, NULL},
    [LOGGER_ITEM_GET] = {512, LOG_FETCHERS, _logger_log_item_get, _logger_parse_ige, NULL},
    [LOGGER_ITEM_STORE] = {512, LOG_MUTATIONS, _logger_log_item_store, _logger_parse_ise, NULL},
    [LOGGER_CRAWLER_STATUS] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=lru_crawler crawler=%d lru=%s low_mark=%llu next_reclaims=%llu since_run=%u next_run=%d elapsed=%u examined=%llu reclaimed=%llu"
    },
    [LOGGER_SLAB_MOVE] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=slab_move src=%d dst=%d"
    },
    [LOGGER_CONNECTION_NEW] = {512, LOG_CONNEVENTS, _logger_log_conn_event, _logger_parse_cne, NULL},
    [LOGGER_CONNECTION_CLOSE] = {512, LOG_CONNEVENTS, _logger_log_conn_event, _logger_parse_cce, NULL},
#ifdef EXTSTORE
    [LOGGER_EXTSTORE_WRITE] = {512, LOG_EVICTIONS, _logger_log_ext_write, _logger_parse_extw, NULL},
    [LOGGER_COMPACT_START] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=compact_start id=%lu version=%llu"
    },
    [LOGGER_COMPACT_ABORT] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=compact_abort id=%lu"
    },
    [LOGGER_COMPACT_READ_START] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=compact_read_start id=%lu offset=%llu"
    },
    [LOGGER_COMPACT_READ_END] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=compact_read_end id=%lu offset=%llu rescues=%lu lost=%lu skipped=%lu"
    },
    [LOGGER_COMPACT_END] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=compact_end id=%lu"
    },
    [LOGGER_COMPACT_FRAGINFO] = {512, LOG_SYSEVENTS, _logger_log_text, _logger_parse_text,
        "type=compact_fraginfo ratio=%.2f bytes=%lu"
    },
#endif
#ifdef PROXY
    [LOGGER_PROXY_CONFIG] = {512, LOG_PROXYEVENTS, _logger_log_text, _logger_parse_text,
        "type=proxy_conf status=%s"
    },
    [LOGGER_PROXY_REQ] = {1024, LOG_PROXYREQS, _logger_log_proxy_req, _logger_parse_prx_req, NULL},
    [LOGGER_PROXY_ERROR] = {512, LOG_PROXYEVENTS, _logger_log_text, _logger_parse_text,
        "type=proxy_error msg=%s"
    },
    [LOGGER_PROXY_USER] = {512, LOG_PROXYUSER, _logger_log_text, _logger_parse_text,
        "type=proxy_user msg=%s"
    },
    [LOGGER_PROXY_BE_ERROR] = {512, LOG_PROXYEVENTS, _logger_log_text, _logger_parse_text,
        "type=proxy_backend error=%s name=%s port=%s"
    },

#endif
};

/*************************
 * Util functions shared between bg thread and workers
 *************************/

/* Logger GID's can be used by watchers to put logs back into strict order
 */
static uint64_t logger_gid = 0;
uint64_t logger_get_gid(void) {
#ifdef HAVE_GCC_64ATOMICS
    return __sync_add_and_fetch(&logger_gid, 1);
#elif defined(__sun)
    return atomic_inc_64_nv(&logger_gid);
#else
    mutex_lock(&logger_atomics_mutex);
    uint64_t res = ++logger_gid;
    mutex_unlock(&logger_atomics_mutex);
    return res;
#endif
}

void logger_set_gid(uint64_t gid) {
#ifdef HAVE_GCC_64ATOMICS
    __sync_add_and_fetch(&logger_gid, gid);
#elif defined(__sun)
    atomic_add_64(&logger_gid);
#else
    mutex_lock(&logger_atomics_mutex);
    logger_gid = gid;
    mutex_unlock(&logger_atomics_mutex);
#endif
}

/* TODO: genericize lists. would be nice to import queue.h if the impact is
 * studied... otherwise can just write a local one.
 */
/* Add to the list of threads with a logger object */
static void logger_link_q(logger *l) {
    pthread_mutex_lock(&logger_stack_lock);
    assert(l != logger_stack_head);

    l->prev = 0;
    l->next = logger_stack_head;
    if (l->next) l->next->prev = l;
    logger_stack_head = l;
    if (logger_stack_tail == 0) logger_stack_tail = l;
    logger_count++;
    pthread_mutex_unlock(&logger_stack_lock);
    return;
}

/* Remove from the list of threads with a logger object */
/*static void logger_unlink_q(logger *l) {
    pthread_mutex_lock(&logger_stack_lock);
    if (logger_stack_head == l) {
        assert(l->prev == 0);
        logger_stack_head = l->next;
    }
    if (logger_stack_tail == l) {
        assert(l->next == 0);
        logger_stack_tail = l->prev;
    }
    assert(l->next != l);
    assert(l->prev != l);

    if (l->next) l->next->prev = l->prev;
    if (l->prev) l->prev->next = l->next;
    logger_count--;
    pthread_mutex_unlock(&logger_stack_lock);
    return;
}*/

/* Called with logger stack locked.
 * Iterates over every watcher collecting enabled flags.
 */
static void logger_set_flags(void) {
    logger *l = NULL;
    int x = 0;
    uint16_t f = 0; /* logger eflags */

    for (x = 0; x < WATCHER_LIMIT; x++) {
        logger_watcher *w = watchers[x];
        if (w == NULL)
            continue;

        f |= w->eflags;
    }
    for (l = logger_stack_head; l != NULL; l=l->next) {
        pthread_mutex_lock(&l->mutex);
        l->eflags = f;
        pthread_mutex_unlock(&l->mutex);
    }
    return;
}

/* Completes rendering of log line. */
static enum logger_parse_entry_ret logger_thread_parse_entry(logentry *e, struct logger_stats *ls,
        char *scratch, int *scratch_len) {
    int total = 0;
    const entry_details *d = &default_entries[e->event];
    assert(d->parse_cb != NULL);
    total = d->parse_cb(e, scratch);

    if (total >= LOGGER_PARSE_SCRATCH || total <= 0) {
        L_DEBUG("LOGGER: Failed to flatten log entry!\n");
        return LOGGER_PARSE_ENTRY_FAILED;
    } else {
        *scratch_len = total;
    }

    return LOGGER_PARSE_ENTRY_OK;
}

/* Writes flattened entry to available watchers */
static void logger_thread_write_entry(logentry *e, struct logger_stats *ls,
        char *scratch, int scratch_len) {
    int x, total;
    /* Write the line into available watchers with matching flags */
    for (x = 0; x < WATCHER_LIMIT; x++) {
        logger_watcher *w = watchers[x];
        char *skip_scr = NULL;
        if (w == NULL || (e->eflags & w->eflags) == 0 || (e->gid < w->min_gid))
            continue;

         /* Avoid poll()'ing constantly when buffer is full by resetting a
         * flag periodically.
         */
        while (!w->failed_flush &&
                (skip_scr = (char *) bipbuf_request(w->buf, scratch_len + 128)) == NULL) {
            if (logger_thread_poll_watchers(0, x) <= 0) {
                L_DEBUG("LOGGER: Watcher had no free space for line of size (%d)\n", scratch_len + 128);
                w->failed_flush = true;
            }
        }

        if (w->failed_flush) {
            L_DEBUG("LOGGER: Fast skipped for watcher [%d] due to failed_flush\n", w->sfd);
            w->skipped++;
            ls->watcher_skipped++;
            continue;
        }

        if (w->skipped > 0) {
            total = snprintf(skip_scr, 128, "skipped=%llu\n", (unsigned long long) w->skipped);
            if (total >= 128 || total <= 0) {
                L_DEBUG("LOGGER: Failed to flatten skipped message into watcher [%d]\n", w->sfd);
                w->skipped++;
                ls->watcher_skipped++;
                continue;
            }
            bipbuf_push(w->buf, total);
            w->skipped = 0;
        }
        /* Can't fail because bipbuf_request succeeded. */
        bipbuf_offer(w->buf, (unsigned char *) scratch, scratch_len);
        ls->watcher_sent++;
    }
}

/* Called with logger stack locked.
 * Releases every chunk associated with a watcher and closes the connection.
 * We can't presently send a connection back to the worker for further
 * processing.
 */
static void logger_thread_close_watcher(logger_watcher *w) {
    L_DEBUG("LOGGER: Closing dead watcher\n");
    watchers[w->id] = NULL;
    sidethread_conn_close(w->c);
    watcher_count--;
    bipbuf_free(w->buf);
    free(w);
    logger_set_flags();
}

/* Reads a particular worker thread's available bipbuf bytes. Parses each log
 * entry into the watcher buffers.
 */
static int logger_thread_read(logger *l, struct logger_stats *ls) {
    unsigned int size;
    unsigned int pos = 0;
    unsigned char *data;
    char scratch[LOGGER_PARSE_SCRATCH];
    logentry *e;
    pthread_mutex_lock(&l->mutex);
    data = bipbuf_peek_all(l->buf, &size);
    pthread_mutex_unlock(&l->mutex);

    if (data == NULL) {
        return 0;
    }
    L_DEBUG("LOGGER: Got %d bytes from bipbuffer\n", size);

    /* parse buffer */
    while (pos < size && watcher_count > 0) {
        enum logger_parse_entry_ret ret;
        int scratch_len = 0;
        e = (logentry *) (data + pos);
        ret = logger_thread_parse_entry(e, ls, scratch, &scratch_len);
        if (ret != LOGGER_PARSE_ENTRY_OK) {
            /* TODO: stats counter */
            fprintf(stderr, "LOGGER: Failed to parse log entry\n");
        } else {
            logger_thread_write_entry(e, ls, scratch, scratch_len);
        }
        pos += sizeof(logentry) + e->size + e->pad;
    }
    assert(pos <= size);

    pthread_mutex_lock(&l->mutex);
    data = bipbuf_poll(l->buf, size);
    ls->worker_written += l->written;
    ls->worker_dropped += l->dropped;
    l->written = 0;
    l->dropped = 0;
    pthread_mutex_unlock(&l->mutex);
    if (data == NULL) {
        fprintf(stderr, "LOGGER: unexpectedly couldn't advance buf pointer\n");
        assert(0);
    }
    return size; /* maybe the count of objects iterated? */
}

/* Since the event loop code isn't reusable without a refactor, and we have a
 * limited number of potential watchers, we run our own poll loop.
 * This calls poll() unnecessarily during write flushes, should be possible to
 * micro-optimize later.
 *
 * This flushes buffers attached to watchers, iterating through the bytes set
 * to each worker. Also checks for readability in case client connection was
 * closed.
 *
 * Allows a specific watcher to be flushed (if buf full)
 */
static int logger_thread_poll_watchers(int force_poll, int watcher) {
    int x;
    int nfd = 0;
    unsigned char *data;
    unsigned int data_size = 0;
    int flushed = 0;

    for (x = 0; x < WATCHER_LIMIT; x++) {
        logger_watcher *w = watchers[x];
        if (w == NULL || (watcher != WATCHER_ALL && x != watcher))
            continue;

        data = bipbuf_peek_all(w->buf, &data_size);
        if (data != NULL) {
            watchers_pollfds[nfd].fd = w->sfd;
            watchers_pollfds[nfd].events = POLLOUT;
            nfd++;
        } else if (force_poll) {
            watchers_pollfds[nfd].fd = w->sfd;
            watchers_pollfds[nfd].events = POLLIN;
            nfd++;
        }
        /* This gets set after a call to poll, and should be used to gate on
         * calling poll again.
         */
        w->failed_flush = false;
    }

    if (nfd == 0)
        return 0;

    //L_DEBUG("LOGGER: calling poll() [data_size: %d]\n", data_size);
    int ret = poll(watchers_pollfds, nfd, 0);

    if (ret < 0) {
        perror("something failed with logger thread watcher fd polling");
        return -1;
    }

    nfd = 0;
    for (x = 0; x < WATCHER_LIMIT; x++) {
        logger_watcher *w = watchers[x];
        if (w == NULL || (watcher != WATCHER_ALL && x != watcher))
            continue;

        data_size = 0;
        /* Early detection of a disconnect. Otherwise we have to wait until
         * the next write
         */
        if (watchers_pollfds[nfd].revents & POLLIN) {
            char buf[1];
            int res = ((conn*)w->c)->read(w->c, buf, 1);
            if (res == 0 || (res == -1 && (errno != EAGAIN && errno != EWOULDBLOCK))) {
                L_DEBUG("LOGGER: watcher closed remotely\n");
                logger_thread_close_watcher(w);
                nfd++;
                continue;
            }
        }
        if ((data = bipbuf_peek_all(w->buf, &data_size)) != NULL) {
            if (watchers_pollfds[nfd].revents & (POLLHUP|POLLERR)) {
                L_DEBUG("LOGGER: watcher closed during poll() call\n");
                logger_thread_close_watcher(w);
            } else if (watchers_pollfds[nfd].revents & POLLOUT) {
                int total = 0;

                /* We can write a bit. */
                switch (w->t) {
                    case LOGGER_WATCHER_STDERR:
                        total = fwrite(data, 1, data_size, stderr);
                        break;
                    case LOGGER_WATCHER_CLIENT:
                        total = ((conn*)w->c)->write(w->c, data, data_size);
                        break;
                }

                L_DEBUG("LOGGER: poll() wrote %d to %d (data_size: %d) (bipbuf_used: %d)\n", total, w->sfd,
                        data_size, bipbuf_used(w->buf));
                if (total == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        logger_thread_close_watcher(w);
                    }
                    L_DEBUG("LOGGER: watcher hit EAGAIN\n");
                } else if (total == 0) {
                    logger_thread_close_watcher(w);
                } else {
                    bipbuf_poll(w->buf, total);
                    flushed += total;
                }
            }
        }
        nfd++;
    }
    return flushed;
}

static void logger_thread_flush_stats(struct logger_stats *ls) {
    STATS_LOCK();
    stats.log_worker_dropped  += ls->worker_dropped;
    stats.log_worker_written  += ls->worker_written;
    stats.log_watcher_skipped += ls->watcher_skipped;
    stats.log_watcher_sent    += ls->watcher_sent;
    stats_state.log_watchers   = ls->watcher_count;
    STATS_UNLOCK();
}

#define MAX_LOGGER_SLEEP 1000000
#define MIN_LOGGER_SLEEP 1000

/* Primary logger thread routine */
static void *logger_thread(void *arg) {
    useconds_t to_sleep = MIN_LOGGER_SLEEP;
    L_DEBUG("LOGGER: Starting logger thread\n");
    // TODO: If we ever have item references in the logger code, will need to
    // ensure everything is dequeued before stopping the thread.
    while (do_run_logger_thread) {
        int found_logs = 0;
        logger *l;
        struct logger_stats ls;
        memset(&ls, 0, sizeof(struct logger_stats));

        /* only sleep if we're *above* the minimum */
        if (to_sleep > MIN_LOGGER_SLEEP)
            usleep(to_sleep);

        /* Call function to iterate each logger. */
        pthread_mutex_lock(&logger_stack_lock);
        if (watcher_count == 0) {
            // Not bothering to loop on the condition here since it's fine to
            // walk through with zero watchers.
            pthread_cond_wait(&logger_stack_cond, &logger_stack_lock);
        }
        for (l = logger_stack_head; l != NULL; l=l->next) {
            /* lock logger, call function to manipulate it */
            found_logs += logger_thread_read(l, &ls);
        }

        logger_thread_poll_watchers(1, WATCHER_ALL);

        /* capture the current count within mutual exclusion of the lock */
        ls.watcher_count = watcher_count;

        pthread_mutex_unlock(&logger_stack_lock);

        /* TODO: abstract into a function and share with lru_crawler */
        if (!found_logs) {
            if (to_sleep < MAX_LOGGER_SLEEP)
                to_sleep += to_sleep / 8;
            if (to_sleep > MAX_LOGGER_SLEEP)
                to_sleep = MAX_LOGGER_SLEEP;
        } else {
            to_sleep /= 2;
            if (to_sleep < MIN_LOGGER_SLEEP)
                to_sleep = MIN_LOGGER_SLEEP;
        }
        logger_thread_flush_stats(&ls);
    }

    return NULL;
}

static int start_logger_thread(void) {
    int ret;
    do_run_logger_thread = 1;
    if ((ret = pthread_create(&logger_tid, NULL,
                              logger_thread, NULL)) != 0) {
        fprintf(stderr, "Can't start logger thread: %s\n", strerror(ret));
        return -1;
    }
    return 0;
}

static int stop_logger_thread(void) {
    // Guarantees that the logger thread is waiting on 'logger_stack_cond'
    // before we signal it.
    pthread_mutex_lock(&logger_stack_lock);
    do_run_logger_thread = 0;
    pthread_cond_signal(&logger_stack_cond);
    pthread_mutex_unlock(&logger_stack_lock);
    pthread_join(logger_tid, NULL);
    return 0;
}

/*************************
 * Public functions for submitting logs and starting loggers from workers.
 *************************/

/* Global logger thread start/init */
void logger_init(void) {
    /* TODO: auto destructor when threads exit */
    /* TODO: error handling */

    /* init stack for iterating loggers */
    logger_stack_head = 0;
    logger_stack_tail = 0;
    pthread_key_create(&logger_key, NULL);

    if (start_logger_thread() != 0) {
        abort();
    }

    /* This is what adding a STDERR watcher looks like. should replace old
     * "verbose" settings. */
    //logger_add_watcher(NULL, 0);
    return;
}

void logger_stop(void) {
    stop_logger_thread();
}

/* called *from* the thread using a logger.
 * initializes the per-thread bipbuf, links it into the list of loggers
 */
logger *logger_create(void) {
    L_DEBUG("LOGGER: Creating and linking new logger instance\n");
    logger *l = calloc(1, sizeof(logger));
    if (l == NULL) {
        return NULL;
    }

    l->buf = bipbuf_new(settings.logger_buf_size);
    if (l->buf == NULL) {
        free(l);
        return NULL;
    }

    l->entry_map = default_entries;

    pthread_mutex_init(&l->mutex, NULL);
    pthread_setspecific(logger_key, l);

    /* add to list of loggers */
    logger_link_q(l);
    return l;
}

/* Public function for logging an entry.
 * Tries to encapsulate as much of the formatting as possible to simplify the
 * caller's code.
 */
enum logger_ret_type logger_log(logger *l, const enum log_entry_type event, const void *entry, ...) {
    bipbuf_t *buf = l->buf;
    bool nospace = false;
    va_list ap;
    logentry *e;

    const entry_details *d = &l->entry_map[event];
    int reqlen = d->reqlen;

    pthread_mutex_lock(&l->mutex);
    /* Request a maximum length of data to write to */
    e = (logentry *) bipbuf_request(buf, (sizeof(logentry) + reqlen));
    if (e == NULL) {
        pthread_mutex_unlock(&l->mutex);
        l->dropped++;
        return LOGGER_RET_NOSPACE;
    }
    e->event = event;
    e->pad = 0;
    e->gid = logger_get_gid();
    /* TODO: Could pass this down as an argument now that we're using
     * LOGGER_LOG() macro.
     */
    e->eflags = d->eflags;
    /* Noting time isn't optional. A feature may be added to avoid rendering
     * time and/or gid to a logger.
     */
    gettimeofday(&e->tv, NULL);

    va_start(ap, entry);
    d->log_cb(e, d, entry, ap);
    va_end(ap);

#ifdef NEED_ALIGN
    /* Need to ensure *next* request is aligned. */
    if (sizeof(logentry) + e->size % 8 != 0) {
        e->pad = 8 - (sizeof(logentry) + e->size % 8);
    }
#endif

    /* Push pointer forward by the actual amount required */
    if (bipbuf_push(buf, (sizeof(logentry) + e->size + e->pad)) == 0) {
        fprintf(stderr, "LOGGER: Failed to bipbuf push a text entry\n");
        pthread_mutex_unlock(&l->mutex);
        return LOGGER_RET_ERR;
    }
    l->written++;
    L_DEBUG("LOGGER: Requested %d bytes, wrote %lu bytes\n", reqlen,
            (sizeof(logentry) + e->size));

    pthread_mutex_unlock(&l->mutex);

    if (nospace) {
        return LOGGER_RET_NOSPACE;
    } else {
        return LOGGER_RET_OK;
    }
}

/* Passes a client connection socket from a primary worker thread to the
 * logger thread. Caller *must* event_del() the client before handing it over.
 * Presently there's no way to hand the client back to the worker thread.
 */
enum logger_add_watcher_ret logger_add_watcher(void *c, const int sfd, uint16_t f) {
    int x;
    logger_watcher *w = NULL;
    pthread_mutex_lock(&logger_stack_lock);
    if (watcher_count >= WATCHER_LIMIT) {
        pthread_mutex_unlock(&logger_stack_lock);
        return LOGGER_ADD_WATCHER_TOO_MANY;
    }

    for (x = 0; x < WATCHER_LIMIT-1; x++) {
        if (watchers[x] == NULL)
            break;
    }

    w = calloc(1, sizeof(logger_watcher));
    if (w == NULL) {
        pthread_mutex_unlock(&logger_stack_lock);
        return LOGGER_ADD_WATCHER_FAILED;
    }
    w->c = c;
    w->sfd = sfd;
    if (sfd == 0 && c == NULL) {
        w->t = LOGGER_WATCHER_STDERR;
    } else {
        w->t = LOGGER_WATCHER_CLIENT;
    }
    w->id = x;
    w->eflags = f;
    w->min_gid = logger_get_gid();
    w->buf = bipbuf_new(settings.logger_watcher_buf_size);
    if (w->buf == NULL) {
        free(w);
        pthread_mutex_unlock(&logger_stack_lock);
        return LOGGER_ADD_WATCHER_FAILED;
    }
    bipbuf_offer(w->buf, (unsigned char *) "OK\r\n", 4);

    watchers[x] = w;
    watcher_count++;
    /* Update what flags the global logs will watch */
    logger_set_flags();
    pthread_cond_signal(&logger_stack_cond);

    pthread_mutex_unlock(&logger_stack_lock);
    return LOGGER_ADD_WATCHER_OK;
}

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <ctype.h>

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

pthread_key_t logger_key;

#if !defined(HAVE_GCC_ATOMICS) && !defined(__sun)
pthread_mutex_t logger_atomics_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define WATCHER_LIMIT 20
logger_watcher *watchers[20];
struct pollfd watchers_pollfds[20];
int watcher_count = 0;

static char *logger_uriencode_map[256];
static char logger_uriencode_str[768];

/* Should this go somewhere else? */
static const entry_details default_entries[] = {
    [LOGGER_ASCII_CMD] = {LOGGER_TEXT_ENTRY, 512, LOG_RAWCMDS, "<%d %s"},
    [LOGGER_EVICTION] = {LOGGER_EVICTION_ENTRY, 512, LOG_EVICTIONS, NULL},
    [LOGGER_ITEM_GET] = {LOGGER_ITEM_GET_ENTRY, 512, LOG_FETCHERS, NULL},
    [LOGGER_ITEM_STORE] = {LOGGER_ITEM_STORE_ENTRY, 512, LOG_MUTATIONS, NULL}
};

#define WATCHER_ALL -1
static int logger_thread_poll_watchers(int force_poll, int watcher);

/*************************
 * Util functions shared between bg thread and workers
 *************************/

static void logger_uriencode_init(void) {
    int x;
    char *str = logger_uriencode_str;
    for (x = 0; x < 256; x++) {
        if (isalnum(x) || x == '-' || x == '.' || x == '_' || x == '~') {
            logger_uriencode_map[x] = NULL;
        } else {
            snprintf(str, 4, "%%%02X", x);
            logger_uriencode_map[x] = str;
            str += 3; /* lobbing off the \0 is fine */
        }
    }
}

static bool logger_uriencode(const char *src, char *dst, const size_t srclen, const size_t dstlen) {
    int x;
    size_t d = 0;
    for (x = 0; x < srclen; x++) {
        if (d + 4 >= dstlen)
            return false;
        if (logger_uriencode_map[(unsigned char) src[x]] != NULL) {
            memcpy(&dst[d], logger_uriencode_map[(unsigned char) src[x]], 3);
            d += 3;
        } else {
            dst[d] = src[x];
            d++;
        }
    }
    dst[d] = '\0';
    return true;
}

/* Logger GID's can be used by watchers to put logs back into strict order
 */
static uint64_t logger_get_gid(void) {
    static uint64_t logger_gid = 0;
#ifdef HAVE_GCC_ATOMICS
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

/*************************
 * Logger background thread functions. Aggregates per-worker buffers and
 * writes to any watchers.
 *************************/

/* Completes rendering of log line, copies to subscribed watchers */
/* FIXME: This can be shortened considerably with a refactor for both the
 * "skipped" writing and string conversion.
 */
#define LOGGER_PARSE_SCRATCH 4096
static enum logger_parse_entry_ret logger_thread_parse_entry(logentry *e, struct logger_stats *ls) {
    int total = 0;
    int line_size = 0;
    int x;
    char scratch[LOGGER_PARSE_SCRATCH];
    char scratch2[LOGGER_PARSE_SCRATCH];
    char *status = "unknown";

    switch (e->event) {
        case LOGGER_TEXT_ENTRY:
            total = snprintf(scratch, LOGGER_PARSE_SCRATCH, "ts=%d.%d gid=%llu %s\n",
                        (int)e->tv.tv_sec, (int)e->tv.tv_usec,
                        (unsigned long long) e->gid, (char *) e->data);
            break;
        case LOGGER_EVICTION_ENTRY: ;
            struct logentry_eviction *le = (struct logentry_eviction *) e->data;
            logger_uriencode(le->key, scratch2, le->nkey, LOGGER_PARSE_SCRATCH);
            total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
                    "ts=%d.%d gid=%llu type=eviction key=%s fetch=%s ttl=%lld la=%d\n",
                    (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid,
                    scratch2, (le->it_flags & ITEM_FETCHED) ? "yes" : "no",
                    (long long int)le->exptime, le->latime);
            break;
        case LOGGER_ITEM_GET_ENTRY: ;
            struct logentry_item_get *lig = (struct logentry_item_get *) e->data;
            switch (lig->was_found) {
                case 0:
                    status = "not_found";
                    break;
                case 1:
                    status = "found";
                    break;
                case 2:
                    status = "flushed";
                    break;
                case 3:
                    status = "expired";
                    break;
            }
            logger_uriencode(lig->key, scratch2, lig->nkey, LOGGER_PARSE_SCRATCH);
            total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
                    "ts=%d.%d gid=%llu type=item_get key=%s status=%s\n",
                    (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid,
                    scratch2, status);
            break;
        case LOGGER_ITEM_STORE_ENTRY: ;
            struct logentry_item_store *lis = (struct logentry_item_store *) e->data;
            char *cmd = "na";
            switch (lis->status) {
                case STORED:
                    status = "stored";
                    break;
                case EXISTS:
                    status = "exists";
                    break;
                case NOT_FOUND:
                    status = "not_found";
                    break;
                case TOO_LARGE:
                    status = "too_large";
                    break;
                case NO_MEMORY:
                    status = "no_memory";
                    break;
            }
            switch (lis->cmd) {
                case NREAD_ADD:
                    cmd = "add";
                    break;
                case NREAD_SET:
                    cmd = "set";
                    break;
                case NREAD_REPLACE:
                    cmd = "replace";
                    break;
                case NREAD_APPEND:
                    cmd = "append";
                    break;
                case NREAD_PREPEND:
                    cmd = "prepend";
                    break;
                case NREAD_CAS:
                    cmd = "cas";
                    break;
            }
            logger_uriencode(lis->key, scratch2, lis->nkey, LOGGER_PARSE_SCRATCH);
            total = snprintf(scratch, LOGGER_PARSE_SCRATCH,
                    "ts=%d.%d gid=%llu type=item_store key=%s status=%s cmd=%s\n",
                    (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid,
                    scratch2, status, cmd);
            break;

    }

    if (total >= LOGGER_PARSE_SCRATCH || total <= 0) {
        L_DEBUG("LOGGER: Failed to flatten log entry!\n");
        return LOGGER_PARSE_ENTRY_FAILED;
    } else {
        line_size = total + 1;
    }

    /* Write the line into available watcher with the right flags */
    for (x = 0; x < WATCHER_LIMIT; x++) {
        logger_watcher *w = watchers[x];
        if (w == NULL)
            continue;

        if ((e->eflags & w->eflags) == 0) {
            L_DEBUG("LOGGER: Skipping event for watcher [%d] (w->eflags: %d) (e->eflags: %d)\n",
                    w->sfd, w->eflags, e->eflags);
            continue;
        }

        if (w->failed_flush) {
            L_DEBUG("LOGGER: Fast skipped for watcher [%d] due to failed_flush\n", w->sfd);
            w->skipped++;
            ls->watcher_skipped++;
        } else if (w->skipped > 0) {
            char *skip_scr = NULL;
            if ((skip_scr = (char *) bipbuf_request(w->buf, line_size + 128)) != NULL) {
                total = snprintf(skip_scr, 128, "skipped=%llu\n", (unsigned long long) w->skipped);
                if (total >= 128 || total <= 0) {
                    L_DEBUG("LOGGER: Failed to flatten skipped message into watcher [%d]\n", w->sfd);
                    w->skipped++;
                    ls->watcher_skipped++;
                } else {
                    /* These can't fail because bipbuf_request succeeded. */
                    bipbuf_push(w->buf, total + 1);
                    bipbuf_offer(w->buf, (unsigned char *) scratch, line_size);
                    w->skipped = 0;
                    ls->watcher_sent++;
                }
            } else {
                L_DEBUG("LOGGER: Continuing to fast skip for watcher [%d]\n", w->sfd);
                w->skipped++;
                ls->watcher_skipped++;
                w->failed_flush = true;
            }
        } else {
             /* Avoid poll()'ing constantly when buffer is full by resetting a
             * flag periodically.
             */
            while (bipbuf_offer(w->buf, (unsigned char *) scratch, line_size) == 0) {
                if (logger_thread_poll_watchers(0, x) <= 0) {
                    L_DEBUG("LOGGER: Watcher had no free space for line of size (%d)\n", line_size);
                    w->failed_flush = true;
                    w->skipped++;
                    ls->watcher_skipped++;
                    break;
                }
            }
            if (!w->failed_flush)
                ls->watcher_sent++;
        }
    }

    return LOGGER_PARSE_ENTRY_OK;
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
        e = (logentry *) (data + pos);
        ret = logger_thread_parse_entry(e, ls);
        if (ret != LOGGER_PARSE_ENTRY_OK) {
            /* TODO: stats counter */
            fprintf(stderr, "LOGGER: Failed to parse log entry\n");
        }
        pos += sizeof(logentry) + e->size;
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
        if (w == NULL)
            continue;

        data_size = 0;
        /* Early detection of a disconnect. Otherwise we have to wait until
         * the next write
         */
        if (watchers_pollfds[nfd].revents & POLLIN) {
            char buf[1];
            int res = read(w->sfd, buf, 1);
            if (res == 0 || (res == -1 && (errno != EAGAIN && errno != EWOULDBLOCK))) {
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
                        total = write(w->sfd, data, data_size);
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

static void logger_thread_sum_stats(struct logger_stats *ls) {
    STATS_LOCK();
    stats.log_worker_dropped  += ls->worker_dropped;
    stats.log_worker_written  += ls->worker_written;
    stats.log_watcher_skipped += ls->watcher_skipped;
    stats.log_watcher_sent    += ls->watcher_sent;
    STATS_UNLOCK();
}

#define MAX_LOGGER_SLEEP 100000
#define MIN_LOGGER_SLEEP 0

/* Primary logger thread routine */
static void *logger_thread(void *arg) {
    useconds_t to_sleep = MIN_LOGGER_SLEEP;
    L_DEBUG("LOGGER: Starting logger thread\n");
    while (do_run_logger_thread) {
        int found_logs = 0;
        logger *l;
        struct logger_stats ls;
        memset(&ls, 0, sizeof(struct logger_stats));
        if (to_sleep)
            usleep(to_sleep);

        /* Call function to iterate each logger. */
        pthread_mutex_lock(&logger_stack_lock);
        for (l = logger_stack_head; l != NULL; l=l->next) {
            /* lock logger, call function to manipulate it */
            found_logs += logger_thread_read(l, &ls);
        }

        logger_thread_poll_watchers(1, WATCHER_ALL);
        pthread_mutex_unlock(&logger_stack_lock);

        /* TODO: abstract into a function and share with lru_crawler */
        if (!found_logs) {
            if (to_sleep < MAX_LOGGER_SLEEP)
                to_sleep += 50;
        } else {
            to_sleep /= 2;
            if (to_sleep < 50)
                to_sleep = MIN_LOGGER_SLEEP;
        }
        logger_thread_sum_stats(&ls);
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

// future.
/*static int stop_logger_thread(void) {
    do_run_logger_thread = 0;
    pthread_join(logger_tid, NULL);
    return 0;
}*/

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
    logger_uriencode_init();

    if (start_logger_thread() != 0) {
        abort();
    }

    /* This can be removed once the global stats initializer is improved */
    STATS_LOCK();
    stats.log_worker_dropped = 0;
    stats.log_worker_written = 0;
    stats.log_watcher_skipped = 0;
    stats.log_watcher_sent = 0;
    STATS_UNLOCK();
    /* This is what adding a STDERR watcher looks like. should replace old
     * "verbose" settings. */
    //logger_add_watcher(NULL, 0);
    return;
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

    l->buf = bipbuf_new(LOGGER_BUF_SIZE);
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

/* helpers for logger_log */

static void _logger_log_evictions(logentry *e, item *it) {
    struct logentry_eviction *le = (struct logentry_eviction *) e->data;
    le->exptime = (it->exptime > 0) ? (long long int)(it->exptime - current_time) : (long long int) -1;
    le->latime = current_time - it->time;
    le->it_flags = it->it_flags;
    le->nkey = it->nkey;
    memcpy(le->key, ITEM_key(it), it->nkey);
    e->size = sizeof(struct logentry_eviction) + le->nkey;
}

/* 0 == nf, 1 == found. 2 == flushed. 3 == expired.
 * might be useful to store/print the flags an item has?
 * could also collapse this and above code into an "item status" struct. wait
 * for more endpoints to be written before making it generic, though.
 * TODO: This and below should track and reprint the client fd.
 */
static void _logger_log_item_get(logentry *e, const int was_found, const char *key, const int nkey) {
    struct logentry_item_get *le = (struct logentry_item_get *) e->data;
    le->was_found = was_found;
    le->nkey = nkey;
    memcpy(le->key, key, nkey);
    e->size = sizeof(struct logentry_item_get) + nkey;
}

static void _logger_log_item_store(logentry *e, const enum store_item_type status,
        const int comm, char *key, const int nkey) {
    struct logentry_item_store *le = (struct logentry_item_store *) e->data;
    le->status = status;
    le->cmd = comm;
    le->nkey = nkey;
    memcpy(le->key, key, nkey);
    e->size = sizeof(struct logentry_item_store) + nkey;
}

/* Public function for logging an entry.
 * Tries to encapsulate as much of the formatting as possible to simplify the
 * caller's code.
 */
enum logger_ret_type logger_log(logger *l, const enum log_entry_type event, const void *entry, ...) {
    bipbuf_t *buf = l->buf;
    bool nospace = false;
    va_list ap;
    int total = 0;
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
    e->gid = logger_get_gid();
    e->event = d->subtype;
    /* TODO: Could pass this down as an argument now that we're using
     * LOGGER_LOG() macro.
     */
    e->eflags = d->eflags;
    /* Noting time isn't optional. A feature may be added to avoid rendering
     * time and/or gid to a logger.
     */
    gettimeofday(&e->tv, NULL);

    switch (d->subtype) {
        case LOGGER_TEXT_ENTRY:
            va_start(ap, entry);
            total = vsnprintf((char *) e->data, reqlen, d->format, ap);
            va_end(ap);
            if (total >= reqlen || total <= 0) {
                fprintf(stderr, "LOGGER: Failed to vsnprintf a text entry: (total) %d\n", total);
                break;
            }
            e->size = total + 1; /* null byte */

            break;
        case LOGGER_EVICTION_ENTRY:
            _logger_log_evictions(e, (item *)entry);
            break;
        case LOGGER_ITEM_GET_ENTRY:
            va_start(ap, entry);
            int was_found = va_arg(ap, int);
            char *key = va_arg(ap, char *);
            size_t nkey = va_arg(ap, size_t);
            _logger_log_item_get(e, was_found, key, nkey);
            va_end(ap);
            break;
        case LOGGER_ITEM_STORE_ENTRY:
            va_start(ap, entry);
            enum store_item_type status = va_arg(ap, enum store_item_type);
            int comm = va_arg(ap, int);
            char *skey = va_arg(ap, char *);
            size_t snkey = va_arg(ap, size_t);
            _logger_log_item_store(e, status, comm, skey, snkey);
            break;
    }

    /* Push pointer forward by the actual amount required */
    if (bipbuf_push(buf, (sizeof(logentry) + e->size)) == 0) {
        fprintf(stderr, "LOGGER: Failed to bipbuf push a text entry\n");
        pthread_mutex_unlock(&l->mutex);
        return LOGGER_RET_ERR;
    }
    l->written++;
    L_DEBUG("LOGGER: Requested %d bytes, wrote %d bytes\n", reqlen, total + 1);

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
        return LOGGER_ADD_WATCHER_TOO_MANY;
    }

    for (x = 0; x < WATCHER_LIMIT; x++) {
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
    w->buf = bipbuf_new(LOGGER_WATCHER_BUF_SIZE);
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

    pthread_mutex_unlock(&logger_stack_lock);
    return LOGGER_ADD_WATCHER_OK;
}

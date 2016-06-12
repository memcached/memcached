/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/* need this to get IOV_MAX on some platforms. */
#ifndef __need_IOV_MAX
#define __need_IOV_MAX
#endif
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>

#include "memcached.h"
#include "bipbuffer.h"

/* FreeBSD 4.x doesn't have IOV_MAX exposed. */
#ifndef IOV_MAX
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__GNU__)
# define IOV_MAX 1024
#endif
#endif

#define LOGGER_DEBUG 1

#if LOGGER_DEBUG
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

bipbuf_t *logger_thread_buf = NULL;

#if !defined(HAVE_GCC_ATOMICS) && !defined(__sun)
pthread_mutex_t logger_atomics_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define WATCHER_LIMIT 20
logger_watcher *watchers[20];
struct pollfd watchers_pollfds[20];
int watcher_count = 0;

/* Should this go somewhere else? */
static const entry_details default_entries[] = {
    [LOGGER_ASCII_CMD] = {LOGGER_TEXT_ENTRY, 512, LOG_RAWCMDS, "<%d %s"},
    [LOGGER_EVICTION] = {LOGGER_EVICTION_ENTRY, 512, LOG_EVICTIONS, "eviction: [key %s] [fetched: %s] [ttl: %d] [la: %d]"}
};

static void logger_poll_watchers(int force_poll);

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

/* return FULLBUF to tell caller buffer is full.
 * caller will then flush and retry log parse
 */
static enum logger_parse_entry_ret logger_parse_entry(bipbuf_t *buf, logentry *e) {
    int total = 0;
    /* "64" needs better definition, since we're extending the length of the
     * logline a bit.
     */
    int esize = sizeof(logentry) + e->size + 64;
    logentry *newe = (logentry *) bipbuf_request(buf, esize);
    if (newe == NULL) {
        return LOGGER_PARSE_ENTRY_FULLBUF;
    }
    /* Not bothering copying the whole struct header. will probably come up
     * with a different shorter struct for this.
     */
    newe->watcher_flag = e->watcher_flag;

    switch (e->event) {
        case LOGGER_TEXT_ENTRY:
        case LOGGER_EVICTION_ENTRY:
            total = snprintf((char *) newe->data, esize, "[%d.%d] [%llu] %s\n",
                        (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid, (char *) e->data);
            if (total >= esize || total <= 0) {
                /* FIXME: This is now a much more fatal error. need to make it
                 * not crash though. */
                L_DEBUG("LOGGER: Failed to flatten log entry!\n");
                return LOGGER_PARSE_ENTRY_FAILED;
            } else {
                newe->size = total + 1;
                bipbuf_push(buf, sizeof(logentry) + newe->size);
            }
            break;
    }

    return LOGGER_PARSE_ENTRY_OK;
}

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
        /* TODO: lock logger, call function to manipulate it */
        l->eflags = f;
    }
    return;
}

/* Called with logger stack locked.
 * Releases every chunk associated with a watcher and closes the connection.
 * We can't presently send a connection back to the worker for further
 * processing.
 */
static void logger_close_watcher(logger_watcher *w) {
    L_DEBUG("LOGGER: Closing dead watcher\n");
    watchers[w->id] = NULL;
    sidethread_conn_close(w->c);
    watcher_count--;
    free(w);
    logger_set_flags();
}

static void logger_push_central_buf(void) {
    int x;
    logger_watcher *w;
    int min_flushed = INT_MAX;
    /* If something is set into min_flushed, we're able to advance the central
     * buffer forward by min_flushed bytes.
     */
    for (x = 0; x < WATCHER_LIMIT; x++) {
        if (watchers[x] == NULL)
            continue;
        w = watchers[x];
        if (w->min_flushed < min_flushed)
            min_flushed = w->min_flushed;
    }
    if (min_flushed != 0) {
        //L_DEBUG("LOGGER: min_flushed [%d], advancing central buffer\n", min_flushed);
        for (x = 0; x < WATCHER_LIMIT; x++) {
            if (watchers[x] == NULL)
                continue;
            assert(watchers[x]->flushed - min_flushed >= 0);
            watchers[x]->flushed -= min_flushed;
            watchers[x]->min_flushed -= min_flushed;
        }
        bipbuf_poll(logger_thread_buf, min_flushed);
    }
}

/* Pick any number of "oldest" behind-watchers and kill them. */
static void logger_kill_watchers(void) {
    int x;
    logger_watcher *w;
    int min_flushed = INT_MAX;
    int min_flushed_watcher = -1;

    for (x = 0; x < WATCHER_LIMIT; x++) {
        w = watchers[x];
        if (w == NULL)
            continue;

        if (w->min_flushed < min_flushed) {
            min_flushed = w->min_flushed;
            min_flushed_watcher = x;
        }
    }
    if (min_flushed_watcher > -1) {
        fprintf(stderr, "LOGGER: Killing watcher [%d] because of low flush bytes (%d)\n",
                watchers[min_flushed_watcher]->sfd, min_flushed);
        logger_close_watcher(watchers[min_flushed_watcher]);
        logger_push_central_buf();
    }
}

/* Reads a particular worker thread's available bipbuf bytes. Parses each log
 * entry into the central logging output buffer.
 * If we run out of buffer space, we simply kill off the most-behind watcher.
 * Might be better to have options for dropping logs vs disconnecting?
 */
static int logger_thread_read(logger *l) {
    unsigned int size;
    unsigned int pos = 0;
    unsigned char *data;
    unsigned int was_full = 0;
    logentry *e;
    pthread_mutex_lock(&l->mutex);
    data = bipbuf_peek_all(l->buf, &size);
    pthread_mutex_unlock(&l->mutex);

    if (data == NULL) {
        return 0;
    }
    //L_DEBUG("LOGGER: Got %d bytes from bipbuffer\n", size);

    /* parse buffer */
    while (pos < size && watcher_count > 0) {
        enum logger_parse_entry_ret ret;
        e = (logentry *) (data + pos);
        ret = logger_parse_entry(logger_thread_buf, e);
        if (ret == LOGGER_PARSE_ENTRY_FULLBUF) {
            /* Buffer was full. Push the last up, force an early flush. */
            if (was_full) {
                /* out of buffer space. show must go on, so kill something. */
                logger_kill_watchers();
            } else {
                logger_poll_watchers(0);
                was_full = 1;
            }
            continue;
        } else if (ret != LOGGER_PARSE_ENTRY_OK) {
            fprintf(stderr, "LOGGER: Failed to parse log entry\n");
            abort();
        }
        was_full = 0;
        pos += sizeof(logentry) + e->size;
    }
    assert(pos <= size);

    pthread_mutex_lock(&l->mutex);
    data = bipbuf_poll(l->buf, size);
    pthread_mutex_unlock(&l->mutex);
    if (data == NULL) {
        fprintf(stderr, "LOGGER: unexpectedly couldn't advance buf pointer\n");
        abort();
        return -1;
    }
    return size; /* maybe the count of objects iterated? */
}

/* helper function or #define: iterate over loggers */
/* called with logger_stack_lock held */
static int logger_iterate(void) {
    logger *l = NULL;
    int count = 0;
    for (l = logger_stack_head; l != NULL; l=l->next) {
        /* lock logger, call function to manipulate it */
        count += logger_thread_read(l);
    }
    return count;
}

/* Since the event loop code isn't reusable without a refactor, and we have a
 * limited number of potential watchers, we run our own poll loop.
 * This calls poll() unnecessarily during write flushes, should be possible to
 * micro-optimize later.
 *
 * This flushes buffers attached to watchers, iterating through the chunks set
 * to each worker. Also checks for readability in case client connection was
 * closed.
 */
static void logger_poll_watchers(int force_poll) {
    int x;
    int nfd = 0;
    logger_watcher *w;
    unsigned char *data;
    unsigned int data_size = 0;
    struct iovec iov[IOV_MAX];
    int iovcnt = 0;
    data = bipbuf_peek_all(logger_thread_buf, &data_size);
    if (data == NULL && force_poll == 0)
        return;

    for (x = 0; x < WATCHER_LIMIT; x++) {
        w = watchers[x];
        if (w == NULL)
            continue;

        if (data_size > w->flushed) {
            watchers_pollfds[nfd].fd = w->sfd;
            watchers_pollfds[nfd].events = POLLOUT;
            nfd++;
        } else if (force_poll) {
            watchers_pollfds[nfd].fd = w->sfd;
            watchers_pollfds[nfd].events = POLLIN;
            nfd++;
        }
    }

    /* FIXME: Verify if this is necessary. */
    if (data != NULL && force_poll == 0)
        assert(nfd != 0);

    if (nfd == 0)
        return;

    L_DEBUG("LOGGER: calling poll() [data_size: %d]\n", data_size);
    int ret = poll(watchers_pollfds, nfd, 0);

    if (ret < 0) {
        perror("something failed with logger thread watcher fd polling");
        return;
    }

    nfd = 0;
    for (x = 0; x < WATCHER_LIMIT; x++) {
        w = watchers[x];
        if (w == NULL)
            continue;
        /* Early detection of a disconnect. Otherwise we have to wait until
         * the next write
         */
        if (watchers_pollfds[nfd].revents & POLLIN) {
            char buf[1];
            int res = read(w->sfd, buf, 1);
            if (res == 0 || (res == -1 && (errno != EAGAIN && errno != EWOULDBLOCK))) {
                logger_close_watcher(w);
                nfd++;
                continue;
            }
        }
        if (data_size > w->flushed) {
            if (watchers_pollfds[nfd].revents & (POLLHUP|POLLERR)) {
                L_DEBUG("LOGGER: watcher closed during poll() call\n");
                logger_close_watcher(w);
            } else if (watchers_pollfds[nfd].revents & POLLOUT) {
                int total = 0;
                /* To account for a partial write into the iovec, pos should
                 * loop and skip logentry's until the next one would be
                 * larger, then set the iov_base as an offset into the
                 * remainder.
                 */
                unsigned int pos = w->flushed;
                iovcnt = 0;
                while (pos < data_size) {
                    logentry *e = (logentry *) (data + pos);
                    int esize = sizeof(logentry) + e->size;
                    int flushed = 0;
                    if (pos + esize < w->flushed) {
                        pos += esize;
                        continue;
                    } else if (pos < w->flushed) {
                        /* We have a remainder. */
                        flushed = w->flushed - (pos + sizeof(logentry));
                        assert(pos + flushed <= w->flushed);
                    } else if ((e->watcher_flag & w->eflags) == 0) {
                        /* If we're ahead of flushed but we aren't listening,
                         * we advance flushed and skip this event
                         */
                        //L_DEBUG("LOGGER: Skipped an event for [%d] (eflags: %d) (watcher_flag: %d)\n",
                        //        w->sfd, w->eflags, e->watcher_flag);
                        pos += esize;
                        w->flushed += esize;
                        w->min_flushed += esize;
                        continue;
                    }
                    iov[iovcnt].iov_base = (e->data + flushed);
                    iov[iovcnt].iov_len = e->size - flushed;
                    //L_DEBUG("LOGGER: incrementing pos [%d] by %d [esize: %d]\n", pos, esize, e->size);
                    pos += esize;
                    iovcnt++;
                }

                if (iovcnt == 0) {
                    /* Turns out we skipped all of the events! */
                    continue;
                }

                /* We can write a bit. */
                switch (w->t) {
                    case LOGGER_WATCHER_STDERR:
                        total = writev(STDERR_FILENO, iov, iovcnt);
                        break;
                    case LOGGER_WATCHER_CLIENT:
                        total = writev(w->sfd, iov, iovcnt);
                        break;
                }

                L_DEBUG("LOGGER: poll() wrote %d to %d (data_size: %d) (flushed: %d)\n", total, w->sfd,
                        data_size, w->flushed);
                if (total == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        logger_close_watcher(w);
                    }
                    L_DEBUG("LOGGER: watcher hit EAGAIN\n");
                } else if (total == 0) {
                    logger_close_watcher(w);
                } else {
                    int rem = total;
                    int x;
                    for (x = 0; x < iovcnt; x++) {
                        rem -= iov[x].iov_len;
                        if (rem >= 0) {
                            w->flushed += iov[x].iov_len + sizeof(logentry);
                        } else {
                            L_DEBUG("LOGGER: remainder %d\n", rem);
                            /* We have a remainder. do count logentry
                             * struct at this time. */
                            rem = abs(rem) + sizeof(logentry);
                            w->flushed += rem;
                            break;
                        }
                    }
                    w->min_flushed = w->flushed - rem;
                }
            }
            nfd++;
        }
    }

    logger_push_central_buf();
}

#define MAX_LOGGER_SLEEP 100000
#define MIN_LOGGER_SLEEP 0

/* Primary logger thread routine */
static void *logger_thread(void *arg) {
    useconds_t to_sleep = MIN_LOGGER_SLEEP;
    L_DEBUG("LOGGER: Starting logger thread\n");
    while (do_run_logger_thread) {
        int found_logs = 0;
        if (to_sleep)
            usleep(to_sleep);

        /* Call function to iterate each logger. */
        pthread_mutex_lock(&logger_stack_lock);
        /* check poll() for current slow watchers */
        found_logs = logger_iterate();
        logger_poll_watchers(1);
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

/* Global logger thread start/init */
void logger_init(void) {
    /* TODO: auto destructor when threads exit */
    /* TODO: error handling */

    /* init stack for iterating loggers */
    logger_stack_head = 0;
    logger_stack_tail = 0;
    pthread_key_create(&logger_key, NULL);

    logger_thread_buf = bipbuf_new(LOGGER_THREAD_BUF_SIZE);
    if (logger_thread_buf == NULL) {
        abort();
    }

    if (start_logger_thread() != 0) {
        abort();
    }
    /* FIXME: temp hack to always add STDERR watcher */
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

#define SET_LOGGER_TIME() \
    do { \
        if (l->eflags & LOG_TIME) { \
            gettimeofday(&e->tv, NULL); \
        } else { \
            e->tv.tv_sec = 0; \
            e->tv.tv_usec = 0; \
        } \
    } while (0)

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
    char scratch[512]; /* some local scratch space */
    item *it;

    const entry_details *d = &l->entry_map[event];
    int reqlen = d->reqlen;
    uint64_t gid = logger_get_gid();

    pthread_mutex_lock(&l->mutex);
    /* Request a maximum length of data to write to */
    e = (logentry *) bipbuf_request(buf, (sizeof(logentry) + reqlen));
    if (e == NULL) {
        pthread_mutex_unlock(&l->mutex);
        return LOGGER_RET_NOSPACE;
    }
    e->gid = gid;
    e->event = d->subtype;
    e->watcher_flag = d->watcher_flag;
    SET_LOGGER_TIME();

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
            it = (item *)entry;
            memcpy(scratch, ITEM_key(it), it->nkey);
            scratch[it->nkey] = '\0';
            total = snprintf((char *) e->data, reqlen, d->format, scratch,
                  (it->it_flags & ITEM_FETCHED) ? "yes" : "no",
                  (it->exptime > 0) ? (it->exptime - current_time) : -1,
                  (current_time - it->time));
            e->size = total + 1;

            break;
    }

    /* Push pointer forward by the actual amount required */
    if (bipbuf_push(buf, (sizeof(logentry) + e->size)) == 0) {
        fprintf(stderr, "LOGGER: Failed to bipbuf push a text entry\n");
        pthread_mutex_unlock(&l->mutex);
        return LOGGER_RET_ERR;
    }
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
    unsigned int size = 0;
    pthread_mutex_lock(&logger_stack_lock);
    if (watcher_count >= WATCHER_LIMIT) {
        return LOGGER_ADD_WATCHER_TOO_MANY;
    }

    for (x = 0; x < WATCHER_LIMIT; x++) {
        if (watchers[x] == NULL)
            break;
    }

    w = calloc(1, sizeof(logger_watcher));
    if (w == NULL)
        return LOGGER_ADD_WATCHER_FAILED;
    w->c = c;
    w->sfd = sfd;
    if (sfd == 0 && c == NULL) {
        w->t = LOGGER_WATCHER_STDERR;
    } else {
        w->t = LOGGER_WATCHER_CLIENT;
    }
    w->id = x;
    w->eflags = f;
    /* Skip any currently queued data, so we only print new lines. */
    if (bipbuf_peek_all(logger_thread_buf, &size) != NULL) {
        w->flushed = size;
        w->min_flushed = size;
    }
    watchers[x] = w;
    watcher_count++;
    /* Update what flags the global logs will watch */
    logger_set_flags();

    pthread_mutex_unlock(&logger_stack_lock);
    return LOGGER_ADD_WATCHER_OK;
}

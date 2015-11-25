/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include "memcached.h"
#include "bipbuffer.h"

#define LOGGER_DEBUG 0

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
logger_chunk *logger_thread_last_lc = NULL;
int logger_thread_lc_count = 0;

#if !defined(HAVE_GCC_ATOMICS) && !defined(__sun)
pthread_mutex_t logger_atomics_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

#define WATCHER_LIMIT 20
logger_watcher *watchers[20];
struct pollfd watchers_pollfds[20];
int watcher_count = 0;

/* Should this go somewhere else? */
static const entry_details default_entries[] = {
    [LOGGER_ASCII_CMD] = {LOGGER_TEXT_ENTRY, 512, "<%d %s"},
    [LOGGER_EVICTION] = {LOGGER_EVICTION_ENTRY, 512, "eviction: [key %s] [fetched: %s] [ttl: %d] [la: %d]"}
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

/* Centralized log chunk buffer. All worker threads dequeue into this buffer,
 * which gets written out to subscribed watchers.
 * The "latest" global chunk is tracked.
 * New chunks get attached to each active watcher, increasing refcount.
 * Watchers flush from this buffer (tracking w->flushed) until buffer is full.
 * When full, a new buffer is created and chained after the old one (lc->next)
 * Watchers then catch up, releasing ref's on old chunks as they complete
 * flushing.
 * When a chunk is fully flushed by all watchers, it's released back to the
 * central bipbuf.
 * When totally out of chunk space, the most-behind watchers are closed.
 *
 * This fiddling is done to avoid excess memcpy'ing. We write directly into
 * the central bipbuf rather than copy into it, and multiple readers access
 * it.
 */
static logger_chunk *logger_get_chunk(void) {
    logger_chunk *lc = logger_thread_last_lc;
    int x;

    if (lc && lc->filled == 0)
        return lc;

    lc = (logger_chunk *) bipbuf_request(logger_thread_buf, (8 * 1024));
    if (lc == NULL) {
        L_DEBUG("LOGGER: Chunk space full.\n");
        return NULL;
    }
    bipbuf_push(logger_thread_buf, (8 * 1024));
    L_DEBUG("LOGGER: Creating new chunk\n");
    memset(lc, 0, sizeof(logger_chunk));
    lc->size = (8 * 1024) - sizeof(logger_chunk);

    /* Each watcher gets a reference to this new chunk */
    for (x = 0; x < WATCHER_LIMIT; x++) {
        logger_watcher *w = watchers[x];
        if (w == NULL)
            continue;

        if (w->lc == NULL) {
            /* Watcher doesn't already have a chunk. */
            w->lc = lc;
        }
        lc->refcount++;
        w->chunks++;
    }

    if (logger_thread_last_lc) {
        assert(logger_thread_last_lc != lc);
        logger_thread_last_lc->next = lc;
    }
    logger_thread_last_lc = lc;
    logger_thread_lc_count++;

    return lc;
}

/* return FULLBUF to tell caller buffer is full.
 * caller will then flush and retry log parse
 */
static enum logger_parse_entry_ret logger_parse_entry(logger_chunk *lc, logentry *e) {
    int total = 0;

    switch (e->event) {
        case LOGGER_TEXT_ENTRY:
        case LOGGER_EVICTION_ENTRY:
            total = snprintf(lc->data + lc->written, (lc->size - lc->written), "[%d.%d] [%llu] %s\n",
                        (int)e->tv.tv_sec, (int)e->tv.tv_usec, (unsigned long long) e->gid, (char *) e->data);
            if (total >= (lc->size - lc->written) || total <= 0) {
                /* ran out of space. don't advance written, run a flush,
                 * retry write?
                 */
                L_DEBUG("LOGGER: Chunk filled\n");
                lc->filled = 1;
                return LOGGER_PARSE_ENTRY_FULLBUF;
            } else {
                lc->written += total;
            }
            break;
    }

    return LOGGER_PARSE_ENTRY_OK;
}

static void logger_chunk_release(logger_chunk *lc) {
    lc->refcount--;
    if (lc->refcount == 0) {
        L_DEBUG("LOGGER: Releasing logger chunk\n");
        if (lc->next == NULL) {
            L_DEBUG("LOGGER: Clearing last LC chunk reference\n");
            logger_thread_last_lc = NULL;
        }
        bipbuf_poll(logger_thread_buf, (8 * 1024));
        logger_thread_lc_count--;
    }
}

/* Called with logger stack locked.
 * Iterates over every watcher collecting enabled flags.
 */
static void logger_set_flags(void) {
    logger *l = NULL;
    int x = 0;
    struct logger_eflags f;
    memset(&f, 0, sizeof(struct logger_eflags));

    /* Would love to | the fields together, but bitfields have intederminate
     * sizing. Could use a union and some startup asserts to sniff out
     * platforms where 8 bitfields take more than a uint64_t.. Some research
     * is required though. For now an if/else tree will have to do.
     */
    for (x = 0; x < WATCHER_LIMIT; x++) {
        logger_watcher *w = watchers[x];
        if (w == NULL)
            continue;

        if (w->f.log_evictions)
            f.log_evictions = 1;

        if (w->f.log_fetchers)
            f.log_fetchers = 1;

        if (w->f.log_time)
            f.log_time = 1;
    }
    for (l = logger_stack_head; l != NULL; l=l->next) {
        /* lock logger, call function to manipulate it */
        memcpy(&l->f, &f, sizeof(struct logger_eflags));
    }
    return;
}

/* Called with logger stack locked.
 * Releases every chunk associated with a watcher and closes the connection.
 * We can't presently send a connection back to the worker for further
 * processing.
 */
static void logger_close_watcher(logger_watcher *w) {
    logger_chunk *lc = w->lc;
    L_DEBUG("LOGGER: Closing dead watcher\n");
    while (lc != NULL) {
        logger_chunk *nlc = lc->next;
        logger_chunk_release(lc);
        lc = nlc;
    }
    watchers[w->id] = NULL;
    sidethread_conn_close(w->c);
    watcher_count--;
    free(w);
    logger_set_flags();
}

/* Pick any number of "oldest" behind-watchers and kill them. */
static void logger_kill_watchers(const int count) {
    int x;
    logger_watcher *w;

    for (x = 0; x < WATCHER_LIMIT; x++) {
        w = watchers[x];
        if (w == NULL)
            continue;

        if (w->lc && w->chunks == count) {
            L_DEBUG("LOGGER: Killing watcher [%d] because it's too behind (%d)\n",
                    w->sfd, w->chunks);
            logger_close_watcher(w);
        }
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
    logentry *e;
    logger_chunk *lc;
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
        lc = logger_get_chunk();
        if (lc == NULL) {
            /* out of buffer space. show must go on, so kill something. */
            logger_kill_watchers(logger_thread_lc_count);
            continue;
        }
        ret = logger_parse_entry(lc, e);
        if (ret == LOGGER_PARSE_ENTRY_FULLBUF) {
            /* Buffer was full. Push the last up, force an early flush. */
            logger_poll_watchers(0);
            continue;
        } else if (ret != LOGGER_PARSE_ENTRY_OK) {
            fprintf(stderr, "LOGGER: Failed to parse log entry\n");
            abort();
        }
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

    for (x = 0; x < WATCHER_LIMIT; x++) {
        w = watchers[x];
        if (w == NULL)
            continue;

        /* If this chunk has been flushed, release it and start the next one.
         * Next chunk may be null, which stops writing. */
        if (w->lc != NULL && w->flushed >= w->lc->written && w->lc->filled) {
            logger_chunk *nlc = w->lc->next;
            logger_chunk_release(w->lc);
            /* More buffers to eat */
            w->lc = nlc;
            w->chunks--;
            w->flushed = 0;
        }

        if (w->lc != NULL && w->lc->written > w->flushed) {
            watchers_pollfds[nfd].fd = w->sfd;
            watchers_pollfds[nfd].events = POLLOUT;
            nfd++;
        } else if (force_poll) {
            watchers_pollfds[nfd].fd = w->sfd;
            watchers_pollfds[nfd].events = POLLIN;
            nfd++;
        }
    }

    if (nfd == 0)
        return;

    L_DEBUG("LOGGER: calling poll()\n");
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
        if (w->lc != NULL) {
            if (watchers_pollfds[nfd].revents & (POLLHUP|POLLERR)) {
                L_DEBUG("LOGGER: watcher closed during poll() call\n");
                logger_close_watcher(w);
            } else if (watchers_pollfds[nfd].revents & POLLOUT) {
                int total = 0;
                /* We can write a bit. */
                switch (w->t) {
                    case LOGGER_WATCHER_STDERR:
                        total = fwrite(w->lc->data + w->flushed, 1, w->lc->written - w->flushed, stderr);
                        break;
                    case LOGGER_WATCHER_CLIENT:
                        total = write(w->sfd, w->lc->data + w->flushed, w->lc->written - w->flushed);
                        break;
                }

                L_DEBUG("LOGGER: poll() wrote %d to %d (written: %d) (flushed: %d)\n", total, w->sfd,
                        w->lc->written, w->flushed);
                if (total == -1) {
                    if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        logger_close_watcher(w);
                    }
                    L_DEBUG("LOGGER: watcher hit EAGAIN\n");
                    nfd++;
                    continue;
                } else if (total == 0) {
                    logger_close_watcher(w);
                }

                w->flushed += total;
            }
            nfd++;
        }
    }
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
        if (l->f.log_time) { \
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
enum logger_add_watcher_ret logger_add_watcher(void *c, const int sfd, const struct logger_eflags f) {
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
    memcpy(&w->f, &f, sizeof(struct logger_eflags));
    /* Attach to an existing log chunk if there is one */
    if (logger_thread_last_lc && !logger_thread_last_lc->filled) {
        logger_chunk *lc = logger_thread_last_lc;
        lc->refcount++;
        w->lc = lc;
        w->flushed = lc->written; /* only write logs after we attach */
        w->chunks++;
    }
    watchers[x] = w;
    watcher_count++;
    /* Update what flags the global logs will watch */
    logger_set_flags();

    pthread_mutex_unlock(&logger_stack_lock);
    return LOGGER_ADD_WATCHER_OK;
}

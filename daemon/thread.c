/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Thread management for memcached.
 */
#include "config.h"
#include "memcached.h"
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>

#define ITEMS_PER_ALLOC 64

static char devnull[8192];
extern volatile sig_atomic_t memcached_shutdown;

/* An item in the connection queue. */
typedef struct conn_queue_item CQ_ITEM;
struct conn_queue_item {
    SOCKET            sfd;
    STATE_FUNC        init_state;
    int               event_flags;
    int               read_buffer_size;
    enum network_transport     transport;
    CQ_ITEM          *next;
};

/* A connection queue. */
typedef struct conn_queue CQ;
struct conn_queue {
    CQ_ITEM *head;
    CQ_ITEM *tail;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
};

/* Connection lock around accepting new connections */
pthread_mutex_t conn_lock = PTHREAD_MUTEX_INITIALIZER;

/* Lock for global stats */
static pthread_mutex_t stats_lock;

/* Free list of CQ_ITEM structs */
static CQ_ITEM *cqi_freelist;
static pthread_mutex_t cqi_freelist_lock;

static LIBEVENT_THREAD dispatcher_thread;

/*
 * Each libevent instance has a wakeup pipe, which other threads
 * can use to signal that they've put a new connection on its queue.
 */
static int nthreads;
static LIBEVENT_THREAD *threads;
static pthread_t *thread_ids;
LIBEVENT_THREAD *tap_thread;

/*
 * Number of worker threads that have finished setting themselves up.
 */
static int init_count = 0;
static pthread_mutex_t init_lock;
static pthread_cond_t init_cond;


static void thread_libevent_process(int fd, short which, void *arg);
static void libevent_tap_process(int fd, short which, void *arg);

/*
 * Initializes a connection queue.
 */
static void cq_init(CQ *cq) {
    pthread_mutex_init(&cq->lock, NULL);
    pthread_cond_init(&cq->cond, NULL);
    cq->head = NULL;
    cq->tail = NULL;
}

/*
 * Looks for an item on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the item, or NULL if no item is available
 */
static CQ_ITEM *cq_pop(CQ *cq) {
    CQ_ITEM *item;

    pthread_mutex_lock(&cq->lock);
    item = cq->head;
    if (NULL != item) {
        cq->head = item->next;
        if (NULL == cq->head)
            cq->tail = NULL;
    }
    pthread_mutex_unlock(&cq->lock);

    return item;
}

/*
 * Adds an item to a connection queue.
 */
static void cq_push(CQ *cq, CQ_ITEM *item) {
    item->next = NULL;

    pthread_mutex_lock(&cq->lock);
    if (NULL == cq->tail)
        cq->head = item;
    else
        cq->tail->next = item;
    cq->tail = item;
    pthread_cond_signal(&cq->cond);
    pthread_mutex_unlock(&cq->lock);
}

/*
 * Returns a fresh connection queue item.
 */
static CQ_ITEM *cqi_new(void) {
    CQ_ITEM *item = NULL;
    pthread_mutex_lock(&cqi_freelist_lock);
    if (cqi_freelist) {
        item = cqi_freelist;
        cqi_freelist = item->next;
    }
    pthread_mutex_unlock(&cqi_freelist_lock);

    if (NULL == item) {
        int i;

        /* Allocate a bunch of items at once to reduce fragmentation */
        item = malloc(sizeof(CQ_ITEM) * ITEMS_PER_ALLOC);
        if (NULL == item)
            return NULL;

        /*
         * Link together all the new items except the first one
         * (which we'll return to the caller) for placement on
         * the freelist.
         */
        for (i = 2; i < ITEMS_PER_ALLOC; i++)
            item[i - 1].next = &item[i];

        pthread_mutex_lock(&cqi_freelist_lock);
        item[ITEMS_PER_ALLOC - 1].next = cqi_freelist;
        cqi_freelist = &item[1];
        pthread_mutex_unlock(&cqi_freelist_lock);
    }

    return item;
}


/*
 * Frees a connection queue item (adds it to the freelist.)
 */
static void cqi_free(CQ_ITEM *item) {
    pthread_mutex_lock(&cqi_freelist_lock);
    item->next = cqi_freelist;
    cqi_freelist = item;
    pthread_mutex_unlock(&cqi_freelist_lock);
}


/*
 * Creates a worker thread.
 */
static void create_worker(void *(*func)(void *), void *arg, pthread_t *id) {
    pthread_attr_t  attr;
    int             ret;

    pthread_attr_init(&attr);

    if ((ret = pthread_create(id, &attr, func, arg)) != 0) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't create thread: %s\n",
                                        strerror(ret));
        exit(1);
    }
}

/****************************** LIBEVENT THREADS *****************************/

bool create_notification_pipe(LIBEVENT_THREAD *me)
{
    if (evutil_socketpair(SOCKETPAIR_AF, SOCK_STREAM, 0,
                          (void*)me->notify) == SOCKET_ERROR) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't create notify pipe: %s",
                                        strerror(errno));
        return false;
    }

    for (int j = 0; j < 2; ++j) {
        int flags = 1;
        setsockopt(me->notify[j], IPPROTO_TCP,
                   TCP_NODELAY, (void *)&flags, sizeof(flags));
        setsockopt(me->notify[j], SOL_SOCKET,
                   SO_REUSEADDR, (void *)&flags, sizeof(flags));


        if (evutil_make_socket_nonblocking(me->notify[j]) == -1) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Failed to enable non-blocking: %s",
                                            strerror(errno));
            return false;
        }
    }
    return true;
}

static void setup_dispatcher(struct event_base *main_base,
                             void (*dispatcher_callback)(int, short, void *))
{
    memset(&dispatcher_thread, 0, sizeof(dispatcher_thread));
    dispatcher_thread.type = DISPATCHER;
    dispatcher_thread.base = main_base;
    dispatcher_thread.thread_id = pthread_self();
    if (!create_notification_pipe(&dispatcher_thread)) {
        exit(1);
    }
    /* Listen for notifications from other threads */
    event_set(&dispatcher_thread.notify_event, dispatcher_thread.notify[0],
              EV_READ | EV_PERSIST, dispatcher_callback, &dispatcher_callback);
    event_base_set(dispatcher_thread.base, &dispatcher_thread.notify_event);

    if (event_add(&dispatcher_thread.notify_event, 0) == -1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't monitor libevent notify pipe\n");
        exit(1);
    }
}

/*
 * Set up a thread's information.
 */
static void setup_thread(LIBEVENT_THREAD *me, bool tap) {
    me->type = tap ? TAP : GENERAL;
    me->base = event_init();
    if (! me->base) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't allocate event base\n");
        exit(1);
    }

    /* Listen for notifications from other threads */
    event_set(&me->notify_event, me->notify[0],
              EV_READ | EV_PERSIST,
              tap ? libevent_tap_process : thread_libevent_process, me);
    event_base_set(me->base, &me->notify_event);

    if (event_add(&me->notify_event, 0) == -1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't monitor libevent notify pipe\n");
        exit(1);
    }

    if (!tap) {
        me->new_conn_queue = malloc(sizeof(struct conn_queue));
        if (me->new_conn_queue == NULL) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Failed to allocate memory for connection queue");
            exit(EXIT_FAILURE);
        }
        cq_init(me->new_conn_queue);
    }

    if ((pthread_mutex_init(&me->mutex, NULL) != 0)) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Failed to initialize mutex: %s\n",
                                        strerror(errno));
        exit(EXIT_FAILURE);
    }

    me->suffix_cache = cache_create("suffix", SUFFIX_SIZE, sizeof(char*),
                                    NULL, NULL);
    if (me->suffix_cache == NULL) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Failed to create suffix cache\n");
        exit(EXIT_FAILURE);
    }
}

/*
 * Worker thread: main event loop
 */
static void *worker_libevent(void *arg) {
    LIBEVENT_THREAD *me = arg;

    /* Any per-thread setup can happen here; thread_init() will block until
     * all threads have finished initializing.
     */

    pthread_mutex_lock(&init_lock);
    init_count++;
    pthread_cond_signal(&init_cond);
    pthread_mutex_unlock(&init_lock);

    event_base_loop(me->base, 0);
    return NULL;
}

int number_of_pending(conn *c, conn *list) {
    int rv = 0;
    for (; list; list = list->next) {
        if (list == c) {
            rv ++;
        }
    }
    return rv;
}

/*
 * Processes an incoming "handle a new connection" item. This is called when
 * input arrives on the libevent wakeup pipe.
 */
static void thread_libevent_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    assert(me->type == GENERAL);
    CQ_ITEM *item;

    if (recv(fd, devnull, sizeof(devnull), 0) == -1) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Can't read from libevent pipe: %s\n",
                                            strerror(errno));
        }
    }

    if (memcached_shutdown) {
         event_base_loopbreak(me->base);
         return ;
    }

    while ((item = cq_pop(me->new_conn_queue)) != NULL) {
        conn *c = conn_new(item->sfd, item->init_state, item->event_flags,
                           item->read_buffer_size, item->transport, me->base,
                           NULL);
        if (c == NULL) {
            if (IS_UDP(item->transport)) {
                settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                         "Can't listen for events on UDP socket\n");
                exit(1);
            } else {
                if (settings.verbose > 0) {
                    settings.extensions.logger->log(EXTENSION_LOG_INFO, NULL,
                            "Can't listen for events on fd %d\n",
                            item->sfd);
                }
                closesocket(item->sfd);
            }
        } else {
            assert(c->thread == NULL);
            c->thread = me;
        }
        cqi_free(item);
    }

    pthread_mutex_lock(&me->mutex);
    conn* pending = me->pending_io;
    me->pending_io = NULL;
    pthread_mutex_unlock(&me->mutex);
    while (pending != NULL) {
        conn *c = pending;
        assert(me == c->thread);
        pending = pending->next;
        c->next = NULL;
        register_event(c, 0);
        /*
         * We don't want the thread to keep on serving all of the data
         * from the context of the notification pipe, so just let it
         * run one time to set up the correct mask in libevent
         */
        c->nevents = 1;
       /* c->nevents = settings.reqs_per_event; */
        while (c->state(c)) {
            /* do task */
        }
    }
}

extern volatile rel_time_t current_time;

bool has_cycle(conn *c) {
    if (!c) {
        return false;
    }
    conn *slowNode, *fastNode1, *fastNode2;
    slowNode = fastNode1 = fastNode2 = c;
    while (slowNode && (fastNode1 = fastNode2->next) && (fastNode2 = fastNode1->next)) {
        if (slowNode == fastNode1 || slowNode == fastNode2) {
            return true;
        }
        slowNode = slowNode->next;
    }
    return false;
}

bool list_contains(conn *haystack, conn *needle) {
    for (; haystack; haystack = haystack -> next) {
        if (needle == haystack) {
            return true;
        }
    }
    return false;
}

conn* list_remove(conn *haystack, conn *needle) {
    if (!haystack) {
        return NULL;
    }

    if (haystack == needle) {
        conn *rv = needle->next;
        needle->next = NULL;
        return rv;
    }

    haystack->next = list_remove(haystack->next, needle);

    return haystack;
}

size_t list_to_array(conn **dest, size_t max_items, conn **l) {
    size_t n_items = 0;
    for (; *l && n_items < max_items - 1; ++n_items) {
        dest[n_items] = *l;
        *l = dest[n_items]->next;
        dest[n_items]->next = NULL;
        dest[n_items]->list_state |= LIST_STATE_PROCESSING;
    }
    return n_items;
}

void enlist_conn(conn *c, conn **list) {
    LIBEVENT_THREAD *thr = c->thread;
    assert(list == &thr->pending_io || list == &thr->pending_close);
    if ((c->list_state & LIST_STATE_PROCESSING) == 0) {
        assert(!list_contains(thr->pending_close, c));
        assert(!list_contains(thr->pending_io, c));
        assert(c->next == NULL);
        c->next = *list;
        *list = c;
        assert(list_contains(*list, c));
        assert(!has_cycle(*list));
    } else {
        c->list_state |= (list == &thr->pending_io ?
                          LIST_STATE_REQ_PENDING_IO :
                          LIST_STATE_REQ_PENDING_CLOSE);
    }
}

void finalize_list(conn **list, size_t items) {
    for (size_t i = 0; i < items; i++) {
        if (list[i] != NULL) {
            list[i]->list_state &= ~LIST_STATE_PROCESSING;
            if (list[i]->sfd != INVALID_SOCKET) {
                if (list[i]->list_state & LIST_STATE_REQ_PENDING_IO) {
                    enlist_conn(list[i], &list[i]->thread->pending_io);
                } else if (list[i]->list_state & LIST_STATE_REQ_PENDING_CLOSE) {
                    enlist_conn(list[i], &list[i]->thread->pending_close);
                }
            }
            list[i]->list_state = 0;
        }
    }
}


static void libevent_tap_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    assert(me->type == TAP);

    if (recv(fd, devnull, sizeof(devnull), 0) == -1) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Can't read from libevent pipe: %s\n",
                                            strerror(errno));
        }
    }

    if (memcached_shutdown) {
        event_base_loopbreak(me->base);
        return ;
    }

    // Do we have pending closes?
    const size_t max_items = 256;
    LOCK_THREAD(me);
    conn *pending_close[max_items];
    size_t n_pending_close = 0;

    if (me->pending_close && me->last_checked != current_time) {
        assert(!has_cycle(me->pending_close));
        me->last_checked = current_time;

        n_pending_close = list_to_array(pending_close, max_items,
                                        &me->pending_close);
    }

    // Now copy the pending IO buffer and run them...
    conn *pending_io[max_items];
    size_t n_items = list_to_array(pending_io, max_items, &me->pending_io);

    UNLOCK_THREAD(me);
    for (size_t i = 0; i < n_items; ++i) {
        conn *c = pending_io[i];

        assert(c->thread == me);

        LOCK_THREAD(c->thread);
        assert(me == c->thread);
        settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                        "Processing tap pending_io for %d\n", c->sfd);

        UNLOCK_THREAD(me);
        if (!c->registered_in_libevent) {
            register_event(c, NULL);
        }
        /*
         * We don't want the thread to keep on serving all of the data
         * from the context of the notification pipe, so just let it
         * run one time to set up the correct mask in libevent
         */
        c->nevents = 1;
        c->which = EV_WRITE;
        while (c->state(c)) {
            /* do task */
        }
    }

    /* Close any connections pending close */
    for (size_t i = 0; i < n_pending_close; ++i) {
        conn *ce = pending_close[i];
        if (ce->refcount == 1) {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                            "OK, time to nuke: %p\n",
                                            (void*)ce);
            assert(ce->next == NULL);
            conn_close(ce);
            pending_close[i] = NULL;
        } else {
            LOCK_THREAD(me);
            enlist_conn(ce, &me->pending_close);
            UNLOCK_THREAD(me);
        }
    }

    LOCK_THREAD(me);
    finalize_list(pending_io, n_items);
    finalize_list(pending_close, n_pending_close);
    UNLOCK_THREAD(me);
}

static bool is_thread_me(LIBEVENT_THREAD *thr) {
#ifdef __WIN32__
    pthread_t tid = pthread_self();
    return(tid.p == thr->thread_id.p && tid.x == thr->thread_id.x);
#else
    return pthread_self() == thr->thread_id;
#endif
}

void notify_io_complete(const void *cookie, ENGINE_ERROR_CODE status)
{
    if (cookie == NULL) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "notify_io_complete called without a valid cookie (status %x)\n",
                                        status);
        return ;
    }

    struct conn *conn = (struct conn *)cookie;

    settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                    "Got notify from %d, status %x\n",
                                    conn->sfd, status);

    /*
    ** TROND:
    **   I changed the logic for the tap connections so that the core
    **   issues the ON_DISCONNECT call to the engine instead of trying
    **   to close the connection. Then it let's the engine have a grace
    **   period to call notify_io_complete if not it will go ahead and
    **   kill it.
    **
    */
    if (status == ENGINE_DISCONNECT && conn->thread == tap_thread) {
        LOCK_THREAD(conn->thread);

        /** Remove the connection from both of the lists */
        conn->thread->pending_io = list_remove(conn->thread->pending_io,
                                               conn);
        conn->thread->pending_close = list_remove(conn->thread->pending_close,
                                                  conn);


        if (conn->state == conn_pending_close ||
            conn->state == conn_immediate_close) {
            if (conn->refcount == 1) {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                                "Complete shutdown of %p",
                                                conn);
                conn_set_state(conn, conn_immediate_close);
                enlist_conn(conn, &conn->thread->pending_close);
            } else {
                settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                                "Keep on waiting for shutdown of %p",
                                                conn);
            }
        } else {
            settings.extensions.logger->log(EXTENSION_LOG_DEBUG, NULL,
                                            "Engine requested shutdown of %p",
                                            conn);
            conn_set_state(conn, conn_closing);
            enlist_conn(conn, &conn->thread->pending_io);
        }

        if (!is_thread_me(conn->thread)) {
            /* kick the thread in the butt */
            notify_thread(conn->thread);
        }

        UNLOCK_THREAD(conn->thread);
        return;
    }

    /*
    ** There may be a race condition between the engine calling this
    ** function and the core closing the connection.
    ** Let's lock the connection structure (this might not be the
    ** correct one) and re-evaluate.
    */
    LIBEVENT_THREAD *thr = conn->thread;
    if (thr == NULL || (conn->state == conn_closing ||
                        conn->state == conn_pending_close ||
                        conn->state == conn_immediate_close)) {
        return;
    }

    int notify = 0;

    LOCK_THREAD(thr);
    if (thr != conn->thread || !conn->ewouldblock) {
        // Ignore
        UNLOCK_THREAD(thr);
        return;
    }

    conn->aiostat = status;

    /* Move the connection to the closing state if the engine
     * wants it to be disconnected
     */
    if (status == ENGINE_DISCONNECT) {
        conn->state = conn_closing;
        notify = 1;
        thr->pending_io = list_remove(thr->pending_io, conn);
        if (number_of_pending(conn, thr->pending_close) == 0) {
            enlist_conn(conn, &thr->pending_close);
        }
    } else {
        if (number_of_pending(conn, thr->pending_io) +
            number_of_pending(conn, thr->pending_close) == 0) {
            if (thr->pending_io == NULL) {
                notify = 1;
            }
            enlist_conn(conn, &thr->pending_io);
        }
    }
    UNLOCK_THREAD(thr);

    /* kick the thread in the butt */
    if (notify) {
        notify_thread(thr);
    }
}

/* Which thread we assigned a connection to most recently. */
static int last_thread = -1;

/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(SOCKET sfd, STATE_FUNC init_state, int event_flags,
                       int read_buffer_size, enum network_transport transport) {
    CQ_ITEM *item = cqi_new();
    int tid = (last_thread + 1) % settings.num_threads;

    LIBEVENT_THREAD *thread = threads + tid;

    last_thread = tid;

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;

    cq_push(thread->new_conn_queue, item);

    MEMCACHED_CONN_DISPATCH(sfd, (uintptr_t)thread->thread_id);
    notify_thread(thread);
}

/*
 * Returns true if this is the thread that listens for new TCP connections.
 */
int is_listen_thread() {
#ifdef __WIN32__
    pthread_t tid = pthread_self();
    return(tid.p == dispatcher_thread.thread_id.p && tid.x == dispatcher_thread.thread_id.x);
#else
    return pthread_self() == dispatcher_thread.thread_id;
#endif
}

void notify_dispatcher(void) {
    notify_thread(&dispatcher_thread);
}

/******************************* GLOBAL STATS ******************************/

void STATS_LOCK() {
    pthread_mutex_lock(&stats_lock);
}

void STATS_UNLOCK() {
    pthread_mutex_unlock(&stats_lock);
}

void threadlocal_stats_clear(struct thread_stats *stats) {
    stats->cmd_get = 0;
    stats->get_misses = 0;
    stats->delete_misses = 0;
    stats->incr_misses = 0;
    stats->decr_misses = 0;
    stats->incr_hits = 0;
    stats->decr_hits = 0;
    stats->cas_misses = 0;
    stats->bytes_written = 0;
    stats->bytes_read = 0;
    stats->cmd_flush = 0;
    stats->conn_yields = 0;
    stats->auth_cmds = 0;
    stats->auth_errors = 0;

    memset(stats->slab_stats, 0,
           sizeof(struct slab_stats) * MAX_NUMBER_OF_SLAB_CLASSES);
}

void threadlocal_stats_reset(struct thread_stats *thread_stats) {
    int ii;
    for (ii = 0; ii < settings.num_threads; ++ii) {
        pthread_mutex_lock(&thread_stats[ii].mutex);
        threadlocal_stats_clear(&thread_stats[ii]);
        pthread_mutex_unlock(&thread_stats[ii].mutex);
    }
}

void threadlocal_stats_aggregate(struct thread_stats *thread_stats, struct thread_stats *stats) {
    int ii, sid;
    for (ii = 0; ii < settings.num_threads; ++ii) {
        pthread_mutex_lock(&thread_stats[ii].mutex);

        stats->cmd_get += thread_stats[ii].cmd_get;
        stats->get_misses += thread_stats[ii].get_misses;
        stats->delete_misses += thread_stats[ii].delete_misses;
        stats->decr_misses += thread_stats[ii].decr_misses;
        stats->incr_misses += thread_stats[ii].incr_misses;
        stats->decr_hits += thread_stats[ii].decr_hits;
        stats->incr_hits += thread_stats[ii].incr_hits;
        stats->cas_misses += thread_stats[ii].cas_misses;
        stats->bytes_read += thread_stats[ii].bytes_read;
        stats->bytes_written += thread_stats[ii].bytes_written;
        stats->cmd_flush += thread_stats[ii].cmd_flush;
        stats->conn_yields += thread_stats[ii].conn_yields;
        stats->auth_cmds += thread_stats[ii].auth_cmds;
        stats->auth_errors += thread_stats[ii].auth_errors;

        for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
            stats->slab_stats[sid].cmd_set +=
                thread_stats[ii].slab_stats[sid].cmd_set;
            stats->slab_stats[sid].get_hits +=
                thread_stats[ii].slab_stats[sid].get_hits;
            stats->slab_stats[sid].delete_hits +=
                thread_stats[ii].slab_stats[sid].delete_hits;
            stats->slab_stats[sid].cas_hits +=
                thread_stats[ii].slab_stats[sid].cas_hits;
            stats->slab_stats[sid].cas_badval +=
                thread_stats[ii].slab_stats[sid].cas_badval;
        }

        pthread_mutex_unlock(&thread_stats[ii].mutex);
    }
}

void slab_stats_aggregate(struct thread_stats *stats, struct slab_stats *out) {
    int sid;

    out->cmd_set = 0;
    out->get_hits = 0;
    out->delete_hits = 0;
    out->cas_hits = 0;
    out->cas_badval = 0;

    for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
        out->cmd_set += stats->slab_stats[sid].cmd_set;
        out->get_hits += stats->slab_stats[sid].get_hits;
        out->delete_hits += stats->slab_stats[sid].delete_hits;
        out->cas_hits += stats->slab_stats[sid].cas_hits;
        out->cas_badval += stats->slab_stats[sid].cas_badval;
    }
}

/*
 * Initializes the thread subsystem, creating various worker threads.
 *
 * nthreads  Number of worker event handler threads to spawn
 * main_base Event base for main thread
 */
void thread_init(int nthr, struct event_base *main_base,
                 void (*dispatcher_callback)(int, short, void *)) {
    int i;
    nthreads = nthr + 1;

    pthread_mutex_init(&stats_lock, NULL);
    pthread_mutex_init(&init_lock, NULL);
    pthread_cond_init(&init_cond, NULL);

    pthread_mutex_init(&cqi_freelist_lock, NULL);
    cqi_freelist = NULL;

    threads = calloc(nthreads, sizeof(LIBEVENT_THREAD));
    if (! threads) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't allocate thread descriptors: %s",
                                        strerror(errno));
        exit(1);
    }
    thread_ids = calloc(nthreads, sizeof(pthread_t));
    if (! thread_ids) {
        perror("Can't allocate thread descriptors");
        exit(1);
    }

    setup_dispatcher(main_base, dispatcher_callback);

    for (i = 0; i < nthreads; i++) {
        if (!create_notification_pipe(&threads[i])) {
            exit(1);
        }
        threads[i].index = i;

        setup_thread(&threads[i], i == (nthreads - 1));
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 0; i < nthreads; i++) {
        create_worker(worker_libevent, &threads[i], &thread_ids[i]);
        threads[i].thread_id = thread_ids[i];
    }

    tap_thread = &threads[nthreads - 1];

    /* Wait for all the threads to set themselves up before returning. */
    pthread_mutex_lock(&init_lock);
    while (init_count < nthreads) {
        pthread_cond_wait(&init_cond, &init_lock);
    }
    pthread_mutex_unlock(&init_lock);
}

void threads_shutdown(void)
{
    for (int ii = 0; ii < nthreads; ++ii) {
        notify_thread(&threads[ii]);
        pthread_join(thread_ids[ii], NULL);
    }
    for (int ii = 0; ii < nthreads; ++ii) {
        safe_close(threads[ii].notify[0]);
        safe_close(threads[ii].notify[1]);
    }
}

void notify_thread(LIBEVENT_THREAD *thread) {
    if (send(thread->notify[1], "", 1, 0) != 1) {
        if (thread == tap_thread) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Failed to notify TAP thread: %s",
                                            strerror(errno));
        } else {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Failed to notify thread: %s",
                                            strerror(errno));
        }
    }
}

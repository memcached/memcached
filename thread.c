/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Thread management for memcached.
 */
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

#define ITEMS_PER_ALLOC 64

extern volatile sig_atomic_t memcached_shutdown;

/* An item in the connection queue. */
typedef struct conn_queue_item CQ_ITEM;
struct conn_queue_item {
    int               sfd;
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

static LIBEVENT_DISPATCHER_THREAD dispatcher_thread;

/*
 * Each libevent instance has a wakeup pipe, which other threads
 * can use to signal that they've put a new connection on its queue.
 */
static int nthreads;
static LIBEVENT_THREAD *threads;
static pthread_t *thread_ids;
LIBEVENT_THREAD tap_thread;
static pthread_t tap_thread_id;

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
    event_set(&me->notify_event, me->notify_receive_fd,
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
    char buf[1];

    if (memcached_shutdown) {
         event_base_loopbreak(me->base);
         return ;
    }

    if (read(fd, buf, 1) != 1)
        if (settings.verbose > 0)
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't read from libevent pipe: %s\n",
                                        strerror(errno));

    item = cq_pop(me->new_conn_queue);

    if (NULL != item) {
        conn *c = conn_new(item->sfd, item->init_state, item->event_flags,
                           item->read_buffer_size, item->transport, me->base, NULL);
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
                close(item->sfd);
            }
        } else {
            assert(c->thread == NULL);
            c->thread = me;
        }
        cqi_free(item);
    }

    conn* pending = NULL;
    pthread_mutex_lock(&me->mutex);
    if (me->pending_io != NULL) {
        pending = me->pending_io;
        me->pending_io = NULL;
    }
    pthread_mutex_unlock(&me->mutex);
    while (pending != NULL) {
        conn *c = pending;
        assert(me == c->thread);
        pending = pending->next;
        c->next = NULL;
        event_add(&c->event, 0);

        c->nevents = settings.reqs_per_event;
        while (c->state(c)) {
            /* do task */
        }
    }
}

static void libevent_tap_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    assert(me->type == TAP);
    char buf[1];

    if (memcached_shutdown) {
        event_base_loopbreak(me->base);
        return ;
    }

    if (read(fd, buf, 1) != 1) {
        if (settings.verbose > 0) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Can't read from libevent pipe: %s\n",
                                            strerror(errno));
        }
    }

    conn* pending = NULL;
    pthread_mutex_lock(&me->mutex);
    if (me->pending_io != NULL) {
        pending = me->pending_io;
        me->pending_io = NULL;
    }
    pthread_mutex_unlock(&me->mutex);
    while (pending != NULL) {
        conn *c = pending;

        assert(c->thread == me);

        LOCK_THREAD(c->thread);
        assert(me == c->thread);
        pending = pending->next;
        c->next = NULL;
        assert(number_of_pending(c, pending) == 0);

        UNLOCK_THREAD(me);
        c->nevents = settings.reqs_per_tap_event;
        c->which = EV_WRITE;

        while (c->state(c)) {
            /* do task */
        }
    }
}

void notify_io_complete(const void *cookie, ENGINE_ERROR_CODE status)
{
    struct conn *conn = (struct conn *)cookie;

    /*
    ** There may be a race condition between the engine calling this
    ** function and the core closing the connection.
    ** Let's lock the connection structure (this might not be the
    ** correct one) and re-evaluate.
    */
    LIBEVENT_THREAD *thr = conn->thread;

    if (thr == NULL || conn->state == conn_closing) {
        return;
    }

    int notify = 0;

    LOCK_THREAD(thr);

    if (thr != conn->thread || conn->state == conn_closing || !conn->ewouldblock) {
        UNLOCK_THREAD(thr);
        return;
    }

    conn->aiostat = status;

    /* Move the connection to the closing state if the engine
     * wants it to be disconnected
     */
    if (status == ENGINE_DISCONNECT) {
        conn->state = conn_closing;
    }

    if (number_of_pending(conn, thr->pending_io) == 0) {
        if (thr->pending_io == NULL) {
            notify = 1;
        }
        conn->next = thr->pending_io;
        thr->pending_io = conn;
    }
    assert(number_of_pending(conn, thr->pending_io) == 1);
    UNLOCK_THREAD(thr);

    /* kick the thread in the butt */
    if (notify && write(thr->notify_send_fd, "", 1) != 1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Writing to thread notify pipe: %s",
                                        strerror(errno));
    }
}

/* Which thread we assigned a connection to most recently. */
static int last_thread = -1;

/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(int sfd, STATE_FUNC init_state, int event_flags,
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
    if (write(thread->notify_send_fd, "", 1) != 1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Writing to thread notify pipe: %s",
                                        strerror(errno));
    }
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
void thread_init(int nthr, struct event_base *main_base) {
    int i;
    nthreads = nthr;
#ifdef __WIN32__
    struct sockaddr_in serv_addr;
    int sockfd;

    if ((sockfd = createLocalListSock(&serv_addr)) < 0)
        exit(1);
#endif

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

    dispatcher_thread.base = main_base;
    dispatcher_thread.thread_id = pthread_self();

    int fds[2];
    for (i = 0; i < nthreads; i++) {
#ifdef __WIN32__
        if (createLocalSocketPair(sockfd,fds,&serv_addr) == -1) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Can't create notify pipe: %s",
                                            strerror(errno));
            exit(1);
        }
#else
        if (pipe(fds)) {
            settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                            "Can't create notify pipe: %s",
                                            strerror(errno));
            exit(1);
        }
#endif

        threads[i].notify_receive_fd = fds[0];
        threads[i].notify_send_fd = fds[1];
        threads[i].index = i;

        setup_thread(&threads[i], false);
#ifdef __WIN32__
        if (i == (nthreads - 1)) {
            shutdown(sockfd, 2);
        }
#endif
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 0; i < nthreads; i++) {
        create_worker(worker_libevent, &threads[i], &thread_ids[i]);
    }

#ifdef __WIN32__
    if (createLocalSocketPair(sockfd, fds, &serv_addr) == -1) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't create notify pipe: %s",
                                        strerror(errno));
        exit(1);
    }
#else
    if (pipe(fds)) {
        settings.extensions.logger->log(EXTENSION_LOG_WARNING, NULL,
                                        "Can't create notify pipe: %s",
                                        strerror(errno));
        exit(1);
    }
#endif

    tap_thread.notify_receive_fd = fds[0];
    tap_thread.notify_send_fd = fds[1];
    tap_thread.index = i;
    setup_thread(&tap_thread, true);
    create_worker(worker_libevent, &tap_thread, &tap_thread_id);

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
        if (write(threads[ii].notify_send_fd, "", 1) < 0) {
            perror("write failure shutting down.");
        }
        pthread_join(thread_ids[ii], NULL);
    }
    if (write(tap_thread.notify_send_fd, "", 1) < 0) {
        perror("write failure shutting down.");
    }
    pthread_join(tap_thread_id, NULL);
    close(tap_thread.notify_receive_fd);
    close(tap_thread.notify_send_fd);
    for (int ii = 0; ii < nthreads; ++ii) {
        close(threads[ii].notify_send_fd);
        close(threads[ii].notify_receive_fd);
    }
}

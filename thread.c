/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Thread management for memcached.
 */
#include "memcached.h"
#ifdef EXTSTORE
#include "storage.h"
#endif
#ifdef HAVE_EVENTFD
#include <sys/eventfd.h>
#endif
#ifdef PROXY
#include "proto_proxy.h"
#endif
#include <assert.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "queue.h"

#ifdef __sun
#include <atomic.h>
#endif

#ifdef TLS
#include <openssl/ssl.h>
#endif

#define ITEMS_PER_ALLOC 64

/* An item in the connection queue. */
enum conn_queue_item_modes {
    queue_new_conn,   /* brand new connection. */
    queue_pause,      /* pause thread */
    queue_timeout,    /* socket sfd timed out */
    queue_redispatch, /* return conn from side thread */
    queue_stop,       /* exit thread */
    queue_return_io,  /* returning a pending IO object immediately */
#ifdef PROXY
    queue_proxy_reload, /* signal proxy to reload worker VM */
#endif
};
typedef struct conn_queue_item CQ_ITEM;
struct conn_queue_item {
    int               sfd;
    enum conn_states  init_state;
    int               event_flags;
    int               read_buffer_size;
    enum network_transport     transport;
    enum conn_queue_item_modes mode;
    conn *c;
    void    *ssl;
    uint64_t conntag;
    enum protocol bproto;
    io_pending_t *io; // IO when used for deferred IO handling.
    STAILQ_ENTRY(conn_queue_item) i_next;
};

/* A connection queue. */
typedef struct conn_queue CQ;
struct conn_queue {
    STAILQ_HEAD(conn_ev_head, conn_queue_item) head;
    pthread_mutex_t lock;
    cache_t *cache; /* freelisted objects */
};

/* Locks for cache LRU operations */
pthread_mutex_t lru_locks[POWER_LARGEST];

/* Connection lock around accepting new connections */
pthread_mutex_t conn_lock = PTHREAD_MUTEX_INITIALIZER;

#if !defined(HAVE_GCC_ATOMICS) && !defined(__sun)
pthread_mutex_t atomics_mutex = PTHREAD_MUTEX_INITIALIZER;
#endif

/* Lock for global stats */
static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;

/* Lock to cause worker threads to hang up after being woken */
static pthread_mutex_t worker_hang_lock;

static pthread_mutex_t *item_locks;
/* size of the item lock hash table */
static uint32_t item_lock_count;
unsigned int item_lock_hashpower;
#define hashsize(n) ((unsigned long int)1<<(n))
#define hashmask(n) (hashsize(n)-1)

/*
 * Each libevent instance has a wakeup pipe, which other threads
 * can use to signal that they've put a new connection on its queue.
 */
static LIBEVENT_THREAD *threads;

/*
 * Number of worker threads that have finished setting themselves up.
 */
static int init_count = 0;
static pthread_mutex_t init_lock;
static pthread_cond_t init_cond;

static void notify_worker(LIBEVENT_THREAD *t, CQ_ITEM *item);
static void notify_worker_fd(LIBEVENT_THREAD *t, int sfd, enum conn_queue_item_modes mode);
static CQ_ITEM *cqi_new(CQ *cq);
static void cq_push(CQ *cq, CQ_ITEM *item);

static void thread_libevent_process(evutil_socket_t fd, short which, void *arg);

/* item_lock() must be held for an item before any modifications to either its
 * associated hash bucket, or the structure itself.
 * LRU modifications must hold the item lock, and the LRU lock.
 * LRU's accessing items must item_trylock() before modifying an item.
 * Items accessible from an LRU must not be freed or modified
 * without first locking and removing from the LRU.
 */

void item_lock(uint32_t hv) {
    mutex_lock(&item_locks[hv & hashmask(item_lock_hashpower)]);
}

void *item_trylock(uint32_t hv) {
    pthread_mutex_t *lock = &item_locks[hv & hashmask(item_lock_hashpower)];
    if (pthread_mutex_trylock(lock) == 0) {
        return lock;
    }
    return NULL;
}

void item_trylock_unlock(void *lock) {
    mutex_unlock((pthread_mutex_t *) lock);
}

void item_unlock(uint32_t hv) {
    mutex_unlock(&item_locks[hv & hashmask(item_lock_hashpower)]);
}

static void wait_for_thread_registration(int nthreads) {
    while (init_count < nthreads) {
        pthread_cond_wait(&init_cond, &init_lock);
    }
}

static void register_thread_initialized(void) {
    pthread_mutex_lock(&init_lock);
    init_count++;
    pthread_cond_signal(&init_cond);
    pthread_mutex_unlock(&init_lock);
    /* Force worker threads to pile up if someone wants us to */
    pthread_mutex_lock(&worker_hang_lock);
    pthread_mutex_unlock(&worker_hang_lock);
}

/* Must not be called with any deeper locks held */
void pause_threads(enum pause_thread_types type) {
    int i;
    bool pause_workers = false;

    switch (type) {
        case PAUSE_ALL_THREADS:
            slabs_rebalancer_pause();
            lru_maintainer_pause();
            lru_crawler_pause();
#ifdef EXTSTORE
            storage_compact_pause();
            storage_write_pause();
#endif
        case PAUSE_WORKER_THREADS:
            pause_workers = true;
            pthread_mutex_lock(&worker_hang_lock);
            break;
        case RESUME_ALL_THREADS:
            slabs_rebalancer_resume();
            lru_maintainer_resume();
            lru_crawler_resume();
#ifdef EXTSTORE
            storage_compact_resume();
            storage_write_resume();
#endif
        case RESUME_WORKER_THREADS:
            pthread_mutex_unlock(&worker_hang_lock);
            break;
        default:
            fprintf(stderr, "Unknown lock type: %d\n", type);
            assert(1 == 0);
            break;
    }

    /* Only send a message if we have one. */
    if (!pause_workers) {
        return;
    }

    pthread_mutex_lock(&init_lock);
    init_count = 0;
    for (i = 0; i < settings.num_threads; i++) {
        notify_worker_fd(&threads[i], 0, queue_pause);
    }
    wait_for_thread_registration(settings.num_threads);
    pthread_mutex_unlock(&init_lock);
}

// MUST not be called with any deeper locks held
// MUST be called only by parent thread
// Note: listener thread is the "main" event base, which has exited its
// loop in order to call this function.
void stop_threads(void) {
    int i;

    // assoc can call pause_threads(), so we have to stop it first.
    stop_assoc_maintenance_thread();
    if (settings.verbose > 0)
        fprintf(stderr, "stopped assoc\n");

    if (settings.verbose > 0)
        fprintf(stderr, "asking workers to stop\n");

    pthread_mutex_lock(&worker_hang_lock);
    pthread_mutex_lock(&init_lock);
    init_count = 0;
    for (i = 0; i < settings.num_threads; i++) {
        notify_worker_fd(&threads[i], 0, queue_stop);
    }
    wait_for_thread_registration(settings.num_threads);
    pthread_mutex_unlock(&init_lock);

    // All of the workers are hung but haven't done cleanup yet.

    if (settings.verbose > 0)
        fprintf(stderr, "asking background threads to stop\n");

    // stop each side thread.
    // TODO: Verify these all work if the threads are already stopped
    stop_item_crawler_thread(CRAWLER_WAIT);
    if (settings.verbose > 0)
        fprintf(stderr, "stopped lru crawler\n");
    if (settings.lru_maintainer_thread) {
        stop_lru_maintainer_thread();
        if (settings.verbose > 0)
            fprintf(stderr, "stopped maintainer\n");
    }
    if (settings.slab_reassign) {
        stop_slab_maintenance_thread();
        if (settings.verbose > 0)
            fprintf(stderr, "stopped slab mover\n");
    }
    logger_stop();
    if (settings.verbose > 0)
        fprintf(stderr, "stopped logger thread\n");
    stop_conn_timeout_thread();
    if (settings.verbose > 0)
        fprintf(stderr, "stopped idle timeout thread\n");

    // Close all connections then let the workers finally exit.
    if (settings.verbose > 0)
        fprintf(stderr, "closing connections\n");
    conn_close_all();
    pthread_mutex_unlock(&worker_hang_lock);
    if (settings.verbose > 0)
        fprintf(stderr, "reaping worker threads\n");
    for (i = 0; i < settings.num_threads; i++) {
        pthread_join(threads[i].thread_id, NULL);
    }

    if (settings.verbose > 0)
        fprintf(stderr, "all background threads stopped\n");

    // At this point, every background thread must be stopped.
}

/*
 * Initializes a connection queue.
 */
static void cq_init(CQ *cq) {
    pthread_mutex_init(&cq->lock, NULL);
    STAILQ_INIT(&cq->head);
    cq->cache = cache_create("cq", sizeof(CQ_ITEM), sizeof(char *));
    if (cq->cache == NULL) {
        fprintf(stderr, "Failed to create connection queue cache\n");
        exit(EXIT_FAILURE);
    }
}

/*
 * Looks for an item on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the item, or NULL if no item is available
 */
static CQ_ITEM *cq_pop(CQ *cq) {
    CQ_ITEM *item;

    pthread_mutex_lock(&cq->lock);
    item = STAILQ_FIRST(&cq->head);
    if (item != NULL) {
        STAILQ_REMOVE_HEAD(&cq->head, i_next);
    }
    pthread_mutex_unlock(&cq->lock);

    return item;
}

/*
 * Adds an item to a connection queue.
 */
static void cq_push(CQ *cq, CQ_ITEM *item) {
    pthread_mutex_lock(&cq->lock);
    STAILQ_INSERT_TAIL(&cq->head, item, i_next);
    pthread_mutex_unlock(&cq->lock);
}

/*
 * Returns a fresh connection queue item.
 */
static CQ_ITEM *cqi_new(CQ *cq) {
    CQ_ITEM *item = cache_alloc(cq->cache);
    if (item == NULL) {
        STATS_LOCK();
        stats.malloc_fails++;
        STATS_UNLOCK();
    }
    return item;
}

/*
 * Frees a connection queue item (adds it to the freelist.)
 */
static void cqi_free(CQ *cq, CQ_ITEM *item) {
    cache_free(cq->cache, item);
}

// TODO: Skip notify if queue wasn't empty?
// - Requires cq_push() returning a "was empty" flag
// - Requires event handling loop to pop the entire queue and work from that
// instead of the ev_count work there now.
// In testing this does result in a large performance uptick, but unclear how
// much that will transfer from a synthetic benchmark.
static void notify_worker(LIBEVENT_THREAD *t, CQ_ITEM *item) {
    cq_push(t->ev_queue, item);
#ifdef HAVE_EVENTFD
    uint64_t u = 1;
    if (write(t->notify_event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
        perror("failed writing to worker eventfd");
        /* TODO: This is a fatal problem. Can it ever happen temporarily? */
    }
#else
    char buf[1] = "c";
    if (write(t->notify_send_fd, buf, 1) != 1) {
        perror("Failed writing to notify pipe");
        /* TODO: This is a fatal problem. Can it ever happen temporarily? */
    }
#endif
}

// NOTE: An external func that takes a conn *c might be cleaner overall.
static void notify_worker_fd(LIBEVENT_THREAD *t, int sfd, enum conn_queue_item_modes mode) {
    CQ_ITEM *item;
    while ( (item = cqi_new(t->ev_queue)) == NULL ) {
        // NOTE: most callers of this function cannot fail, but mallocs in
        // theory can fail. Small mallocs essentially never do without also
        // killing the process. Syscalls can also fail but the original code
        // never handled this either.
        // As a compromise, I'm leaving this note and this loop: This alloc
        // cannot fail, but pre-allocating the data is too much code in an
        // area I want to keep more lean. If this CQ business becomes a more
        // generic queue I'll reconsider.
    }

    item->mode = mode;
    item->sfd = sfd;
    notify_worker(t, item);
}

/*
 * Creates a worker thread.
 */
static void create_worker(void *(*func)(void *), void *arg) {
    pthread_attr_t  attr;
    int             ret;

    pthread_attr_init(&attr);

    if ((ret = pthread_create(&((LIBEVENT_THREAD*)arg)->thread_id, &attr, func, arg)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n",
                strerror(ret));
        exit(1);
    }
}

/*
 * Sets whether or not we accept new connections.
 */
void accept_new_conns(const bool do_accept) {
    pthread_mutex_lock(&conn_lock);
    do_accept_new_conns(do_accept);
    pthread_mutex_unlock(&conn_lock);
}
/****************************** LIBEVENT THREADS *****************************/

/*
 * Set up a thread's information.
 */
static void setup_thread(LIBEVENT_THREAD *me) {
#if defined(LIBEVENT_VERSION_NUMBER) && LIBEVENT_VERSION_NUMBER >= 0x02000101
    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    me->base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);
#else
    me->base = event_init();
#endif

    if (! me->base) {
        fprintf(stderr, "Can't allocate event base\n");
        exit(1);
    }

    /* Listen for notifications from other threads */
#ifdef HAVE_EVENTFD
    event_set(&me->notify_event, me->notify_event_fd,
              EV_READ | EV_PERSIST, thread_libevent_process, me);
#else
    event_set(&me->notify_event, me->notify_receive_fd,
              EV_READ | EV_PERSIST, thread_libevent_process, me);
#endif
    event_base_set(me->base, &me->notify_event);

    if (event_add(&me->notify_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }

    me->ev_queue = malloc(sizeof(struct conn_queue));
    if (me->ev_queue == NULL) {
        perror("Failed to allocate memory for connection queue");
        exit(EXIT_FAILURE);
    }
    cq_init(me->ev_queue);

    if (pthread_mutex_init(&me->stats.mutex, NULL) != 0) {
        perror("Failed to initialize mutex");
        exit(EXIT_FAILURE);
    }

    me->rbuf_cache = cache_create("rbuf", READ_BUFFER_SIZE, sizeof(char *));
    if (me->rbuf_cache == NULL) {
        fprintf(stderr, "Failed to create read buffer cache\n");
        exit(EXIT_FAILURE);
    }
    // Note: we were cleanly passing in num_threads before, but this now
    // relies on settings globals too much.
    if (settings.read_buf_mem_limit) {
        int limit = settings.read_buf_mem_limit / settings.num_threads;
        if (limit < READ_BUFFER_SIZE) {
            limit = 1;
        } else {
            limit = limit / READ_BUFFER_SIZE;
        }
        cache_set_limit(me->rbuf_cache, limit);
    }

    me->io_cache = cache_create("io", sizeof(io_pending_t), sizeof(char*));
    if (me->io_cache == NULL) {
        fprintf(stderr, "Failed to create IO object cache\n");
        exit(EXIT_FAILURE);
    }
#ifdef TLS
    if (settings.ssl_enabled) {
        me->ssl_wbuf = (char *)malloc((size_t)settings.ssl_wbuf_size);
        if (me->ssl_wbuf == NULL) {
            fprintf(stderr, "Failed to allocate the SSL write buffer\n");
            exit(EXIT_FAILURE);
        }
    }
#endif
#ifdef EXTSTORE
    // me->storage is set just before this function is called.
    if (me->storage) {
        thread_io_queue_add(me, IO_QUEUE_EXTSTORE, me->storage,
            storage_submit_cb, storage_complete_cb, NULL, storage_finalize_cb);
    }
#endif
#ifdef PROXY
    thread_io_queue_add(me, IO_QUEUE_PROXY, settings.proxy_ctx, proxy_submit_cb,
            proxy_complete_cb, proxy_return_cb, proxy_finalize_cb);

    // TODO: maybe register hooks to be called here from sub-packages? ie;
    // extstore, TLS, proxy.
    if (settings.proxy_enabled) {
        proxy_thread_init(me);
    }
#endif
    thread_io_queue_add(me, IO_QUEUE_NONE, NULL, NULL, NULL, NULL, NULL);
}

/*
 * Worker thread: main event loop
 */
static void *worker_libevent(void *arg) {
    LIBEVENT_THREAD *me = arg;

    /* Any per-thread setup can happen here; memcached_thread_init() will block until
     * all threads have finished initializing.
     */
    me->l = logger_create();
    me->lru_bump_buf = item_lru_bump_buf_create();
    if (me->l == NULL || me->lru_bump_buf == NULL) {
        abort();
    }

    if (settings.drop_privileges) {
        drop_worker_privileges();
    }

    register_thread_initialized();

    event_base_loop(me->base, 0);

    // same mechanism used to watch for all threads exiting.
    register_thread_initialized();

    event_base_free(me->base);
    return NULL;
}


/*
 * Processes an incoming "connection event" item. This is called when
 * input arrives on the libevent wakeup pipe.
 */
// Syscalls can be expensive enough that handling a few of them once here can
// save both throughput and overall latency.
#define MAX_PIPE_EVENTS 32
static void thread_libevent_process(evutil_socket_t fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    CQ_ITEM *item;
    conn *c;
    uint64_t ev_count = 0; // max number of events to loop through this run.
#ifdef HAVE_EVENTFD
    // NOTE: unlike pipe we aren't limiting the number of events per read.
    // However we do limit the number of queue pulls to what the count was at
    // the time of this function firing.
    if (read(fd, &ev_count, sizeof(uint64_t)) != sizeof(uint64_t)) {
        if (settings.verbose > 0)
            fprintf(stderr, "Can't read from libevent pipe\n");
        return;
    }
#else
    char buf[MAX_PIPE_EVENTS];

    ev_count = read(fd, buf, MAX_PIPE_EVENTS);
    if (ev_count == 0) {
        if (settings.verbose > 0)
            fprintf(stderr, "Can't read from libevent pipe\n");
        return;
    }
#endif

    for (int x = 0; x < ev_count; x++) {
        item = cq_pop(me->ev_queue);
        if (item == NULL) {
            return;
        }

        switch (item->mode) {
            case queue_new_conn:
                c = conn_new(item->sfd, item->init_state, item->event_flags,
                                   item->read_buffer_size, item->transport,
                                   me->base, item->ssl, item->conntag, item->bproto);
                if (c == NULL) {
                    if (IS_UDP(item->transport)) {
                        fprintf(stderr, "Can't listen for events on UDP socket\n");
                        exit(1);
                    } else {
                        if (settings.verbose > 0) {
                            fprintf(stderr, "Can't listen for events on fd %d\n",
                                item->sfd);
                        }
#ifdef TLS
                        if (item->ssl) {
                            SSL_shutdown(item->ssl);
                            SSL_free(item->ssl);
                        }
#endif
                        close(item->sfd);
                    }
                } else {
                    c->thread = me;
                    conn_io_queue_setup(c);
#ifdef TLS
                    if (settings.ssl_enabled && c->ssl != NULL) {
                        assert(c->thread && c->thread->ssl_wbuf);
                        c->ssl_wbuf = c->thread->ssl_wbuf;
                    }
#endif
                }
                break;
            case queue_pause:
                /* we were told to pause and report in */
                register_thread_initialized();
                break;
            case queue_timeout:
                /* a client socket timed out */
                conn_close_idle(conns[item->sfd]);
                break;
            case queue_redispatch:
                /* a side thread redispatched a client connection */
                conn_worker_readd(conns[item->sfd]);
                break;
            case queue_stop:
                /* asked to stop */
                event_base_loopexit(me->base, NULL);
                break;
            case queue_return_io:
                /* getting an individual IO object back */
                conn_io_queue_return(item->io);
                break;
#ifdef PROXY
            case queue_proxy_reload:
                proxy_worker_reload(settings.proxy_ctx, me);
                break;
#endif
        }

        cqi_free(me->ev_queue, item);
    }
}

// NOTE: need better encapsulation.
// used by the proxy module to iterate the worker threads.
LIBEVENT_THREAD *get_worker_thread(int id) {
    return &threads[id];
}

/* Which thread we assigned a connection to most recently. */
static int last_thread = -1;

/* Last thread we assigned to a connection based on napi_id */
static int last_thread_by_napi_id = -1;

static LIBEVENT_THREAD *select_thread_round_robin(void)
{
    int tid = (last_thread + 1) % settings.num_threads;

    last_thread = tid;

    return threads + tid;
}

static void reset_threads_napi_id(void)
{
    LIBEVENT_THREAD *thread;
    int i;

    for (i = 0; i < settings.num_threads; i++) {
         thread = threads + i;
         thread->napi_id = 0;
    }

    last_thread_by_napi_id = -1;
}

/* Select a worker thread based on the NAPI ID of an incoming connection
 * request. NAPI ID is a globally unique ID that identifies a NIC RX queue
 * on which a flow is received.
 */
static LIBEVENT_THREAD *select_thread_by_napi_id(int sfd)
{
    LIBEVENT_THREAD *thread;
    int napi_id, err, i;
    socklen_t len;
    int tid = -1;

    len = sizeof(socklen_t);
    err = getsockopt(sfd, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &len);
    if ((err == -1) || (napi_id == 0)) {
        STATS_LOCK();
        stats.round_robin_fallback++;
        STATS_UNLOCK();
        return select_thread_round_robin();
    }

select:
    for (i = 0; i < settings.num_threads; i++) {
         thread = threads + i;
         if (last_thread_by_napi_id < i) {
             thread->napi_id = napi_id;
             last_thread_by_napi_id = i;
             tid = i;
             break;
         }
         if (thread->napi_id == napi_id) {
             tid = i;
             break;
         }
    }

    if (tid == -1) {
        STATS_LOCK();
        stats.unexpected_napi_ids++;
        STATS_UNLOCK();
        reset_threads_napi_id();
        goto select;
    }

    return threads + tid;
}

/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
                       int read_buffer_size, enum network_transport transport, void *ssl,
                       uint64_t conntag, enum protocol bproto) {
    CQ_ITEM *item = NULL;
    LIBEVENT_THREAD *thread;

    if (!settings.num_napi_ids)
        thread = select_thread_round_robin();
    else
        thread = select_thread_by_napi_id(sfd);

    item = cqi_new(thread->ev_queue);
    if (item == NULL) {
        close(sfd);
        /* given that malloc failed this may also fail, but let's try */
        fprintf(stderr, "Failed to allocate memory for connection object\n");
        return;
    }

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;
    item->mode = queue_new_conn;
    item->ssl = ssl;
    item->conntag = conntag;
    item->bproto = bproto;

    MEMCACHED_CONN_DISPATCH(sfd, (int64_t)thread->thread_id);
    notify_worker(thread, item);
}

/*
 * Re-dispatches a connection back to the original thread. Can be called from
 * any side thread borrowing a connection.
 */
void redispatch_conn(conn *c) {
    notify_worker_fd(c->thread, c->sfd, queue_redispatch);
}

void timeout_conn(conn *c) {
    notify_worker_fd(c->thread, c->sfd, queue_timeout);
}
#ifdef PROXY
void proxy_reload_notify(LIBEVENT_THREAD *t) {
    notify_worker_fd(t, 0, queue_proxy_reload);
}
#endif

void return_io_pending(io_pending_t *io) {
    CQ_ITEM *item = cqi_new(io->thread->ev_queue);
    if (item == NULL) {
        // TODO: how can we avoid this?
        // In the main case I just loop, since a malloc failure here for a
        // tiny object that's generally in a fixed size queue is going to
        // implode shortly.
        return;
    }

    item->mode = queue_return_io;
    item->io = io;

    notify_worker(io->thread, item);
}

/* This misses the allow_new_conns flag :( */
void sidethread_conn_close(conn *c) {
    if (settings.verbose > 1)
        fprintf(stderr, "<%d connection closing from side thread.\n", c->sfd);

    c->state = conn_closing;
    // redispatch will see closing flag and properly close connection.
    redispatch_conn(c);
    return;
}

/********************************* ITEM ACCESS *******************************/

/*
 * Allocates a new item.
 */
item *item_alloc(char *key, size_t nkey, int flags, rel_time_t exptime, int nbytes) {
    item *it;
    /* do_item_alloc handles its own locks */
    it = do_item_alloc(key, nkey, flags, exptime, nbytes);
    return it;
}

/*
 * Returns an item if it hasn't been marked as expired,
 * lazy-expiring as needed.
 */
item *item_get(const char *key, const size_t nkey, conn *c, const bool do_update) {
    item *it;
    uint32_t hv;
    hv = hash(key, nkey);
    item_lock(hv);
    it = do_item_get(key, nkey, hv, c, do_update);
    item_unlock(hv);
    return it;
}

// returns an item with the item lock held.
// lock will still be held even if return is NULL, allowing caller to replace
// an item atomically if desired.
item *item_get_locked(const char *key, const size_t nkey, conn *c, const bool do_update, uint32_t *hv) {
    item *it;
    *hv = hash(key, nkey);
    item_lock(*hv);
    it = do_item_get(key, nkey, *hv, c, do_update);
    return it;
}

item *item_touch(const char *key, size_t nkey, uint32_t exptime, conn *c) {
    item *it;
    uint32_t hv;
    hv = hash(key, nkey);
    item_lock(hv);
    it = do_item_touch(key, nkey, exptime, hv, c);
    item_unlock(hv);
    return it;
}

/*
 * Links an item into the LRU and hashtable.
 */
int item_link(item *item) {
    int ret;
    uint32_t hv;

    hv = hash(ITEM_key(item), item->nkey);
    item_lock(hv);
    ret = do_item_link(item, hv);
    item_unlock(hv);
    return ret;
}

/*
 * Decrements the reference count on an item and adds it to the freelist if
 * needed.
 */
void item_remove(item *item) {
    uint32_t hv;
    hv = hash(ITEM_key(item), item->nkey);

    item_lock(hv);
    do_item_remove(item);
    item_unlock(hv);
}

/*
 * Replaces one item with another in the hashtable.
 * Unprotected by a mutex lock since the core server does not require
 * it to be thread-safe.
 */
int item_replace(item *old_it, item *new_it, const uint32_t hv) {
    return do_item_replace(old_it, new_it, hv);
}

/*
 * Unlinks an item from the LRU and hashtable.
 */
void item_unlink(item *item) {
    uint32_t hv;
    hv = hash(ITEM_key(item), item->nkey);
    item_lock(hv);
    do_item_unlink(item, hv);
    item_unlock(hv);
}

/*
 * Does arithmetic on a numeric item value.
 */
enum delta_result_type add_delta(conn *c, const char *key,
                                 const size_t nkey, bool incr,
                                 const int64_t delta, char *buf,
                                 uint64_t *cas) {
    enum delta_result_type ret;
    uint32_t hv;

    hv = hash(key, nkey);
    item_lock(hv);
    ret = do_add_delta(c, key, nkey, incr, delta, buf, cas, hv, NULL);
    item_unlock(hv);
    return ret;
}

/*
 * Stores an item in the cache (high level, obeys set/add/replace semantics)
 */
enum store_item_type store_item(item *item, int comm, conn* c) {
    enum store_item_type ret;
    uint32_t hv;

    hv = hash(ITEM_key(item), item->nkey);
    item_lock(hv);
    ret = do_store_item(item, comm, c, hv);
    item_unlock(hv);
    return ret;
}

/******************************* GLOBAL STATS ******************************/

void STATS_LOCK() {
    pthread_mutex_lock(&stats_lock);
}

void STATS_UNLOCK() {
    pthread_mutex_unlock(&stats_lock);
}

void threadlocal_stats_reset(void) {
    int ii;
    for (ii = 0; ii < settings.num_threads; ++ii) {
        pthread_mutex_lock(&threads[ii].stats.mutex);
#define X(name) threads[ii].stats.name = 0;
        THREAD_STATS_FIELDS
#ifdef EXTSTORE
        EXTSTORE_THREAD_STATS_FIELDS
#endif
#ifdef PROXY
        PROXY_THREAD_STATS_FIELDS
#endif
#undef X

        memset(&threads[ii].stats.slab_stats, 0,
                sizeof(threads[ii].stats.slab_stats));
        memset(&threads[ii].stats.lru_hits, 0,
                sizeof(uint64_t) * POWER_LARGEST);

        pthread_mutex_unlock(&threads[ii].stats.mutex);
    }
}

void threadlocal_stats_aggregate(struct thread_stats *stats) {
    int ii, sid;

    /* The struct has a mutex, but we can safely set the whole thing
     * to zero since it is unused when aggregating. */
    memset(stats, 0, sizeof(*stats));

    for (ii = 0; ii < settings.num_threads; ++ii) {
        pthread_mutex_lock(&threads[ii].stats.mutex);
#define X(name) stats->name += threads[ii].stats.name;
        THREAD_STATS_FIELDS
#ifdef EXTSTORE
        EXTSTORE_THREAD_STATS_FIELDS
#endif
#ifdef PROXY
        PROXY_THREAD_STATS_FIELDS
#endif
#undef X

        for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
#define X(name) stats->slab_stats[sid].name += \
            threads[ii].stats.slab_stats[sid].name;
            SLAB_STATS_FIELDS
#undef X
        }

        for (sid = 0; sid < POWER_LARGEST; sid++) {
            stats->lru_hits[sid] +=
                threads[ii].stats.lru_hits[sid];
            stats->slab_stats[CLEAR_LRU(sid)].get_hits +=
                threads[ii].stats.lru_hits[sid];
        }

        stats->read_buf_count += threads[ii].rbuf_cache->total;
        stats->read_buf_bytes += threads[ii].rbuf_cache->total * READ_BUFFER_SIZE;
        stats->read_buf_bytes_free += threads[ii].rbuf_cache->freecurr * READ_BUFFER_SIZE;
        pthread_mutex_unlock(&threads[ii].stats.mutex);
    }
}

void slab_stats_aggregate(struct thread_stats *stats, struct slab_stats *out) {
    int sid;

    memset(out, 0, sizeof(*out));

    for (sid = 0; sid < MAX_NUMBER_OF_SLAB_CLASSES; sid++) {
#define X(name) out->name += stats->slab_stats[sid].name;
        SLAB_STATS_FIELDS
#undef X
    }
}

/*
 * Initializes the thread subsystem, creating various worker threads.
 *
 * nthreads  Number of worker event handler threads to spawn
 */
void memcached_thread_init(int nthreads, void *arg) {
    int         i;
    int         power;

    for (i = 0; i < POWER_LARGEST; i++) {
        pthread_mutex_init(&lru_locks[i], NULL);
    }
    pthread_mutex_init(&worker_hang_lock, NULL);

    pthread_mutex_init(&init_lock, NULL);
    pthread_cond_init(&init_cond, NULL);

    /* Want a wide lock table, but don't waste memory */
    if (nthreads < 3) {
        power = 10;
    } else if (nthreads < 4) {
        power = 11;
    } else if (nthreads < 5) {
        power = 12;
    } else if (nthreads <= 10) {
        power = 13;
    } else if (nthreads <= 20) {
        power = 14;
    } else {
        /* 32k buckets. just under the hashpower default. */
        power = 15;
    }

    if (power >= hashpower) {
        fprintf(stderr, "Hash table power size (%d) cannot be equal to or less than item lock table (%d)\n", hashpower, power);
        fprintf(stderr, "Item lock table grows with `-t N` (worker threadcount)\n");
        fprintf(stderr, "Hash table grows with `-o hashpower=N` \n");
        exit(1);
    }

    item_lock_count = hashsize(power);
    item_lock_hashpower = power;

    item_locks = calloc(item_lock_count, sizeof(pthread_mutex_t));
    if (! item_locks) {
        perror("Can't allocate item locks");
        exit(1);
    }
    for (i = 0; i < item_lock_count; i++) {
        pthread_mutex_init(&item_locks[i], NULL);
    }

    threads = calloc(nthreads, sizeof(LIBEVENT_THREAD));
    if (! threads) {
        perror("Can't allocate thread descriptors");
        exit(1);
    }

    for (i = 0; i < nthreads; i++) {
#ifdef HAVE_EVENTFD
        threads[i].notify_event_fd = eventfd(0, EFD_NONBLOCK);
        if (threads[i].notify_event_fd == -1) {
            perror("failed creating eventfd for worker thread");
            exit(1);
        }
#else
        int fds[2];
        if (pipe(fds)) {
            perror("Can't create notify pipe");
            exit(1);
        }

        threads[i].notify_receive_fd = fds[0];
        threads[i].notify_send_fd = fds[1];
#endif
#ifdef EXTSTORE
        threads[i].storage = arg;
#endif
        setup_thread(&threads[i]);
        /* Reserve three fds for the libevent base, and two for the pipe */
        stats_state.reserved_fds += 5;
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 0; i < nthreads; i++) {
        create_worker(worker_libevent, &threads[i]);
    }

    /* Wait for all the threads to set themselves up before returning. */
    pthread_mutex_lock(&init_lock);
    wait_for_thread_registration(nthreads);
    pthread_mutex_unlock(&init_lock);
}


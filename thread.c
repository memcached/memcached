/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Thread management for memcached.
 *
 *  $Id$
 */
#include "memcached.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#ifdef USE_THREADS

#include <pthread.h>

#define ITEMS_PER_ALLOC 64

/* An item in the connection queue. */
typedef struct conn_queue_item CQ_ITEM;
struct conn_queue_item {
    int     sfd;
    int     init_state;
    int     event_flags;
    int     read_buffer_size;
    int     is_udp;
    CQ_ITEM *next;
};

/* A connection queue. */
typedef struct conn_queue CQ;
struct conn_queue {
    CQ_ITEM *head;
    CQ_ITEM *tail;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
};

/* Lock for connection freelist */
static pthread_mutex_t conn_lock;

/* Lock for alternative item suffix freelist */
static pthread_mutex_t suffix_lock;

/* Lock for cache operations (item_*, assoc_*) */
static pthread_mutex_t cache_lock;

/* Lock for slab allocator operations */
static pthread_mutex_t slabs_lock;

/* Lock for global stats */
static pthread_mutex_t stats_lock;

/* Free list of CQ_ITEM structs */
static CQ_ITEM *cqi_freelist;
static pthread_mutex_t cqi_freelist_lock;

/*
 * Each libevent instance has a wakeup pipe, which other threads
 * can use to signal that they've put a new connection on its queue.
 */
typedef struct {
    pthread_t thread_id;        /* unique ID of this thread */
    struct event_base *base;    /* libevent handle this thread uses */
    struct event notify_event;  /* listen event for notify pipe */
    int notify_receive_fd;      /* receiving end of notify pipe */
    int notify_send_fd;         /* sending end of notify pipe */
    CQ  new_conn_queue;         /* queue of new connections to handle */
} LIBEVENT_THREAD;

static LIBEVENT_THREAD *threads;

/*
 * Number of threads that have finished setting themselves up.
 */
static int init_count = 0;
static pthread_mutex_t init_lock;
static pthread_cond_t init_cond;


static void thread_libevent_process(int fd, short which, void *arg);

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
 * Waits for work on a connection queue.
 */
static CQ_ITEM *cq_pop(CQ *cq) {
    CQ_ITEM *item;

    pthread_mutex_lock(&cq->lock);
    while (NULL == cq->head)
        pthread_cond_wait(&cq->cond, &cq->lock);
    item = cq->head;
    cq->head = item->next;
    if (NULL == cq->head)
        cq->tail = NULL;
    pthread_mutex_unlock(&cq->lock);

    return item;
}

/*
 * Looks for an item on a connection queue, but doesn't block if there isn't
 * one.
 * Returns the item, or NULL if no item is available
 */
static CQ_ITEM *cq_peek(CQ *cq) {
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
static CQ_ITEM *cqi_new() {
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
static void create_worker(void *(*func)(void *), void *arg) {
    pthread_t       thread;
    pthread_attr_t  attr;
    int             ret;

    pthread_attr_init(&attr);

    if ((ret = pthread_create(&thread, &attr, func, arg)) != 0) {
        fprintf(stderr, "Can't create thread: %s\n",
                strerror(ret));
        exit(1);
    }
}


/*
 * Pulls a conn structure from the freelist, if one is available.
 */
conn *mt_conn_from_freelist() {
    conn *c;

    pthread_mutex_lock(&conn_lock);
    c = do_conn_from_freelist();
    pthread_mutex_unlock(&conn_lock);

    return c;
}


/*
 * Adds a conn structure to the freelist.
 *
 * Returns 0 on success, 1 if the structure couldn't be added.
 */
bool mt_conn_add_to_freelist(conn *c) {
    bool result;

    pthread_mutex_lock(&conn_lock);
    result = do_conn_add_to_freelist(c);
    pthread_mutex_unlock(&conn_lock);

    return result;
}

/*
 * Pulls a suffix buffer from the freelist, if one is available.
 */
char *mt_suffix_from_freelist() {
    char *s;

    pthread_mutex_lock(&suffix_lock);
    s = do_suffix_from_freelist();
    pthread_mutex_unlock(&suffix_lock);

    return s;
}


/*
 * Adds a suffix buffer to the freelist.
 *
 * Returns 0 on success, 1 if the buffer couldn't be added.
 */
bool mt_suffix_add_to_freelist(char *s) {
    bool result;

    pthread_mutex_lock(&suffix_lock);
    result = do_suffix_add_to_freelist(s);
    pthread_mutex_unlock(&suffix_lock);

    return result;
}


/****************************** LIBEVENT THREADS *****************************/

/*
 * Set up a thread's information.
 */
static void setup_thread(LIBEVENT_THREAD *me) {
    if (! me->base) {
        me->base = event_init();
        if (! me->base) {
            fprintf(stderr, "Can't allocate event base\n");
            exit(1);
        }
    }

    /* Listen for notifications from other threads */
    event_set(&me->notify_event, me->notify_receive_fd,
              EV_READ | EV_PERSIST, thread_libevent_process, me);
    event_base_set(me->base, &me->notify_event);

    if (event_add(&me->notify_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }

    cq_init(&me->new_conn_queue);
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

    return (void*) event_base_loop(me->base, 0);
}


/*
 * Processes an incoming "handle a new connection" item. This is called when
 * input arrives on the libevent wakeup pipe.
 */
static void thread_libevent_process(int fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    CQ_ITEM *item;
    char buf[1];

    if (read(fd, buf, 1) != 1)
        if (settings.verbose > 0)
            fprintf(stderr, "Can't read from libevent pipe\n");

    item = cq_peek(&me->new_conn_queue);

    if (NULL != item) {
        conn *c = conn_new(item->sfd, item->init_state, item->event_flags,
                           item->read_buffer_size, item->is_udp, me->base);
        if (c == NULL) {
            if (item->is_udp) {
                fprintf(stderr, "Can't listen for events on UDP socket\n");
                exit(1);
            } else {
                if (settings.verbose > 0) {
                    fprintf(stderr, "Can't listen for events on fd %d\n",
                        item->sfd);
                }
                close(item->sfd);
            }
        }
        cqi_free(item);
    }
}

/* Which thread we assigned a connection to most recently. */
static int last_thread = -1;

/*
 * Dispatches a new connection to another thread. This is only ever called
 * from the main thread, either during initialization (for UDP) or because
 * of an incoming connection.
 */
void dispatch_conn_new(int sfd, int init_state, int event_flags,
                       int read_buffer_size, int is_udp) {
    CQ_ITEM *item = cqi_new();
    int thread = (last_thread + 1) % settings.num_threads;

    last_thread = thread;

    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->is_udp = is_udp;

    cq_push(&threads[thread].new_conn_queue, item);
    if (write(threads[thread].notify_send_fd, "", 1) != 1) {
        perror("Writing to thread notify pipe");
    }
}

/*
 * Returns true if this is the thread that listens for new TCP connections.
 */
int mt_is_listen_thread() {
    return pthread_self() == threads[0].thread_id;
}

/********************************* ITEM ACCESS *******************************/

/*
 * Walks through the list of deletes that have been deferred because the items
 * were locked down at the tmie.
 */
void mt_run_deferred_deletes() {
    pthread_mutex_lock(&cache_lock);
    do_run_deferred_deletes();
    pthread_mutex_unlock(&cache_lock);
}

/*
 * Allocates a new item.
 */
item *mt_item_alloc(char *key, size_t nkey, int flags, rel_time_t exptime, int nbytes) {
    item *it;
    pthread_mutex_lock(&cache_lock);
    it = do_item_alloc(key, nkey, flags, exptime, nbytes);
    pthread_mutex_unlock(&cache_lock);
    return it;
}

/*
 * Returns an item if it hasn't been marked as expired or deleted,
 * lazy-expiring as needed.
 */
item *mt_item_get_notedeleted(const char *key, const size_t nkey, bool *delete_locked) {
    item *it;
    pthread_mutex_lock(&cache_lock);
    it = do_item_get_notedeleted(key, nkey, delete_locked);
    pthread_mutex_unlock(&cache_lock);
    return it;
}

/*
 * Links an item into the LRU and hashtable.
 */
int mt_item_link(item *item) {
    int ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_item_link(item);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/*
 * Decrements the reference count on an item and adds it to the freelist if
 * needed.
 */
void mt_item_remove(item *item) {
    pthread_mutex_lock(&cache_lock);
    do_item_remove(item);
    pthread_mutex_unlock(&cache_lock);
}

/*
 * Replaces one item with another in the hashtable.
 */
int mt_item_replace(item *old, item *new) {
    int ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_item_replace(old, new);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/*
 * Unlinks an item from the LRU and hashtable.
 */
void mt_item_unlink(item *item) {
    pthread_mutex_lock(&cache_lock);
    do_item_unlink(item);
    pthread_mutex_unlock(&cache_lock);
}

/*
 * Moves an item to the back of the LRU queue.
 */
void mt_item_update(item *item) {
    pthread_mutex_lock(&cache_lock);
    do_item_update(item);
    pthread_mutex_unlock(&cache_lock);
}

/*
 * Adds an item to the deferred-delete list so it can be reaped later.
 */
char *mt_defer_delete(item *item, time_t exptime) {
    char *ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_defer_delete(item, exptime);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/*
 * Does arithmetic on a numeric item value.
 */
char *mt_add_delta(item *item, int incr, const int64_t delta, char *buf) {
    char *ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_add_delta(item, incr, delta, buf);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/*
 * Stores an item in the cache (high level, obeys set/add/replace semantics)
 */
int mt_store_item(item *item, int comm) {
    int ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_store_item(item, comm);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/*
 * Flushes expired items after a flush_all call
 */
void mt_item_flush_expired() {
    pthread_mutex_lock(&cache_lock);
    do_item_flush_expired();
    pthread_mutex_unlock(&cache_lock);
}

/*
 * Dumps part of the cache
 */
char *mt_item_cachedump(unsigned int slabs_clsid, unsigned int limit, unsigned int *bytes) {
    char *ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_item_cachedump(slabs_clsid, limit, bytes);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/*
 * Dumps statistics about slab classes
 */
char *mt_item_stats(int *bytes) {
    char *ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_item_stats(bytes);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/*
 * Dumps a list of objects of each size in 32-byte increments
 */
char *mt_item_stats_sizes(int *bytes) {
    char *ret;

    pthread_mutex_lock(&cache_lock);
    ret = do_item_stats_sizes(bytes);
    pthread_mutex_unlock(&cache_lock);
    return ret;
}

/****************************** HASHTABLE MODULE *****************************/

void mt_assoc_move_next_bucket() {
    pthread_mutex_lock(&cache_lock);
    do_assoc_move_next_bucket();
    pthread_mutex_unlock(&cache_lock);
}

/******************************* SLAB ALLOCATOR ******************************/

void *mt_slabs_alloc(size_t size, unsigned int id) {
    void *ret;

    pthread_mutex_lock(&slabs_lock);
    ret = do_slabs_alloc(size, id);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

void mt_slabs_free(void *ptr, size_t size, unsigned int id) {
    pthread_mutex_lock(&slabs_lock);
    do_slabs_free(ptr, size, id);
    pthread_mutex_unlock(&slabs_lock);
}

char *mt_slabs_stats(int *buflen) {
    char *ret;

    pthread_mutex_lock(&slabs_lock);
    ret = do_slabs_stats(buflen);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

#ifdef ALLOW_SLABS_REASSIGN
int mt_slabs_reassign(unsigned char srcid, unsigned char dstid) {
    int ret;

    pthread_mutex_lock(&slabs_lock);
    ret = do_slabs_reassign(srcid, dstid);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}
#endif

/******************************* GLOBAL STATS ******************************/

void mt_stats_lock() {
    pthread_mutex_lock(&stats_lock);
}

void mt_stats_unlock() {
    pthread_mutex_unlock(&stats_lock);
}

/*
 * Initializes the thread subsystem, creating various worker threads.
 *
 * nthreads  Number of event handler threads to spawn
 * main_base Event base for main thread
 */
void thread_init(int nthreads, struct event_base *main_base) {
    int         i;

    pthread_mutex_init(&cache_lock, NULL);
    pthread_mutex_init(&conn_lock, NULL);
    pthread_mutex_init(&slabs_lock, NULL);
    pthread_mutex_init(&stats_lock, NULL);

    pthread_mutex_init(&init_lock, NULL);
    pthread_cond_init(&init_cond, NULL);

    pthread_mutex_init(&cqi_freelist_lock, NULL);
    cqi_freelist = NULL;

    threads = malloc(sizeof(LIBEVENT_THREAD) * nthreads);
    if (! threads) {
        perror("Can't allocate thread descriptors");
        exit(1);
    }

    threads[0].base = main_base;
    threads[0].thread_id = pthread_self();

    for (i = 0; i < nthreads; i++) {
        int fds[2];
        if (pipe(fds)) {
            perror("Can't create notify pipe");
            exit(1);
        }

        threads[i].notify_receive_fd = fds[0];
        threads[i].notify_send_fd = fds[1];

    setup_thread(&threads[i]);
    }

    /* Create threads after we've done all the libevent setup. */
    for (i = 1; i < nthreads; i++) {
        create_worker(worker_libevent, &threads[i]);
    }

    /* Wait for all the threads to set themselves up before returning. */
    pthread_mutex_lock(&init_lock);
    init_count++; /* main thread */
    while (init_count < nthreads) {
        pthread_cond_wait(&init_cond, &init_lock);
    }
    pthread_mutex_unlock(&init_lock);
}

#endif

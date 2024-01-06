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
#ifdef PROXY
    queue_proxy_reload, /* signal proxy to reload worker VM */
#endif
};
typedef struct conn_queue_item CQ_ITEM;
/**
 * 表示连接队列中的一个项目的结构体。
 */
struct conn_queue_item {
    int               sfd;                     // 套接字文件描述符
    enum conn_states  init_state;              // 连接的初始状态
    int               event_flags;             // 表示连接事件的标志位
    int               read_buffer_size;        // 读缓冲区的大小
    enum network_transport transport;           // 网络传输类型
    enum conn_queue_item_modes mode;           // 连接队列项的模式
    conn *c;                                  // 连接对象
    void    *ssl;                             // SSL/TLS 信息（如果适用）
    uint64_t conntag;                         // 连接的唯一标识符
    enum protocol bproto;                     // 用于通信的协议
    io_pending_t *io;                         // 延迟IO处理时使用的IO
    STAILQ_ENTRY(conn_queue_item) i_next;     // 连接队列中的下一个项目
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
static unsigned int item_lock_hashpower;
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
static void thread_libevent_ionotify(evutil_socket_t fd, short which, void *arg);

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
 * 初始化连接队列。
 */
static void cq_init(CQ *cq) {
    // 初始化连接队列的互斥锁
    pthread_mutex_init(&cq->lock, NULL);

    // 初始化连接队列的头部
    STAILQ_INIT(&cq->head);

    // 创建连接队列的缓存
    cq->cache = cache_create("cq", sizeof(CQ_ITEM), sizeof(char *));
    if (cq->cache == NULL) {
        fprintf(stderr, "无法创建连接队列缓存\n");
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
    if (write(t->n.notify_event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
        perror("failed writing to worker eventfd");
        /* TODO: This is a fatal problem. Can it ever happen temporarily? */
    }
#else
    char buf[1] = "c";
    if (write(t->n.notify_send_fd, buf, 1) != 1) {
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
 * 创建工作线程。
 */
static void create_worker(void *(*func)(void *), void *arg) {
    pthread_attr_t  attr;
    int             ret;

    // 初始化线程属性
    pthread_attr_init(&attr);

    // 创建线程并运行指定的函数
    if ((ret = pthread_create(&((LIBEVENT_THREAD*)arg)->thread_id, &attr, func, arg)) != 0) {
        fprintf(stderr, "无法创建线程: %s\n", strerror(ret));
        exit(1);
    }

    // 为线程设置名称
    thread_setname(((LIBEVENT_THREAD*)arg)->thread_id, "mc-worker");
}


/*
 * 设置是否接受新连接。
 * Parameters:
 *   - do_accept: 指示是否接受新连接的布尔值。
 */
void accept_new_conns(const bool do_accept) {
    // 线程安全地锁住连接锁
    pthread_mutex_lock(&conn_lock);

    // 调用实际处理新连接的函数
    do_accept_new_conns(do_accept);

    // 解锁连接锁
    pthread_mutex_unlock(&conn_lock);
}

/****************************** LIBEVENT THREADS *****************************/

/*
 * 设置线程通知机制。
 * Parameters:
 *   - me: 指向当前线程结构体的指针。
 *   - tn: 指向线程通知结构体的指针。
 *   - cb: 线程通知回调函数。
 */
static void setup_thread_notify(LIBEVENT_THREAD *me, struct thread_notify *tn,
        void(*cb)(int, short, void *)) {
    #ifdef HAVE_EVENTFD
        // 使用eventfd进行线程通知
        event_set(&tn->notify_event, tn->notify_event_fd,
                  EV_READ | EV_PERSIST, cb, me);
    #else
        // 在没有eventfd的情况下，使用管道进行线程通知
        event_set(&tn->notify_event, tn->notify_receive_fd,
                  EV_READ | EV_PERSIST, cb, me);
    #endif

    // 将事件与当前线程的事件处理基底关联
    event_base_set(me->base, &tn->notify_event);

    // 将事件添加到事件处理基底中，并设置为持久事件
    if (event_add(&tn->notify_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }
}


/*
 * 设置线程的信息。
 */
static void setup_thread(LIBEVENT_THREAD *me) {
#if defined(LIBEVENT_VERSION_NUMBER) && LIBEVENT_VERSION_NUMBER >= 0x02000101
    // 使用新版本的libevent API设置线程的event base，并禁用基本的锁
    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    me->base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);
#else
    // 使用旧版本的libevent API初始化线程的event base
    me->base = event_init();
#endif

    if (!me->base) {
        fprintf(stderr, "无法分配event base\n");
        exit(1);
    }

    /* 监听来自其他线程的通知 */
    setup_thread_notify(me, &me->n, thread_libevent_process);
    setup_thread_notify(me, &me->ion, thread_libevent_ionotify);
    pthread_mutex_init(&me->ion_lock, NULL);
    STAILQ_INIT(&me->ion_head);

    // 分配连接队列
    me->ev_queue = malloc(sizeof(struct conn_queue));
    if (me->ev_queue == NULL) {
        perror("无法为连接队列分配内存");
        exit(EXIT_FAILURE);
    }
    cq_init(me->ev_queue);

    // 初始化统计信息的互斥锁
    if (pthread_mutex_init(&me->stats.mutex, NULL) != 0) {
        perror("无法初始化互斥锁");
        exit(EXIT_FAILURE);
    }

    // 创建读缓冲区的缓存
    me->rbuf_cache = cache_create("rbuf", READ_BUFFER_SIZE, sizeof(char *));
    if (me->rbuf_cache == NULL) {
        fprintf(stderr, "无法创建读缓冲区缓存\n");
        exit(EXIT_FAILURE);
    }
    // 注意: 以前是干净地传递num_threads的，但现在太过依赖settings全局变量。
    if (settings.read_buf_mem_limit) {
        int limit = settings.read_buf_mem_limit / settings.num_threads;
        if (limit < READ_BUFFER_SIZE) {
            limit = 1;
        } else {
            limit = limit / READ_BUFFER_SIZE;
        }
        cache_set_limit(me->rbuf_cache, limit);
    }

    // 创建IO对象的缓存
    me->io_cache = cache_create("io", sizeof(io_pending_t), sizeof(char *));
    if (me->io_cache == NULL) {
        fprintf(stderr, "无法创建IO对象缓存\n");
        exit(EXIT_FAILURE);
    }
#ifdef TLS
    // 如果启用SSL，则分配SSL写缓冲区
    if (settings.ssl_enabled) {
        me->ssl_wbuf = (char *)malloc((size_t)settings.ssl_wbuf_size);
        if (me->ssl_wbuf == NULL) {
            fprintf(stderr, "无法分配SSL写缓冲区\n");
            exit(EXIT_FAILURE);
        }
    }
#endif
#ifdef EXTSTORE
    // 设置线程的存储引擎
    if (me->storage) {
        thread_io_queue_add(me, IO_QUEUE_EXTSTORE, me->storage, storage_submit_cb);
    }
#endif
#ifdef PROXY
    // 向IO队列添加代理任务
    thread_io_queue_add(me, IO_QUEUE_PROXY, settings.proxy_ctx, proxy_submit_cb);

    // TODO: 或许可以在这里从子包注册需要调用的钩子? 比如; extstore, TLS, proxy.
    if (settings.proxy_enabled) {
        // 初始化代理线程
        proxy_thread_init(settings.proxy_ctx, me);
    }
#endif
    // 向IO队列添加空任务
    thread_io_queue_add(me, IO_QUEUE_NONE, NULL, NULL);
}


/*
 * 工作线程: 主事件循环
 */
static void *worker_libevent(void *arg) {
    LIBEVENT_THREAD *me = arg;

    /* 在这里进行任何线程特定的设置；memcached_thread_init() 将会阻塞直到
     * 所有线程完成初始化。
     */
    me->l = logger_create();
    me->lru_bump_buf = item_lru_bump_buf_create();
    if (me->l == NULL || me->lru_bump_buf == NULL) {
        abort();
    }

    // 如果设置了降低权限选项，则降低工作线程的权限
    if (settings.drop_privileges) {
        drop_worker_privileges();
    }

    // 注册线程初始化完成
    register_thread_initialized();

    // 进入libevent的事件循环
    event_base_loop(me->base, 0);

    // 使用相同的机制检测所有线程是否退出
    register_thread_initialized();

    // 释放libevent的事件基础结构
    event_base_free(me->base);
    return NULL;
}


// Syscalls can be expensive enough that handling a few of them once here can
// save both throughput and overall latency.
#define MAX_PIPE_EVENTS 32

// dedicated worker thread notify system for IO objects.
static void thread_libevent_ionotify(evutil_socket_t fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    uint64_t ev_count = 0;
    iop_head_t head;

    STAILQ_INIT(&head);
#ifdef HAVE_EVENTFD
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

    // pull entire queue and zero the thread head.
    // need to do this after reading a syscall as we are only guaranteed to
    // get syscalls if the queue is empty.
    pthread_mutex_lock(&me->ion_lock);
    STAILQ_CONCAT(&head, &me->ion_head);
    pthread_mutex_unlock(&me->ion_lock);

    while (!STAILQ_EMPTY(&head)) {
        io_pending_t *io = STAILQ_FIRST(&head);
        STAILQ_REMOVE_HEAD(&head, iop_next);
        conn_io_queue_return(io);
    }
}

/*
 * 处理一个传入的“连接事件”项目。当libevent的唤醒管道上有输入时调用。
 */
static void thread_libevent_process(evutil_socket_t fd, short which, void *arg) {
    LIBEVENT_THREAD *me = arg;
    CQ_ITEM *item;
    conn *c;
    uint64_t ev_count = 0; // 本轮最大事件循环次数。
#ifdef HAVE_EVENTFD
    // 注意：与管道不同，我们没有限制每次读取的事件数量。
    // 但我们确实限制了队列拉取的次数，即在此函数触发时的计数。
    if (read(fd, &ev_count, sizeof(uint64_t)) != sizeof(uint64_t)) {
        if (settings.verbose > 0)
            fprintf(stderr, "无法从libevent管道中读取\n");
        return;
    }
#else
    char buf[MAX_PIPE_EVENTS];

    ev_count = read(fd, buf, MAX_PIPE_EVENTS);
    if (ev_count == 0) {
        if (settings.verbose > 0)
            fprintf(stderr, "无法从libevent管道中读取\n");
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
                        fprintf(stderr, "无法监听UDP套接字上的事件\n");
                        exit(1);
                    } else {
                        if (settings.verbose > 0) {
                            fprintf(stderr, "无法监听fd %d 上的事件\n",
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
                /* 被告知暂停并报告 */
                register_thread_initialized();
                break;
            case queue_timeout:
                /* 客户端套接字超时 */
                conn_close_idle(conns[item->sfd]);
                break;
            case queue_redispatch:
                /* 侧线程重新分发客户端连接 */
                conn_worker_readd(conns[item->sfd]);
                break;
            case queue_stop:
                /* 被要求停止 */
                event_base_loopexit(me->base, NULL);
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


// Interface is slightly different on various platforms.
// On linux, at least, the len limit is 16 bytes.
#define THR_NAME_MAXLEN 16
void thread_setname(pthread_t thread, const char *name) {
assert(strlen(name) < THR_NAME_MAXLEN);
#if defined(__linux__)
pthread_setname_np(thread, name);
#endif
}
#undef THR_NAME_MAXLEN

// NOTE: need better encapsulation.
// used by the proxy module to iterate the worker threads.
LIBEVENT_THREAD *get_worker_thread(int id) {
    return &threads[id];
}

/* Which thread we assigned a connection to most recently. */
static int last_thread = -1;

/* Last thread we assigned to a connection based on napi_id */
static int last_thread_by_napi_id = -1;

/**
 * 以轮询方式选择下一个事件处理线程
 * 
 * @return 返回选中的事件处理线程对象
 */
static LIBEVENT_THREAD *select_thread_round_robin(void)
{
    int tid = (last_thread + 1) % settings.num_threads;

    last_thread = tid;

    return threads + tid;
}

/**
 * 重置所有事件处理线程的NAPI ID
 */
static void reset_threads_napi_id(void)
{
    LIBEVENT_THREAD *thread;
    int i;

    // 遍历所有事件处理线程，将其NAPI ID重置为0
    for (i = 0; i < settings.num_threads; i++) {
         thread = threads + i;
         thread->napi_id = 0;
    }

    last_thread_by_napi_id = -1;  // 重置最后一个NAPI ID的记录
}


/**
 * 根据连接请求的NAPI ID选择一个工作线程
 * NAPI ID是一个全局唯一的标识符，用于标识一个NIC RX队列
 * 在该队列上接收到的流。
 * 
 * @param sfd 套接字文件描述符
 * @return 返回选中的工作线程对象
 */
static LIBEVENT_THREAD *select_thread_by_napi_id(int sfd)
{
    LIBEVENT_THREAD *thread;
    int napi_id, err, i;
    socklen_t len;
    int tid = -1;

    len = sizeof(socklen_t);
    err = getsockopt(sfd, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id, &len);

    // 获取NAPI ID失败或者NAPI ID为0，则使用轮询方式选择线程
    if ((err == -1) || (napi_id == 0)) {
        STATS_LOCK();
        stats.round_robin_fallback++;
        STATS_UNLOCK();
        return select_thread_round_robin();
    }

select:
    // 遍历所有线程，根据NAPI ID选择一个线程
    for (i = 0; i < settings.num_threads; i++) {
         thread = threads + i;

         // 如果线程的NAPI ID之前未被记录，或者是第一个具有该NAPI ID的线程
         if (last_thread_by_napi_id < i) {
             thread->napi_id = napi_id;
             last_thread_by_napi_id = i;
             tid = i;
             break;
         }

         // 如果线程的NAPI ID与给定NAPI ID相同，则选择该线程
         if (thread->napi_id == napi_id) {
             tid = i;
             break;
         }
    }

    // 如果未找到匹配的线程，记录异常的NAPI ID数量，重置所有线程的NAPI ID，重新选择
    if (tid == -1) {
        STATS_LOCK();
        stats.unexpected_napi_ids++;
        STATS_UNLOCK();
        reset_threads_napi_id();
        goto select;
    }

    return threads + tid;  // 返回选中的工作线程对象
}


/*
 * 将新连接分派给另一个线程。这只能从主线程调用，要么是在初始化时（用于UDP），要么是因为有新连接到来。
 */
void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags,
                       int read_buffer_size, enum network_transport transport, void *ssl,
                       uint64_t conntag, enum protocol bproto) {
    // 申明一个连接队列项指针
    CQ_ITEM *item = NULL;

    // 获取目标线程
    LIBEVENT_THREAD *thread;

    // 根据是否启用 NAPI，选择线程的分配方式
    if (!settings.num_napi_ids)
        thread = select_thread_round_robin();
    else
        thread = select_thread_by_napi_id(sfd);

    // 分配一个连接队列项
    item = cqi_new(thread->ev_queue);
    if (item == NULL) {
        // 如果分配失败，关闭连接并输出错误信息
        close(sfd);
        fprintf(stderr, "Failed to allocate memory for connection object\n");
        return;
    }

    // 设置连接队列项的各项属性
    item->sfd = sfd;
    item->init_state = init_state;
    item->event_flags = event_flags;
    item->read_buffer_size = read_buffer_size;
    item->transport = transport;
    item->mode = queue_new_conn;
    item->ssl = ssl;
    item->conntag = conntag;
    item->bproto = bproto;

    // 记录连接调度的信息，包括连接描述符和目标线程的线程ID
    MEMCACHED_CONN_DISPATCH(sfd, (int64_t)thread->thread_id);

    // 通知目标线程处理新连接
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
    bool do_notify = false;
    LIBEVENT_THREAD *t = io->thread;
    pthread_mutex_lock(&t->ion_lock);
    if (STAILQ_EMPTY(&t->ion_head)) {
        do_notify = true;
    }
    STAILQ_INSERT_TAIL(&t->ion_head, io, iop_next);
    pthread_mutex_unlock(&t->ion_lock);

    // skip the syscall if there was already data in the queue, as it's
    // already been notified.
    if (do_notify) {
#ifdef HAVE_EVENTFD
        uint64_t u = 1;
        if (write(t->ion.notify_event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
            perror("failed writing to worker eventfd");
            /* TODO: This is a fatal problem. Can it ever happen temporarily? */
        }
#else
        char buf[1] = "c";
        if (write(t->ion.notify_send_fd, buf, 1) != 1) {
            perror("Failed writing to notify pipe");
            /* TODO: This is a fatal problem. Can it ever happen temporarily? */
        }
#endif
    }
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
item *item_alloc(const char *key, size_t nkey, client_flags_t flags, rel_time_t exptime, int nbytes) {
    item *it;
    /* do_item_alloc handles its own locks */
    it = do_item_alloc(key, nkey, flags, exptime, nbytes);
    return it;
}

/*
 * Returns an item if it hasn't been marked as expired,
 * lazy-expiring as needed.
 */
item *item_get(const char *key, const size_t nkey, LIBEVENT_THREAD *t, const bool do_update) {
    item *it;
    uint32_t hv;
    hv = hash(key, nkey);
    item_lock(hv);
    it = do_item_get(key, nkey, hv, t, do_update);
    item_unlock(hv);
    return it;
}

// returns an item with the item lock held.
// lock will still be held even if return is NULL, allowing caller to replace
// an item atomically if desired.
item *item_get_locked(const char *key, const size_t nkey, LIBEVENT_THREAD *t, const bool do_update, uint32_t *hv) {
    item *it;
    *hv = hash(key, nkey);
    item_lock(*hv);
    it = do_item_get(key, nkey, *hv, t, do_update);
    return it;
}

item *item_touch(const char *key, size_t nkey, uint32_t exptime, LIBEVENT_THREAD *t) {
    item *it;
    uint32_t hv;
    hv = hash(key, nkey);
    item_lock(hv);
    it = do_item_touch(key, nkey, exptime, hv, t);
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
enum delta_result_type add_delta(LIBEVENT_THREAD *t, const char *key,
                                 const size_t nkey, bool incr,
                                 const int64_t delta, char *buf,
                                 uint64_t *cas) {
    enum delta_result_type ret;
    uint32_t hv;

    hv = hash(key, nkey);
    item_lock(hv);
    ret = do_add_delta(t, key, nkey, incr, delta, buf, cas, hv, NULL);
    item_unlock(hv);
    return ret;
}

/*
 * Stores an item in the cache (high level, obeys set/add/replace semantics)
 */
enum store_item_type store_item(item *item, int comm, LIBEVENT_THREAD *t, int *nbytes, uint64_t *cas, bool cas_stale) {
    enum store_item_type ret;
    uint32_t hv;

    hv = hash(ITEM_key(item), item->nkey);
    item_lock(hv);
    ret = do_store_item(item, comm, t, hv, nbytes, cas, cas_stale);
    item_unlock(hv);
    return ret;
}

/******************************* GLOBAL STATS ******************************/

void STATS_LOCK(void) {
    pthread_mutex_lock(&stats_lock);
}

void STATS_UNLOCK(void) {
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
 * 初始化线程通知结构体。
 */
static void memcached_thread_notify_init(struct thread_notify *tn) {
#ifdef HAVE_EVENTFD
        // 使用eventfd创建通知事件描述符
        tn->notify_event_fd = eventfd(0, EFD_NONBLOCK);
        if (tn->notify_event_fd == -1) {
            perror("创建工作线程的eventfd失败");
            exit(1);
        }
#else
        // 使用pipe创建通知事件描述符
        int fds[2];
        if (pipe(fds)) {
            perror("无法创建通知管道");
            exit(1);
        }

        tn->notify_receive_fd = fds[0];
        tn->notify_send_fd = fds[1];
#endif
}

/*
 * 初始化线程子系统，创建各个工作线程。
 *
 * nthreads  要生成的工作事件处理线程数
 */
void memcached_thread_init(int nthreads, void *arg) {
    int         i;
    int         power;

    // 初始化LRU锁
    for (i = 0; i < POWER_LARGEST; i++) {
        pthread_mutex_init(&lru_locks[i], NULL);
    }
    pthread_mutex_init(&worker_hang_lock, NULL);

    pthread_mutex_init(&init_lock, NULL);
    pthread_cond_init(&init_cond, NULL);

    /* 设置一个宽敞的锁表，但不浪费内存 */
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
        /* 32k buckets. 刚好略小于散列幂的默认值。 */
        power = 15;
    }

    // 确保散列表的大小大于等于项目锁表的大小
    if (power >= hashpower) {
        fprintf(stderr, "Hash表幂大小 (%d) 不能等于或小于项目锁表 (%d)\n", hashpower, power);
        fprintf(stderr, "项目锁表随 `-t N` (工作线程数量) 增长\n");
        fprintf(stderr, "Hash表随 `-o hashpower=N` 增长\n");
        exit(1);
    }

    // 设置项目锁表的大小和散列幂
    item_lock_count = hashsize(power);
    item_lock_hashpower = power;

    // 分配项目锁
    item_locks = calloc(item_lock_count, sizeof(pthread_mutex_t));
    if (!item_locks) {
        perror("无法分配项目锁");
        exit(1);
    }
    for (i = 0; i < item_lock_count; i++) {
        pthread_mutex_init(&item_locks[i], NULL);
    }

    // 分配线程描述符
    threads = calloc(nthreads, sizeof(LIBEVENT_THREAD));
    if (!threads) {
        perror("无法分配线程描述符");
        exit(1);
    }

    // 初始化每个线程的相关属性
    for (i = 0; i < nthreads; i++) {
        memcached_thread_notify_init(&threads[i].n);
        memcached_thread_notify_init(&threads[i].ion);
#ifdef EXTSTORE
        threads[i].storage = arg;
#endif
        threads[i].thread_baseid = i;
        setup_thread(&threads[i]);
        /* 为libevent基础保留三个fd，为管道保留两个fd */
        stats_state.reserved_fds += 5;
    }

    // 在进行libevent设置后创建线程
    for (i = 0; i < nthreads; i++) {
        create_worker(worker_libevent, &threads[i]);
    }

    // 在返回前等待所有线程完成注册
    pthread_mutex_lock(&init_lock);
    wait_for_thread_registration(nthreads);
    pthread_mutex_unlock(&init_lock);
}



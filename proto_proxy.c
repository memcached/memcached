/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Functions for handling the proxy layer. wraps text protocols
 *
 * NOTE: many lua functions generate pointers via "lua_newuserdatauv" or
 * similar. Normal memory checking isn't done as lua will throw a high level
 * error if malloc fails. Must keep this in mind while allocating data so any
 * manually malloc'ed information gets freed properly.
 */

#include "memcached.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "config.h"

#if defined(__linux__)
#define USE_EVENTFD 1
#include <sys/eventfd.h>
#endif

#ifdef HAVE_LIBURING
#include <liburing.h>
#include <poll.h> // POLLOUT for liburing.
#define PRING_QUEUE_SQ_ENTRIES 2048
#define PRING_QUEUE_CQ_ENTRIES 16384
#endif

#include "proto_proxy.h"
#include "proto_text.h"
#include "queue.h"
#define XXH_INLINE_ALL // modifier for xxh3's include below
#include "xxhash.h"

#ifdef PROXY_DEBUG
#define P_DEBUG(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)
#else
#define P_DEBUG(...)
#endif

#define WSTAT_L(t) pthread_mutex_lock(&t->stats.mutex);
#define WSTAT_UL(t) pthread_mutex_unlock(&t->stats.mutex);
#define WSTAT_INCR(c, stat, amount) { \
    pthread_mutex_lock(&c->thread->stats.mutex); \
    c->thread->stats.stat += amount; \
    pthread_mutex_unlock(&c->thread->stats.mutex); \
}
#define STAT_L(ctx) pthread_mutex_lock(&ctx->stats_lock);
#define STAT_UL(ctx) pthread_mutex_unlock(&ctx->stats_lock);
#define STAT_INCR(ctx, stat, amount) { \
        pthread_mutex_lock(&ctx->stats_lock); \
        ctx->global_stats.stat += amount; \
        pthread_mutex_unlock(&ctx->stats_lock); \
}

#define STAT_DECR(ctx, stat, amount) { \
        pthread_mutex_lock(&ctx->stats_lock); \
        ctx->global_stats.stat -= amount; \
        pthread_mutex_unlock(&ctx->stats_lock); \
}

// FIXME (v2): do include dir properly.
#include "vendor/mcmc/mcmc.h"

// Note: value created from thin air. Could be shorter.
#define MCP_REQUEST_MAXLEN KEY_MAX_LENGTH * 2

#define ENDSTR "END\r\n"
#define ENDLEN sizeof(ENDSTR)-1

#define MCP_THREAD_UPVALUE 1
#define MCP_ATTACH_UPVALUE 2
#define MCP_BACKEND_UPVALUE 3

// all possible commands.
#define CMD_FIELDS \
    X(CMD_MG) \
    X(CMD_MS) \
    X(CMD_MD) \
    X(CMD_MN) \
    X(CMD_MA) \
    X(CMD_ME) \
    X(CMD_GET) \
    X(CMD_GAT) \
    X(CMD_SET) \
    X(CMD_ADD) \
    X(CMD_CAS) \
    X(CMD_GETS) \
    X(CMD_GATS) \
    X(CMD_INCR) \
    X(CMD_DECR) \
    X(CMD_TOUCH) \
    X(CMD_APPEND) \
    X(CMD_DELETE) \
    X(CMD_REPLACE) \
    X(CMD_PREPEND) \
    X(CMD_END_STORAGE) \
    X(CMD_QUIT) \
    X(CMD_STATS) \
    X(CMD_SLABS) \
    X(CMD_WATCH) \
    X(CMD_LRU) \
    X(CMD_VERSION) \
    X(CMD_SHUTDOWN) \
    X(CMD_EXTSTORE) \
    X(CMD_FLUSH_ALL) \
    X(CMD_VERBOSITY) \
    X(CMD_LRU_CRAWLER) \
    X(CMD_REFRESH_CERTS) \
    X(CMD_CACHE_MEMLIMIT)

#define X(name) name,
enum proxy_defines {
    P_OK = 0,
    CMD_FIELDS
    CMD_SIZE, // used to define array size for command hooks.
    CMD_ANY, // override _all_ commands
    CMD_ANY_STORAGE, // override commands specific to key storage.
};
#undef X

// certain classes of ascii commands have similar parsing (ie;
// get/gets/gat/gats). Use types so we don't have to test a ton of them.
enum proxy_cmd_types {
    CMD_TYPE_GENERIC = 0,
    CMD_TYPE_GET, // get/gets/gat/gats
    CMD_TYPE_UPDATE, // add/set/cas/prepend/append/replace
    CMD_TYPE_META, // m*'s.
};

typedef struct _io_pending_proxy_t io_pending_proxy_t;
typedef struct proxy_event_thread_s proxy_event_thread_t;

#ifdef HAVE_LIBURING
typedef void (*proxy_event_cb)(void *udata, struct io_uring_cqe *cqe);
typedef struct {
    void *udata;
    proxy_event_cb cb;
    bool set; // NOTE: not sure if necessary if code structured properly
} proxy_event_t;

static struct __kernel_timespec updater_ts = {.tv_sec = 3, .tv_nsec = 0};
static void _proxy_evthr_evset_notifier(proxy_event_thread_t *t);
static void _proxy_evthr_evset_clock(proxy_event_thread_t *t);
static void *proxy_event_thread_ur(void *arg);
static void proxy_event_updater_ur(void *udata, struct io_uring_cqe *cqe);
#endif

struct proxy_user_stats {
    size_t num_stats; // number of stats, for sizing various arrays
    char **names; // not needed for worker threads
    uint64_t *counters; // array of counters.
};

struct proxy_global_stats {
    uint64_t config_reloads;
    uint64_t config_reload_fails;
    uint64_t backend_total;
    uint64_t backend_disconn; // backends with no connections
    uint64_t backend_requests; // reqs sent to backends
    uint64_t backend_responses; // responses received from backends
    uint64_t backend_errors; // errors from backends
    uint64_t backend_marked_bad; // backend set to autofail
    uint64_t backend_failed; // an error caused a backend reset
};

struct proxy_tunables {
    struct timeval connect;
    struct timeval retry; // wait time before retrying a dead backend
    struct timeval read;
#ifdef HAVE_LIBURING
    struct __kernel_timespec connect_ur;
    struct __kernel_timespec retry_ur;
    struct __kernel_timespec read_ur;
#endif // HAVE_LIBURING
    int backend_failure_limit;
};

typedef STAILQ_HEAD(pool_head_s, mcp_pool_s) pool_head_t;
typedef struct {
    lua_State *proxy_state;
    void *proxy_code;
    proxy_event_thread_t *proxy_threads;
    pthread_mutex_t config_lock;
    pthread_cond_t config_cond;
    pthread_t config_tid;
    pthread_mutex_t worker_lock;
    pthread_cond_t worker_cond;
    pthread_t manager_tid; // deallocation management thread
    pthread_mutex_t manager_lock;
    pthread_cond_t manager_cond;
    pool_head_t manager_head; // stack for pool deallocation.
    bool worker_done; // signal variable for the worker lock/cond system.
    bool worker_failed; // covered by worker_lock as well.
    bool use_uring; // use IO_URING for backend connections.
    struct proxy_global_stats global_stats;
    struct proxy_user_stats user_stats;
    struct proxy_tunables tunables; // NOTE: updates covered by stats_lock
    pthread_mutex_t stats_lock; // used for rare global counters
} proxy_ctx_t;

struct proxy_hook {
    int lua_ref;
    bool is_lua; // pull the lua reference and call it as a lua function.
};

// TODO (v2): some hash functions (crc?) might require initializers. If we run into
// any the interface might need expanding.
typedef uint64_t (*key_hash_func)(const void *key, size_t len, uint64_t seed);
struct proxy_hash_func {
    key_hash_func func;
};
typedef const char *(*key_hash_filter_func)(const char *conf, const char *key, size_t klen, size_t *newlen);
typedef uint32_t (*hash_selector_func)(uint64_t hash, void *ctx);
struct proxy_hash_caller {
    hash_selector_func selector_func;
    void *ctx;
};

enum mcp_backend_states {
    mcp_backend_read = 0, // waiting to read any response
    mcp_backend_parse, // have some buffered data to check
    mcp_backend_read_end, // looking for an "END" marker for GET
    mcp_backend_want_read, // read more data to complete command
    mcp_backend_next, // advance to the next IO
};

typedef struct mcp_backend_s mcp_backend_t;
typedef struct mcp_request_s mcp_request_t;
typedef struct mcp_parser_s mcp_parser_t;

#define PARSER_MAX_TOKENS 24

struct mcp_parser_meta_s {
    uint64_t flags;
};

// Note that we must use offsets into request for tokens,
// as *request can change between parsing and later accessors.
struct mcp_parser_s {
    const char *request;
    void *vbuf; // temporary buffer for holding value lengths.
    uint8_t command;
    uint8_t cmd_type; // command class.
    uint8_t ntokens;
    uint8_t keytoken; // because GAT. sigh. also cmds without a key.
    uint32_t parsed; // how far into the request we parsed already
    uint32_t reqlen; // full length of request buffer.
    int vlen;
    uint32_t klen; // length of key.
    uint16_t tokens[PARSER_MAX_TOKENS]; // offsets for start of each token
    bool has_space; // a space was found after the last byte parsed.
    union {
        struct mcp_parser_meta_s meta;
    } t;
};

#define MCP_PARSER_KEY(pr) (&pr.request[pr.tokens[pr.keytoken]])

#define MAX_REQ_TOKENS 2
struct mcp_request_s {
    mcp_parser_t pr; // non-lua-specific parser handling.
    struct timeval start; // time this object was created.
    mcp_backend_t *be; // backend handling this request.
    bool ascii_multiget; // ascii multiget mode. (hide errors/END)
    bool was_modified; // need to rewrite the request
    int tokent_ref; // reference to token table if modified.
    char request[];
};

typedef STAILQ_HEAD(io_head_s, _io_pending_proxy_t) io_head_t;
#define MAX_IPLEN 45
#define MAX_PORTLEN 6
// TODO (v2): IOV_MAX tends to be 1000+ which would allow for more batching but we
// don't have a good temporary space and don't want to malloc/free on every
// write. transmit() uses the stack but we can't do that for uring's use case.
#if (IOV_MAX > 128)
#define BE_IOV_MAX 128
#else
#define BE_IOV_MAX IOV_MAX
#endif
struct mcp_backend_s {
    char ip[MAX_IPLEN+1];
    char port[MAX_PORTLEN+1];
    double weight;
    int depth;
    int failed_count; // number of fails (timeouts) in a row
    pthread_mutex_t mutex; // covers stack.
    proxy_event_thread_t *event_thread; // event thread owning this backend.
    void *client; // mcmc client
    STAILQ_ENTRY(mcp_backend_s) be_next; // stack for backends
    io_head_t io_head; // stack of requests.
    char *rbuf; // static allocated read buffer.
    struct event event; // libevent
#ifdef HAVE_LIBURING
    proxy_event_t ur_rd_ev; // liburing.
    proxy_event_t ur_wr_ev; // need a separate event/cb for writing/polling
    proxy_event_t ur_te_ev; // for timeout handling
#endif
    enum mcp_backend_states state; // readback state machine
    bool connecting; // in the process of an asynch connection.
    bool can_write; // recently got a WANT_WRITE or are connecting.
    bool stacked; // if backend already queued for syscalls.
    bool bad; // timed out, marked as bad.
    struct iovec write_iovs[BE_IOV_MAX]; // iovs to stage batched writes
};
typedef STAILQ_HEAD(be_head_s, mcp_backend_s) be_head_t;

struct proxy_event_thread_s {
    pthread_t thread_id;
    struct event_base *base;
    struct event notify_event; // listen event for the notify pipe/eventfd.
    struct event clock_event; // timer for updating event thread data.
#ifdef HAVE_LIBURING
    struct io_uring ring;
    proxy_event_t ur_notify_event; // listen on eventfd.
    proxy_event_t ur_clock_event; // timer for updating event thread data.
    eventfd_t event_counter;
    bool use_uring;
#endif
    pthread_mutex_t mutex; // covers stack.
    pthread_cond_t cond; // condition to wait on while stack drains.
    io_head_t io_head_in; // inbound requests to process.
    be_head_t be_head; // stack of backends for processing.
#ifdef USE_EVENTFD
    int event_fd;
#else
    int notify_receive_fd;
    int notify_send_fd;
#endif
    proxy_ctx_t *ctx; // main context.
    struct proxy_tunables tunables; // periodically copied from main ctx
};

#define RESP_CMD_MAX 8
typedef struct {
    mcmc_resp_t resp;
    struct timeval start; // start time inherited from paired request
    char cmd[RESP_CMD_MAX+1]; // until we can reverse CMD_*'s to strings directly.
    int status; // status code from mcmc_read()
    char *buf; // response line + potentially value.
    size_t blen; // total size of the value to read.
    int bread; // amount of bytes read into value so far.
} mcp_resp_t;

// re-cast an io_pending_t into this more descriptive structure.
// the first few items _must_ match the original struct.
struct _io_pending_proxy_t {
    int io_queue_type;
    LIBEVENT_THREAD *thread;
    conn *c;
    mc_resp *resp;  // original struct ends here

    struct _io_pending_proxy_t *next; // stack for IO submission
    STAILQ_ENTRY(_io_pending_proxy_t) io_next; // stack for backends
    int coro_ref; // lua registry reference to the coroutine
    int mcpres_ref; // mcp.res reference used for await()
    lua_State *coro; // pointer directly to the coroutine
    mcp_backend_t *backend; // backend server to request from
    struct iovec iov[2]; // request string + tail buffer
    int iovcnt; // 1 or 2...
    unsigned int iovbytes; // total bytes in the iovec
    int await_ref; // lua reference if we were an await object
    mcp_resp_t *client_resp; // reference (currently pointing to a lua object)
    bool flushed; // whether we've fully written this request to a backend.
    bool ascii_multiget; // passed on from mcp_r_t
    bool is_await; // are we an await object?
};

// Note: does *be have to be a sub-struct? how stable are userdata pointers?
// https://stackoverflow.com/questions/38718475/lifetime-of-lua-userdata-pointers
// - says no.
typedef struct {
    int ref; // luaL_ref reference.
    mcp_backend_t *be;
} mcp_pool_be_t;

#define KEY_HASH_FILTER_MAX 5
typedef struct mcp_pool_s mcp_pool_t;
struct mcp_pool_s {
    struct proxy_hash_caller phc;
    key_hash_filter_func key_filter;
    key_hash_func key_hasher;
    pthread_mutex_t lock; // protects refcount.
    proxy_ctx_t *ctx; // main context.
    STAILQ_ENTRY(mcp_pool_s) next; // stack for deallocator.
    char key_filter_conf[KEY_HASH_FILTER_MAX+1];
    uint64_t hash_seed; // calculated from a string.
    int refcount;
    int phc_ref;
    int self_ref; // TODO (v2): double check that this is needed.
    int pool_size;
    mcp_pool_be_t pool[];
};

typedef struct {
    mcp_pool_t *main; // ptr to original
} mcp_pool_proxy_t;

static int proxy_run_coroutine(lua_State *Lc, mc_resp *resp, io_pending_proxy_t *p, conn *c);
#define PROCESS_MULTIGET true
#define PROCESS_NORMAL false
static void proxy_process_command(conn *c, char *command, size_t cmdlen, bool multiget);
static size_t _process_request_next_key(mcp_parser_t *pr);
static int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen);
static void dump_stack(lua_State *L);
static void mcp_queue_io(conn *c, mc_resp *resp, int coro_ref, lua_State *Lc);
static mcp_request_t *mcp_new_request(lua_State *L, mcp_parser_t *pr, const char *command, size_t cmdlen);
static void mcp_request_attach(lua_State *L, mcp_request_t *rq, io_pending_proxy_t *p);
static int mcplib_await_run(conn *c, lua_State *L, int coro_ref);
static int mcplib_await_return(io_pending_proxy_t *p);
static void proxy_backend_handler(const int fd, const short which, void *arg);
static void proxy_event_handler(evutil_socket_t fd, short which, void *arg);
static void proxy_event_updater(evutil_socket_t fd, short which, void *arg);
static void *proxy_event_thread(void *arg);
static void proxy_out_errstring(mc_resp *resp, const char *str);
static int _flush_pending_write(mcp_backend_t *be);
static int _reset_bad_backend(mcp_backend_t *be);
static void _set_event(mcp_backend_t *be, struct event_base *base, int flags, struct timeval t, event_callback_fn callback);
static int proxy_thread_loadconf(LIBEVENT_THREAD *thr);
static int proxy_backend_drive_machine(mcp_backend_t *be, int bread, char **rbuf, size_t *toread);

static void proxy_lua_error(lua_State *L, const char *s);
static void proxy_lua_ferror(lua_State *L, const char *fmt, ...);

/******** EXTERNAL FUNCTIONS ******/
// functions starting with _ are breakouts for the public functions.

// see also: process_extstore_stats()
// FIXME (v2): get context off of conn? global variables
void proxy_stats(ADD_STAT add_stats, conn *c) {
    if (!settings.proxy_enabled) {
       return;
    }
    proxy_ctx_t *ctx = settings.proxy_ctx;
    STAT_L(ctx);

    APPEND_STAT("proxy_config_reloads", "%llu", (unsigned long long)ctx->global_stats.config_reloads);
    APPEND_STAT("proxy_config_reload_fails", "%llu", (unsigned long long)ctx->global_stats.config_reload_fails);
    APPEND_STAT("proxy_backend_total", "%llu", (unsigned long long)ctx->global_stats.backend_total);
    APPEND_STAT("proxy_backend_marked_bad", "%llu", (unsigned long long)ctx->global_stats.backend_marked_bad);
    APPEND_STAT("proxy_backend_failed", "%llu", (unsigned long long)ctx->global_stats.backend_failed);
    STAT_UL(ctx);
}

void process_proxy_stats(ADD_STAT add_stats, conn *c) {
    char key_str[STAT_KEY_LEN];

    if (!settings.proxy_enabled) {
        return;
    }
    proxy_ctx_t *ctx = settings.proxy_ctx;
    STAT_L(ctx);

    // prepare aggregated counters.
    struct proxy_user_stats *us = &ctx->user_stats;
    uint64_t counters[us->num_stats];
    memset(counters, 0, sizeof(counters));

    // aggregate worker thread counters.
    for (int x = 0; x < settings.num_threads; x++) {
        LIBEVENT_THREAD *t = get_worker_thread(x);
        struct proxy_user_stats *tus = t->proxy_stats;
        WSTAT_L(t);
        for (int i = 0; i < tus->num_stats; i++) {
            counters[i] += tus->counters[i];
        }
        WSTAT_UL(t);
    }

    // return all of the stats
    for (int x = 0; x < us->num_stats; x++) {
        snprintf(key_str, STAT_KEY_LEN-1, "user_%s", us->names[x]);
        APPEND_STAT(key_str, "%llu", (unsigned long long)counters[x]);
    }
    STAT_UL(ctx);
}

struct _dumpbuf {
    size_t size;
    size_t used;
    char *buf;
};

static int _dump_helper(lua_State *L, const void *p, size_t sz, void *ud) {
    (void)L;
    struct _dumpbuf *db = ud;
    if (db->used + sz > db->size) {
        db->size *= 2;
        char *nb = realloc(db->buf, db->size);
        if (nb == NULL) {
            return -1;
        }
        db->buf = nb;
    }
    memcpy(db->buf + db->used, (const char *)p, sz);
    db->used += sz;
    return 0;
}

static const char * _load_helper(lua_State *L, void *data, size_t *size) {
    (void)L;
    struct _dumpbuf *db = data;
    if (db->used == 0) {
        *size = 0;
        return NULL;
    }
    *size = db->used;
    db->used = 0;
    return db->buf;
}

void proxy_start_reload(void *arg) {
    proxy_ctx_t *ctx = arg;
    if (pthread_mutex_trylock(&ctx->config_lock) == 0) {
        pthread_cond_signal(&ctx->config_cond);
        pthread_mutex_unlock(&ctx->config_lock);
    }
}

// Manages a queue of inbound objects destined to be deallocated.
static void *_proxy_manager_thread(void *arg) {
    proxy_ctx_t *ctx = arg;
    pool_head_t head;

    pthread_mutex_lock(&ctx->manager_lock);
    while (1) {
        STAILQ_INIT(&head);
        while (STAILQ_EMPTY(&ctx->manager_head)) {
            pthread_cond_wait(&ctx->manager_cond, &ctx->manager_lock);
        }

        // pull dealloc queue into local queue.
        STAILQ_CONCAT(&head, &ctx->manager_head);
        pthread_mutex_unlock(&ctx->manager_lock);

        // Config lock is required for using config VM.
        pthread_mutex_lock(&ctx->config_lock);
        lua_State *L = ctx->proxy_state;
        mcp_pool_t *p;
        STAILQ_FOREACH(p, &head, next) {
            // we let the pool object _gc() handle backend references.

            luaL_unref(L, LUA_REGISTRYINDEX, p->phc_ref);
            // need to... unref self.
            // NOTE: double check if we really need to self-reference.
            // this is a backup here to ensure the external refcounts hit zero
            // before lua garbage collects the object. other things hold a
            // reference to the object though.
            luaL_unref(L, LUA_REGISTRYINDEX, p->self_ref);
        }
        pthread_mutex_unlock(&ctx->config_lock);

        // done.
        pthread_mutex_lock(&ctx->manager_lock);
    }

    return NULL;
}

// Thread handling the configuration reload sequence.
// TODO (v2): get a logger instance.
// TODO (v2): making this "safer" will require a few phases of work.
// 1) JFDI
// 2) "test VM" -> from config thread, test the worker reload portion.
// 3) "unit testing" -> from same temporary worker VM, execute set of
// integration tests that must pass.
// 4) run update on each worker, collecting new mcp.attach() hooks.
//    Once every worker has successfully executed and set new hooks, roll
//    through a _second_ time to actually swap the hook structures and unref
//    the old structures where marked dirty.
static void *_proxy_config_thread(void *arg) {
    proxy_ctx_t *ctx = arg;

    logger_create();
    pthread_mutex_lock(&ctx->config_lock);
    while (1) {
        pthread_cond_wait(&ctx->config_cond, &ctx->config_lock);
        LOGGER_LOG(NULL, LOG_SYSEVENTS, LOGGER_PROXY_CONFIG, NULL, "start");
        STAT_INCR(ctx, config_reloads, 1);
        lua_State *L = ctx->proxy_state;
        lua_settop(L, 0); // clear off any crud that could have been left on the stack.

        // The main stages of config reload are:
        // - load and execute the config file
        // - run mcp_config_pools()
        // - for each worker:
        //   - copy and execute new lua code
        //   - copy selector table
        //   - run mcp_config_routes()

        if (proxy_load_config(ctx) != 0) {
            // Failed to load. log and wait for a retry.
            STAT_INCR(ctx, config_reload_fails, 1);
            LOGGER_LOG(NULL, LOG_SYSEVENTS, LOGGER_PROXY_CONFIG, NULL, "failed");
            continue;
        }

        // TODO (v2): create a temporary VM to test-load the worker code into.
        // failing to load partway through the worker VM reloads can be
        // critically bad if we're not careful about references.
        // IE: the config VM _must_ hold references to selectors and backends
        // as long as they exist in any worker for any reason.

        for (int x = 0; x < settings.num_threads; x++) {
            LIBEVENT_THREAD *thr = get_worker_thread(x);

            pthread_mutex_lock(&ctx->worker_lock);
            ctx->worker_done = false;
            ctx->worker_failed = false;
            proxy_reload_notify(thr);
            while (!ctx->worker_done) {
                // in case of spurious wakeup.
                pthread_cond_wait(&ctx->worker_cond, &ctx->worker_lock);
            }
            pthread_mutex_unlock(&ctx->worker_lock);

            // Code load bailed.
            if (ctx->worker_failed) {
                STAT_INCR(ctx, config_reload_fails, 1);
                LOGGER_LOG(NULL, LOG_SYSEVENTS, LOGGER_PROXY_CONFIG, NULL, "failed");
                continue;
            }
        }
        LOGGER_LOG(NULL, LOG_SYSEVENTS, LOGGER_PROXY_CONFIG, NULL, "done");
    }

    return NULL;
}

static int _start_proxy_config_threads(proxy_ctx_t *ctx) {
    int ret;

    pthread_mutex_lock(&ctx->config_lock);
    if ((ret = pthread_create(&ctx->config_tid, NULL,
                    _proxy_config_thread, ctx)) != 0) {
        fprintf(stderr, "Failed to start proxy configuration thread: %s\n",
                strerror(ret));
        pthread_mutex_unlock(&ctx->config_lock);
        return -1;
    }
    pthread_mutex_unlock(&ctx->config_lock);

    pthread_mutex_lock(&ctx->manager_lock);
    if ((ret = pthread_create(&ctx->manager_tid, NULL,
                    _proxy_manager_thread, ctx)) != 0) {
        fprintf(stderr, "Failed to start proxy configuration thread: %s\n",
                strerror(ret));
        pthread_mutex_unlock(&ctx->manager_lock);
        return -1;
    }
    pthread_mutex_unlock(&ctx->manager_lock);

    return 0;
}

// TODO (v2): IORING_SETUP_ATTACH_WQ port from bench_event once we have multiple
// event threads.
static void _proxy_init_evthread_events(proxy_event_thread_t *t) {
#ifdef HAVE_LIBURING
    bool use_uring = t->ctx->use_uring;
    struct io_uring_params p = {0};
    assert(t->event_fd); // uring only exists where eventfd also does.

    // Setup the CQSIZE to be much larger than SQ size, since backpressure
    // issues can cause us to block on SQ submissions and as a network server,
    // stuff happens.

    if (use_uring) {
        p.flags = IORING_SETUP_CQSIZE;
        p.cq_entries = PRING_QUEUE_CQ_ENTRIES;
        int ret = io_uring_queue_init_params(PRING_QUEUE_SQ_ENTRIES, &t->ring, &p);
        if (ret) {
            perror("io_uring_queue_init_params");
            exit(1);
        }
        if (!(p.features & IORING_FEAT_NODROP)) {
            fprintf(stderr, "uring: kernel missing IORING_FEAT_NODROP, using libevent\n");
            use_uring = false;
        }
        if (!(p.features & IORING_FEAT_SINGLE_MMAP)) {
            fprintf(stderr, "uring: kernel missing IORING_FEAT_SINGLE_MMAP, using libevent\n");
            use_uring = false;
        }
        if (!(p.features & IORING_FEAT_FAST_POLL)) {
            fprintf(stderr, "uring: kernel missing IORING_FEAT_FAST_POLL, using libevent\n");
            use_uring = false;
        }

        if (use_uring) {
            // FIXME (v2): Sigh. we need a blocking event_fd for io_uring but we've a
            // chicken and egg in here. need a better structure... in meantime
            // re-create the event_fd.
            close(t->event_fd);
            t->event_fd = eventfd(0, 0);
            // FIXME (v2): hack for event init.
            t->ur_notify_event.set = false;
            _proxy_evthr_evset_notifier(t);

            // periodic data updater for event thread
            t->ur_clock_event.cb = proxy_event_updater_ur;
            t->ur_clock_event.udata = t;
            t->ur_clock_event.set = false;
            _proxy_evthr_evset_clock(t);

            t->use_uring = true;
            return;
        } else {
            // Decided to not use io_uring, so don't waste memory.
            t->use_uring = false;
            io_uring_queue_exit(&t->ring);
        }
    } else {
        t->use_uring = false;
    }
#endif

    struct event_config *ev_config;
    ev_config = event_config_new();
    event_config_set_flag(ev_config, EVENT_BASE_FLAG_NOLOCK);
    t->base = event_base_new_with_config(ev_config);
    event_config_free(ev_config);
    if (! t->base) {
        fprintf(stderr, "Can't allocate event base\n");
        exit(1);
    }

    // listen for notifications.
    // NULL was thread_libevent_process
    // FIXME (v2): use modern format? (event_assign)
#ifdef USE_EVENTFD
    event_set(&t->notify_event, t->event_fd,
          EV_READ | EV_PERSIST, proxy_event_handler, t);
#else
    event_set(&t->notify_event, t->notify_receive_fd,
          EV_READ | EV_PERSIST, proxy_event_handler, t);
#endif

    evtimer_set(&t->clock_event, proxy_event_updater, t);
    event_base_set(t->base, &t->clock_event);
    struct timeval rate = {.tv_sec = 3, .tv_usec = 0};
    evtimer_add(&t->clock_event, &rate);

    event_base_set(t->base, &t->notify_event);
    if (event_add(&t->notify_event, 0) == -1) {
        fprintf(stderr, "Can't monitor libevent notify pipe\n");
        exit(1);
    }

}

// start the centralized lua state and config thread.
// TODO (v2): return ctx ptr. avoid global vars.
void proxy_init(bool use_uring) {
    proxy_ctx_t *ctx = calloc(1, sizeof(proxy_ctx_t));
    settings.proxy_ctx = ctx;
    ctx->use_uring = use_uring;

    pthread_mutex_init(&ctx->config_lock, NULL);
    pthread_cond_init(&ctx->config_cond, NULL);
    pthread_mutex_init(&ctx->worker_lock, NULL);
    pthread_cond_init(&ctx->worker_cond, NULL);
    pthread_mutex_init(&ctx->manager_lock, NULL);
    pthread_cond_init(&ctx->manager_cond, NULL);
    pthread_mutex_init(&ctx->stats_lock, NULL);

    // FIXME (v2): default defines.
    ctx->tunables.backend_failure_limit = 3;
    ctx->tunables.connect.tv_sec = 5;
    ctx->tunables.retry.tv_sec = 3;
    ctx->tunables.read.tv_sec = 3;
#ifdef HAVE_LIBURING
    ctx->tunables.connect_ur.tv_sec = 5;
    ctx->tunables.retry_ur.tv_sec = 3;
    ctx->tunables.read_ur.tv_sec = 3;
#endif // HAVE_LIBURING

    STAILQ_INIT(&ctx->manager_head);
    lua_State *L = luaL_newstate();
    ctx->proxy_state = L;
    luaL_openlibs(L);
    // NOTE: might need to differentiate the libs yes?
    proxy_register_libs(NULL, L);

    // Create/start the backend threads, which we need before servers
    // start getting created.
    // Supporting N event threads should be possible, but it will be a
    // low number of N to avoid too many wakeup syscalls.
    // For now we hardcode to 1.
    proxy_event_thread_t *threads = calloc(1, sizeof(proxy_event_thread_t));
    ctx->proxy_threads = threads;
    for (int i = 0; i < 1; i++) {
        proxy_event_thread_t *t = &threads[i];
        t->ctx = ctx;
#ifdef USE_EVENTFD
        t->event_fd = eventfd(0, EFD_NONBLOCK);
        if (t->event_fd == -1) {
            perror("failed to create backend notify eventfd");
            exit(1);
        }
#else
        int fds[2];
        if (pipe(fds)) {
            perror("can't create proxy backend notify pipe");
            exit(1);
        }

        t->notify_receive_fd = fds[0];
        t->notify_send_fd = fds[1];
#endif
        _proxy_init_evthread_events(t);

        // incoming request queue.
        STAILQ_INIT(&t->io_head_in);
        pthread_mutex_init(&t->mutex, NULL);
        pthread_cond_init(&t->cond, NULL);

        memcpy(&t->tunables, &ctx->tunables, sizeof(t->tunables));

#ifdef HAVE_LIBURING
        if (t->use_uring) {
            pthread_create(&t->thread_id, NULL, proxy_event_thread_ur, t);
        } else {
            pthread_create(&t->thread_id, NULL, proxy_event_thread, t);
        }
#else
        pthread_create(&t->thread_id, NULL, proxy_event_thread, t);
#endif // HAVE_LIBURING
    }

    _start_proxy_config_threads(ctx);
}

int proxy_load_config(void *arg) {
    proxy_ctx_t *ctx = arg;
    lua_State *L = ctx->proxy_state;
    int res = luaL_loadfile(L, settings.proxy_startfile);
    if (res != LUA_OK) {
        fprintf(stderr, "ERROR: Failed to load proxy_startfile: %s\n", lua_tostring(L, -1));
        return -1;
    }
    // LUA_OK, LUA_ERRSYNTAX, LUA_ERRMEM, LUA_ERRFILE

    // Now we need to dump the compiled code into bytecode.
    // This will then get loaded into worker threads.
    struct _dumpbuf *db = malloc(sizeof(struct _dumpbuf));
    db->size = 16384;
    db->used = 0;
    db->buf = malloc(db->size);
    lua_dump(L, _dump_helper, db, 0);
    // 0 means no error.
    ctx->proxy_code = db;

    // now we complete the data load by calling the function.
    res = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (res != LUA_OK) {
        fprintf(stderr, "ERROR: Failed to load data into lua config state: %s\n", lua_tostring(L, -1));
        exit(EXIT_FAILURE);
    }

    // call the mcp_config_pools function to get the central backends.
    lua_getglobal(L, "mcp_config_pools");

    if (lua_isnil(L, -1)) {
        fprintf(stderr, "ERROR: Configuration file missing 'mcp_config_pools' function\n");
        exit(EXIT_FAILURE);
    }
    lua_pushnil(L); // no "old" config yet.
    if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
        fprintf(stderr, "ERROR: Failed to execute mcp_config_pools: %s\n", lua_tostring(L, -1));
        exit(EXIT_FAILURE);
    }

    // result is our main config.
    return 0;
}

static int _copy_pool(lua_State *from, lua_State *to) {
    // from, -3 should have he userdata.
    mcp_pool_t *p = luaL_checkudata(from, -3, "mcp.pool");
    size_t size = sizeof(mcp_pool_proxy_t);
    mcp_pool_proxy_t *pp = lua_newuserdatauv(to, size, 0);
    luaL_setmetatable(to, "mcp.pool_proxy");

    pp->main = p;
    pthread_mutex_lock(&p->lock);
    p->refcount++;
    pthread_mutex_unlock(&p->lock);
    return 0;
}

static void _copy_config_table(lua_State *from, lua_State *to);
// (from, -1) is the source value
// should end with (to, -1) being the new value.
static void _copy_config_table(lua_State *from, lua_State *to) {
    int type = lua_type(from, -1);
    bool found = false;
    luaL_checkstack(from, 4, "configuration error: table recursion too deep");
    luaL_checkstack(to, 4, "configuration error: table recursion too deep");
    switch (type) {
        case LUA_TNIL:
            lua_pushnil(to);
            break;
        case LUA_TUSERDATA:
            // see dump_stack() - check if it's something we handle.
            if (lua_getmetatable(from, -1) != 0) {
                lua_pushstring(from, "__name");
                if (lua_rawget(from, -2) != LUA_TNIL) {
                    const char *name = lua_tostring(from, -1);
                    if (strcmp(name, "mcp.pool") == 0) {
                        _copy_pool(from, to);
                        found = true;
                    }
                }
                lua_pop(from, 2);
            }
            if (!found) {
                proxy_lua_ferror(from, "unhandled userdata type in configuration table\n");
            }
            break;
        case LUA_TNUMBER:
            if (lua_isinteger(from, -1)) {
                lua_pushinteger(to, lua_tointeger(from, -1));
            } else {
                lua_pushnumber(to, lua_tonumber(from, -1));
            }
            break;
        case LUA_TSTRING:
            lua_pushlstring(to, lua_tostring(from, -1), lua_rawlen(from, -1));
            break;
        case LUA_TTABLE:
            // TODO (v2): copy the metatable first?
            // TODO (v2): size narr/nrec from old table and use createtable to
            // pre-allocate.
            lua_newtable(to); // throw new table on worker
            int t = lua_absindex(from, -1); // static index of table to copy.
            int nt = lua_absindex(to, -1); // static index of new table.
            lua_pushnil(from); // start iterator for main
            while (lua_next(from, t) != 0) {
                // (key, -2), (val, -1)
                int keytype = lua_type(from, -2);
                // to intentionally limit complexity and allow for future
                // optimizations we restrict what types may be used as keys
                // for sub-tables.
                switch (keytype) {
                    case LUA_TSTRING:
                        // to[l]string converts the actual key in the table
                        // into a string, so we must not do that unless it
                        // already is one.
                        lua_pushlstring(to, lua_tostring(from, -2), lua_rawlen(from, -2));
                        break;
                    case LUA_TNUMBER:
                        if (lua_isinteger(from, -1)) {
                            lua_pushinteger(to, lua_tointeger(from, -1));
                        } else {
                            lua_pushnumber(to, lua_tonumber(from, -1));
                        }
                        break;
                    default:
                        proxy_lua_error(from, "configuration table keys must be strings or numbers");
                }
                // lua_settable(to, n) - n being the table
                // takes -2 key -1 value, pops both.
                // use lua_absindex(L, -1) and so to convert easier?
                _copy_config_table(from, to); // push next value.
                lua_settable(to, nt);
                lua_pop(from, 1); // drop value, keep key.
            }
            // top of from is now the original table.
            // top of to should be the new table.
            break;
        default:
            proxy_lua_error(from, "unhandled data type in configuration table\n");
    }
}

// Run from proxy worker to coordinate code reload.
// config_lock must be held first.
void proxy_worker_reload(void *arg, LIBEVENT_THREAD *thr) {
    proxy_ctx_t *ctx = arg;
    pthread_mutex_lock(&ctx->worker_lock);
    if (proxy_thread_loadconf(thr) != 0) {
        ctx->worker_failed = true;
    }
    ctx->worker_done = true;
    pthread_cond_signal(&ctx->worker_cond);
    pthread_mutex_unlock(&ctx->worker_lock);
}

// FIXME (v2): need to test how to recover from an actual error here. error message
// needs to go somewhere useful, counters added, etc.
static int proxy_thread_loadconf(LIBEVENT_THREAD *thr) {
    lua_State *L = thr->L;
    // load the precompiled config function.
    proxy_ctx_t *ctx = settings.proxy_ctx;
    struct _dumpbuf *db = ctx->proxy_code;
    struct _dumpbuf db2; // copy because the helper modifies it.
    memcpy(&db2, db, sizeof(struct _dumpbuf));

    lua_load(L, _load_helper, &db2, "config", NULL);
    // LUA_OK + all errs from loadfile except LUA_ERRFILE.
    //dump_stack(L);
    // - pcall the func (which should load it)
    int res = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (res != LUA_OK) {
        // FIXME (v2): don't exit here!
        fprintf(stderr, "Failed to load data into worker thread\n");
        return -1;
    }

    lua_getglobal(L, "mcp_config_routes");
    // create deepcopy of argument to pass into mcp_config_routes.
    // FIXME (v2): to avoid lua SIGABRT'ing on errors we need to protect the call
    // normal pattern:
    // lua_pushcfunction(L, &_copy_config_table);
    // lua_pushlightuserdata(L, &L2);
    // res = la_pcall(L, etc);
    // ... but since this is cross-VM we could get errors from not the
    // protected VM, breaking setjmp/etc.
    // for this part of the code we should override lua_atpanic(),
    // allowing us to specifically recover and bail.
    // However, again, this will require the next version of the config reload
    // code since we are re-using the VM's and a panic can leave us in a
    // broken state.
    // If the setjump/longjump combos are compatible a pcall for from and
    // atpanic for to might work best, since the config VM is/should be long
    // running and worker VM's should be rotated.
    _copy_config_table(ctx->proxy_state, L);

    // copied value is in front of route function, now call it.
    if (lua_pcall(L, 1, 1, 0) != LUA_OK) {
        fprintf(stderr, "Failed to execute mcp_config_routes: %s\n", lua_tostring(L, -1));
        return -1;
    }

    // update user stats
    STAT_L(ctx);
    struct proxy_user_stats *us = &ctx->user_stats;
    struct proxy_user_stats *tus = NULL;
    if (us->num_stats != 0) {
        pthread_mutex_lock(&thr->stats.mutex);
        if (thr->proxy_stats == NULL) {
            tus = calloc(1, sizeof(struct proxy_user_stats));
            thr->proxy_stats = tus;
        } else {
            tus = thr->proxy_stats;
        }

        // originally this was a realloc routine but it felt fragile.
        // that might still be a better idea; still need to zero out the end.
        uint64_t *counters = calloc(us->num_stats, sizeof(uint64_t));

        // note that num_stats can _only_ grow in size.
        // we also only care about counters on the worker threads.
        if (tus->counters) {
            assert(tus->num_stats <= us->num_stats);
            memcpy(counters, tus->counters, tus->num_stats * sizeof(uint64_t));
            free(tus->counters);
        }

        tus->counters = counters;
        tus->num_stats = us->num_stats;
        pthread_mutex_unlock(&thr->stats.mutex);
    }
    STAT_UL(ctx);

    return 0;
}

// Initialize the VM for an individual worker thread.
void proxy_thread_init(LIBEVENT_THREAD *thr) {
    // Create the hook table.
    thr->proxy_hooks = calloc(CMD_SIZE, sizeof(struct proxy_hook));
    if (thr->proxy_hooks == NULL) {
        fprintf(stderr, "Failed to allocate proxy hooks\n");
        exit(EXIT_FAILURE);
    }

    // Initialize the lua state.
    lua_State *L = luaL_newstate();
    thr->L = L;
    luaL_openlibs(L);
    proxy_register_libs(thr, L);

    // kick off the configuration.
    if (proxy_thread_loadconf(thr) != 0) {
        exit(EXIT_FAILURE);
    }
}

// ctx_stack is a stack of io_pending_proxy_t's.
void proxy_submit_cb(io_queue_t *q) {
    proxy_event_thread_t *e = ((proxy_ctx_t *)q->ctx)->proxy_threads;
    io_pending_proxy_t *p = q->stack_ctx;
    io_head_t head;
    STAILQ_INIT(&head);

    // NOTE: responses get returned in the correct order no matter what, since
    // mc_resp's are linked.
    // we just need to ensure stuff is parsed off the backend in the correct
    // order.
    // So we can do with a single list here, but we need to repair the list as
    // responses are parsed. (in the req_remaining-- section)
    // TODO (v2):
    // - except we can't do that because the deferred IO stack isn't
    // compatible with queue.h.
    // So for now we build the secondary list with an STAILQ, which
    // can be transplanted/etc.
    while (p) {
        // insert into tail so head is oldest request.
        STAILQ_INSERT_TAIL(&head, p, io_next);
        if (!p->is_await) {
            // funny workaround: awaiting IOP's don't count toward
            // resuming a connection, only the completion of the await
            // condition.
            q->count++;
        }

        p = p->next;
    }

    // clear out the submit queue so we can re-queue new IO's inline.
    q->stack_ctx = NULL;

    // Transfer request stack to event thread.
    pthread_mutex_lock(&e->mutex);
    STAILQ_CONCAT(&e->io_head_in, &head);
    // No point in holding the lock since we're not doing a cond signal.
    pthread_mutex_unlock(&e->mutex);

    // Signal to check queue.
#ifdef USE_EVENTFD
    uint64_t u = 1;
    // TODO (v2): check result? is it ever possible to get a short write/failure
    // for an eventfd?
    if (write(e->event_fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
        assert(1 == 0);
    }
#else
    if (write(e->notify_send_fd, "w", 1) <= 0) {
        assert(1 == 0);
    }
#endif

    return;
}

void proxy_complete_cb(io_queue_t *q) {
    /*
    io_pending_proxy_t *p = q->stack_ctx;
    q->stack_ctx = NULL;

    while (p) {
        io_pending_proxy_t *next = p->next;
        mc_resp *resp = p->resp;
        lua_State *Lc = p->coro;

        // in order to resume we need to remove the objects that were
        // originally returned
        // what's currently on the top of the stack is what we want to keep.
        lua_rotate(Lc, 1, 1);
        // We kept the original results from the yield so lua would not
        // collect them in the meantime. We can drop those now.
        lua_settop(Lc, 1);

        proxy_run_coroutine(Lc, resp, p, NULL);

        // don't need to flatten main thread here, since the coro is gone.

        p = next;
    }
    return;
    */
}

// called from worker thread after an individual IO has been returned back to
// the worker thread. Do post-IO run and cleanup work.
void proxy_return_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;
    if (p->is_await) {
        mcplib_await_return(p);
    } else {
        lua_State *Lc = p->coro;

        // in order to resume we need to remove the objects that were
        // originally returned
        // what's currently on the top of the stack is what we want to keep.
        lua_rotate(Lc, 1, 1);
        // We kept the original results from the yield so lua would not
        // collect them in the meantime. We can drop those now.
        lua_settop(Lc, 1);

        // p can be freed/changed from the call below, so fetch the queue now.
        io_queue_t *q = conn_io_queue_get(p->c, p->io_queue_type);
        conn *c = p->c;
        proxy_run_coroutine(Lc, p->resp, p, NULL);

        q->count--;
        if (q->count == 0) {
            // call re-add directly since we're already in the worker thread.
            conn_worker_readd(c);
        }
    }
}

// called from the worker thread as an mc_resp is being freed.
// must let go of the coroutine reference if there is one.
// caller frees the pending IO.
void proxy_finalize_cb(io_pending_t *pending) {
    io_pending_proxy_t *p = (io_pending_proxy_t *)pending;

    // release our coroutine reference.
    // TODO (v2): coroutines are reusable in lua 5.4. we can stack this onto a freelist
    // after a lua_resetthread(Lc) call.
    if (p->coro_ref) {
        // Note: lua registry is the same for main thread or a coroutine.
        luaL_unref(p->coro, LUA_REGISTRYINDEX, p->coro_ref);
    }
    return;
}

int try_read_command_proxy(conn *c) {
    char *el, *cont;

    if (c->rbytes == 0)
        return 0;

    el = memchr(c->rcurr, '\n', c->rbytes);
    if (!el) {
        if (c->rbytes > 1024) {
            /*
             * We didn't have a '\n' in the first k. This _has_ to be a
             * large multiget, if not we should just nuke the connection.
             */
            char *ptr = c->rcurr;
            while (*ptr == ' ') { /* ignore leading whitespaces */
                ++ptr;
            }

            if (ptr - c->rcurr > 100 ||
                (strncmp(ptr, "get ", 4) && strncmp(ptr, "gets ", 5))) {

                conn_set_state(c, conn_closing);
                return 1;
            }

            // ASCII multigets are unbound, so our fixed size rbuf may not
            // work for this particular workload... For backcompat we'll use a
            // malloc/realloc/free routine just for this.
            if (!c->rbuf_malloced) {
                if (!rbuf_switch_to_malloc(c)) {
                    conn_set_state(c, conn_closing);
                    return 1;
                }
            }
        }

        return 0;
    }
    cont = el + 1;

    assert(cont <= (c->rcurr + c->rbytes));

    c->last_cmd_time = current_time;
    proxy_process_command(c, c->rcurr, cont - c->rcurr, PROCESS_NORMAL);

    c->rbytes -= (cont - c->rcurr);
    c->rcurr = cont;

    assert(c->rcurr <= (c->rbuf + c->rsize));

    return 1;

}

// Called when a connection is closed while in nread state reading a set
// Must only be called with an active coroutine.
void proxy_cleanup_conn(conn *c) {
    assert(c->proxy_coro_ref != 0);
    LIBEVENT_THREAD *thr = c->thread;
    lua_State *L = thr->L;
    luaL_unref(L, LUA_REGISTRYINDEX, c->proxy_coro_ref);
    c->proxy_coro_ref = 0;
}

// we buffered a SET of some kind.
void complete_nread_proxy(conn *c) {
    assert(c != NULL);

    LIBEVENT_THREAD *thr = c->thread;
    lua_State *L = thr->L;

    if (c->proxy_coro_ref == 0) {
        complete_nread_ascii(c);
        return;
    }

    conn_set_state(c, conn_new_cmd);

    // Grab our coroutine.
    lua_rawgeti(L, LUA_REGISTRYINDEX, c->proxy_coro_ref);
    luaL_unref(L, LUA_REGISTRYINDEX, c->proxy_coro_ref);
    lua_State *Lc = lua_tothread(L, -1);
    mcp_request_t *rq = luaL_checkudata(Lc, -1, "mcp.request");

    // validate the data chunk.
    if (strncmp((char *)c->item + rq->pr.vlen - 2, "\r\n", 2) != 0) {
        lua_settop(L, 0); // clear anything remaining on the main thread.
        // FIXME (v2): need to set noreply false if mset_res, but that's kind
        // of a weird hack to begin with. Evaluate how to best do that here.
        out_string(c, "CLIENT_ERROR bad data chunk");
        return;
    }

    // We move ownership of the c->item buffer from the connection to the
    // request object here. Else we can double free if the conn closes while
    // inside nread.
    rq->pr.vbuf = c->item;
    c->item = NULL;
    c->item_malloced = false;
    c->proxy_coro_ref = 0;

    proxy_run_coroutine(Lc, c->resp, NULL, c);

    lua_settop(L, 0); // clear anything remaining on the main thread.

    return;
}

/******** NETWORKING AND INTERNAL FUNCTIONS ******/

static int _proxy_event_handler_dequeue(proxy_event_thread_t *t) {
    io_head_t head;

    STAILQ_INIT(&head);
    STAILQ_INIT(&t->be_head);

    // Pull the entire stack of inbound into local queue.
    pthread_mutex_lock(&t->mutex);
    STAILQ_CONCAT(&head, &t->io_head_in);
    pthread_mutex_unlock(&t->mutex);

    int io_count = 0;
    int be_count = 0;
    while (!STAILQ_EMPTY(&head)) {
        io_pending_proxy_t *io = STAILQ_FIRST(&head);
        io->flushed = false;
        mcp_backend_t *be = io->backend;
        // So the backend can retrieve its event base.
        be->event_thread = t;

        // _no_ mutex on backends. they are owned by the event thread.
        STAILQ_REMOVE_HEAD(&head, io_next);
        if (be->bad) {
            P_DEBUG("%s: fast failing request to bad backend\n", __func__);
            io->client_resp->status = MCMC_ERR;
            return_io_pending((io_pending_t *)io);
            continue;
        }
        STAILQ_INSERT_TAIL(&be->io_head, io, io_next);
        be->depth++;
        io_count++;
        if (!be->stacked) {
            be->stacked = true;
            STAILQ_INSERT_TAIL(&t->be_head, be, be_next);
            be_count++;
        }
    }
    //P_DEBUG("%s: io/be counts for syscalls [%d/%d]\n", __func__, io_count, be_count);
    return io_count;
}

#ifdef HAVE_LIBURING
static void _proxy_evthr_evset_be_read(mcp_backend_t *be, char *buf, size_t len, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_wrpoll(mcp_backend_t *be, struct __kernel_timespec *ts);
static void _proxy_evthr_evset_be_retry(mcp_backend_t *be);

static void proxy_event_updater_ur(void *udata, struct io_uring_cqe *cqe) {
    proxy_event_thread_t *t = udata;
    proxy_ctx_t *ctx = t->ctx;

    _proxy_evthr_evset_clock(t);

    // we reuse the "global stats" lock since it's hardly ever used.
    STAT_L(ctx);
    memcpy(&t->tunables, &ctx->tunables, sizeof(t->tunables));
    STAT_UL(ctx);
}

// No-op at the moment. when the linked timeout fires uring returns the
// linked request (read/write/poll/etc) with an interrupted/timeout/cancelled
// error. So we don't need to explicitly handle timeouts.
// I'm leaving the structure in to simplify the callback routine.
// Since timeouts rarely get called the extra code here shouldn't matter.
static void proxy_backend_timeout_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    return;
}

static void proxy_backend_retry_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    _proxy_evthr_evset_be_wrpoll(be, &be->event_thread->tunables.connect_ur);
}

static void _proxy_evthr_evset_be_retry(mcp_backend_t *be) {
    struct io_uring_sqe *sqe;
    if (be->ur_te_ev.set)
        return;

    be->ur_te_ev.cb = proxy_backend_retry_handler_ur;
    be->ur_te_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // TODO (v2): NULL?

    io_uring_prep_timeout(sqe, &be->event_thread->tunables.retry_ur, 0, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
    be->ur_te_ev.set = true;
}

static void _backend_failed_ur(mcp_backend_t *be) {
    if (++be->failed_count > be->event_thread->tunables.backend_failure_limit) {
        P_DEBUG("%s: marking backend as bad\n", __func__);
        be->bad = true;
        _proxy_evthr_evset_be_retry(be);
    } else {
        _proxy_evthr_evset_be_wrpoll(be, &be->event_thread->tunables.retry_ur);
    }
}

// read handler.
static void proxy_backend_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    int bread = cqe->res;
    char *rbuf = NULL;
    size_t toread = 0;
    // Error or disconnection.
    if (bread <= 0) {
        _reset_bad_backend(be);
        // NOTE: Not calling backed_failed here since if the backend is busted
        // it should be caught by the connect routine.
        // This is probably not _always_ true in practice. Leaving this note
        // so I can re-evaluate later.
        return;
    }

    int res = proxy_backend_drive_machine(be, bread, &rbuf, &toread);
    P_DEBUG("%s: bread: %d res: %d toread: %lu\n", __func__, bread, res, toread);

    if (res > 0) {
        _proxy_evthr_evset_be_read(be, rbuf, toread, &be->event_thread->tunables.read_ur);
    } else if (res == -1) {
        _reset_bad_backend(be);
        return;
    }

    // TODO (v2): when exactly do we need to reset the backend handler?
    if (!STAILQ_EMPTY(&be->io_head)) {
        _proxy_evthr_evset_be_read(be, be->rbuf, READ_BUFFER_SIZE, &be->event_thread->tunables.read_ur);
    }
}

static void proxy_backend_wrhandler_ur(void *udata, struct io_uring_cqe *cqe) {
    mcp_backend_t *be = udata;
    int flags = 0;

    be->can_write = true;
    if (be->connecting) {
        int err = 0;
        // We were connecting, now ensure we're properly connected.
        if (mcmc_check_nonblock_connect(be->client, &err) != MCMC_OK) {
            // kick the bad backend, clear the queue, retry later.
            // TODO (v2): if a connect fails, anything currently in the queue
            // should be safe to hold up until their timeout.
            _reset_bad_backend(be);
            _backend_failed_ur(be);
            P_DEBUG("%s: backend failed to connect\n", __func__);
            return;
        }
        P_DEBUG("%s: backend connected\n", __func__);
        be->connecting = false;
        be->state = mcp_backend_read;
        be->bad = false;
        be->failed_count = 0;
    }
    int res = _flush_pending_write(be);
    if (res == -1) {
        _reset_bad_backend(be);
        return;
    }

    if (flags & EV_WRITE) {
        _proxy_evthr_evset_be_wrpoll(be, &be->event_thread->tunables.connect_ur);
    }

    _proxy_evthr_evset_be_read(be, be->rbuf, READ_BUFFER_SIZE, &be->event_thread->tunables.read_ur);
}

static void proxy_event_handler_ur(void *udata, struct io_uring_cqe *cqe) {
    proxy_event_thread_t *t = udata;

    // liburing always uses eventfd for the notifier.
    // *cqe has our result.
    assert(cqe->res != -EINVAL);
    if (cqe->res != sizeof(eventfd_t)) {
        P_DEBUG("%s: cqe->res: %d\n", __func__, cqe->res);
        // FIXME (v2): figure out if this is impossible, and how to handle if not.
        assert(1 == 0);
    }

    // need to re-arm the listener every time.
    _proxy_evthr_evset_notifier(t);

    // TODO (v2): sqe queues for writing to backends
    //  - _ur handler for backend write completion is to set a read event and
    //  re-submit. ugh.
    // Should be possible to have standing reads, but flow is harder and lets
    // optimize that later. (ie; allow matching reads to a request but don't
    // actually dequeue anything until both read and write are confirmed)
    if (_proxy_event_handler_dequeue(t) == 0) {
        //P_DEBUG("%s: no IO's to complete\n", __func__);
        return;
    }

    // Re-walk each backend and check set event as required.
    mcp_backend_t *be = NULL;

    // TODO (v2): for each backend, queue writev's into sqe's
    // move the backend sqe bits into a write complete handler
    STAILQ_FOREACH(be, &t->be_head, be_next) {
        be->stacked = false;
        int flags = 0;

        if (be->connecting) {
            P_DEBUG("%s: deferring IO pending connecting\n", __func__);
            flags |= EV_WRITE;
        } else {
            flags = _flush_pending_write(be);
        }

        if (flags == -1) {
            _reset_bad_backend(be);
        } else {
            // FIXME (v2): needs a re-write to handle sqe starvation.
            // FIXME (v2): can't actually set the read here? need to confirm _some_
            // write first?
            if (flags & EV_WRITE) {
                _proxy_evthr_evset_be_wrpoll(be, &t->tunables.connect_ur);
            }
            if (flags & EV_READ) {
                _proxy_evthr_evset_be_read(be, be->rbuf, READ_BUFFER_SIZE, &t->tunables.read_ur);
            }
        }
    }
}

static void _proxy_evthr_evset_be_wrpoll(mcp_backend_t *be, struct __kernel_timespec *ts) {
    struct io_uring_sqe *sqe;
    if (be->ur_wr_ev.set)
        return;

    be->ur_wr_ev.cb = proxy_backend_wrhandler_ur;
    be->ur_wr_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // FIXME (v2): NULL?

    io_uring_prep_poll_add(sqe, mcmc_fd(be->client), POLLOUT);
    io_uring_sqe_set_data(sqe, &be->ur_wr_ev);
    be->ur_wr_ev.set = true;

    sqe->flags |= IOSQE_IO_LINK;

    // add a timeout.
    be->ur_te_ev.cb = proxy_backend_timeout_handler_ur;
    be->ur_te_ev.udata = be;
    sqe = io_uring_get_sqe(&be->event_thread->ring);

    io_uring_prep_link_timeout(sqe, ts, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
}

static void _proxy_evthr_evset_be_read(mcp_backend_t *be, char *buf, size_t len, struct __kernel_timespec *ts) {
    P_DEBUG("%s: setting: %lu\n", __func__, len);
    struct io_uring_sqe *sqe;
    if (be->ur_rd_ev.set) {
        P_DEBUG("%s: already set\n", __func__);
        return;
    }

    be->ur_rd_ev.cb = proxy_backend_handler_ur;
    be->ur_rd_ev.udata = be;

    sqe = io_uring_get_sqe(&be->event_thread->ring);
    // FIXME (v2): NULL?
    assert(be->rbuf != NULL);
    io_uring_prep_recv(sqe, mcmc_fd(be->client), buf, len, 0);
    io_uring_sqe_set_data(sqe, &be->ur_rd_ev);
    be->ur_rd_ev.set = true;

    sqe->flags |= IOSQE_IO_LINK;

    // add a timeout.
    // TODO (v2): we can pre-set the event data and avoid always re-doing it here.
    be->ur_te_ev.cb = proxy_backend_timeout_handler_ur;
    be->ur_te_ev.udata = be;
    sqe = io_uring_get_sqe(&be->event_thread->ring);

    io_uring_prep_link_timeout(sqe, ts, 0);
    io_uring_sqe_set_data(sqe, &be->ur_te_ev);
}

static void _proxy_evthr_evset_clock(proxy_event_thread_t *t) {
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&t->ring);
    // FIXME (v2): NULL?

    io_uring_prep_timeout(sqe, &updater_ts, 0, 0);
    io_uring_sqe_set_data(sqe, &t->ur_clock_event);
    t->ur_clock_event.set = true;
}

static void _proxy_evthr_evset_notifier(proxy_event_thread_t *t) {
    struct io_uring_sqe *sqe;
    P_DEBUG("%s: setting: %d\n", __func__, t->ur_notify_event.set);
    if (t->ur_notify_event.set)
        return;

    t->ur_notify_event.cb = proxy_event_handler_ur;
    t->ur_notify_event.udata = t;

    sqe = io_uring_get_sqe(&t->ring);
    // FIXME (v2): NULL?
    io_uring_prep_read(sqe, t->event_fd, &t->event_counter, sizeof(eventfd_t), 0);
    io_uring_sqe_set_data(sqe, &t->ur_notify_event);
}

// TODO (v2): CQE's can generate many SQE's, so we might need to occasionally check
// for space free in the sqe queue and submit in the middle of the cqe
// foreach.
// There might be better places to do this, but I think it's cleaner if
// submission and cqe can stay in this function.
// TODO (v2): The problem is io_submit() can deadlock if too many cqe's are
// waiting.
// Need to understand if this means "CQE's ready to be picked up" or "CQE's in
// flight", because the former is much easier to work around (ie; only run the
// backend handler after dequeuing everything else)
// TODO (v2): IOURING_FEAT_NODROP: uring_submit() should return -EBUSY if out of CQ
// events slots. Therefore might starve SQE's if we were low beforehand.
// - switch from for_each_cqe to doing one at a time (for now?)
// - track # of sqe's allocated in the cqe loop.
// - stop and submit if we've >= half the queue.
// - ??? when can a CQE generate > 1 SQE?
//   - wrhandler_ur can set both wrpoll and read
// - if CQE's can gen > 1 SQE at a time, we'll eventually starve.
// - proper flow: CQE's can enqueue backends to be processed.
// - after CQE's are processed, backends are processed (ouch?)
//   - if SQE's starve here, bail but keep the BE queue.
// - then submit SQE's
static void *proxy_event_thread_ur(void *arg) {
    proxy_event_thread_t *t = arg;
    struct io_uring_cqe *cqe;

    P_DEBUG("%s: starting\n", __func__);

    while (1) {
        P_DEBUG("%s: submit and wait\n", __func__);
        io_uring_submit_and_wait(&t->ring, 1);
        //P_DEBUG("%s: sqe submitted: %d\n", __func__, ret);

        uint32_t head = 0;
        uint32_t count = 0;

        io_uring_for_each_cqe(&t->ring, head, cqe) {
            P_DEBUG("%s: got a CQE [count:%d]\n", __func__, count);

            proxy_event_t *pe = io_uring_cqe_get_data(cqe);
            pe->set = false;
            pe->cb(pe->udata, cqe);

            count++;
        }

        P_DEBUG("%s: advancing [count:%d]\n", __func__, count);
        io_uring_cq_advance(&t->ring, count);
    }

    return NULL;
}
#endif // HAVE_LIBURING

// We need to get timeout/retry/etc updates to the event thread(s)
// occasionally. I'd like to have a better inteface around this where updates
// are shipped directly; but this is good enough to start with.
static void proxy_event_updater(evutil_socket_t fd, short which, void *arg) {
    proxy_event_thread_t *t = arg;
    proxy_ctx_t *ctx = t->ctx;

    // TODO (v2): double check how much of this boilerplate is still necessary?
    // reschedule the clock event.
    evtimer_del(&t->clock_event);

    evtimer_set(&t->clock_event, proxy_event_updater, t);
    event_base_set(t->base, &t->clock_event);
    struct timeval rate = {.tv_sec = 3, .tv_usec = 0};
    evtimer_add(&t->clock_event, &rate);

    // we reuse the "global stats" lock since it's hardly ever used.
    STAT_L(ctx);
    memcpy(&t->tunables, &ctx->tunables, sizeof(t->tunables));
    STAT_UL(ctx);
}

// event handler for executing backend requests
static void proxy_event_handler(evutil_socket_t fd, short which, void *arg) {
    proxy_event_thread_t *t = arg;

#ifdef USE_EVENTFD
    uint64_t u;
    if (read(fd, &u, sizeof(uint64_t)) != sizeof(uint64_t)) {
        // Temporary error or wasn't actually ready to read somehow.
        return;
    }
#else
    char buf[1];
    // TODO (v2): This is a lot more fatal than it should be. can it fail? can
    // it blow up the server?
    // TODO (v2): a cross-platform method of speeding this up would be nice. With
    // event fds we can queue N events and wakeup once here.
    // If we're pulling one byte out of the pipe at a time here it'll just
    // wake us up too often.
    // If the pipe is O_NONBLOCK then maybe just a larger read would work?
    if (read(fd, buf, 1) != 1) {
        P_DEBUG("%s: pipe read failed\n", __func__);
        return;
    }
#endif

    if (_proxy_event_handler_dequeue(t) == 0) {
        //P_DEBUG("%s: no IO's to complete\n", __func__);
        return;
    }

    // Re-walk each backend and check set event as required.
    mcp_backend_t *be = NULL;
    struct timeval tmp_time = t->tunables.read;

    // FIXME (v2): _set_event() is buggy, see notes on function.
    STAILQ_FOREACH(be, &t->be_head, be_next) {
        be->stacked = false;
        int flags = 0;

        if (be->connecting) {
            P_DEBUG("%s: deferring IO pending connecting\n", __func__);
        } else {
            flags = _flush_pending_write(be);
        }

        if (flags == -1) {
            _reset_bad_backend(be);
        } else {
            flags = be->can_write ? EV_READ|EV_TIMEOUT : EV_READ|EV_WRITE|EV_TIMEOUT;
            _set_event(be, t->base, flags, tmp_time, proxy_backend_handler);
        }
    }

}

static void *proxy_event_thread(void *arg) {
    proxy_event_thread_t *t = arg;

    event_base_loop(t->base, 0);
    event_base_free(t->base);

    // TODO (v2): join bt threads, free array.

    return NULL;
}


// Need a custom function so we can prefix lua strings easily.
static void proxy_out_errstring(mc_resp *resp, const char *str) {
    size_t len;
    const static char error_prefix[] = "SERVER_ERROR ";
    const static int error_prefix_len = sizeof(error_prefix) - 1;

    assert(resp != NULL);

    resp_reset(resp);
    // avoid noreply since we're throwing important errors.

    // Fill response object with static string.
    len = strlen(str);
    if ((len + error_prefix_len + 2) > WRITE_BUFFER_SIZE) {
        /* ought to be always enough. just fail for simplicity */
        str = "SERVER_ERROR output line too long";
        len = strlen(str);
    }

    char *w = resp->wbuf;
    memcpy(w, error_prefix, error_prefix_len);
    w += error_prefix_len;

    memcpy(w, str, len);
    w += len;

    memcpy(w, "\r\n", 2);
    resp_add_iov(resp, resp->wbuf, len + error_prefix_len + 2);
    return;
}

// Simple error wrapper for common failures.
// lua_error() is a jump so this function never returns
// for clarity add a 'return' after calls to this.
static void proxy_lua_error(lua_State *L, const char *s) {
    lua_pushstring(L, s);
    lua_error(L);
}

static void proxy_lua_ferror(lua_State *L, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    lua_pushfstring(L, fmt, ap);
    va_end(ap);
    lua_error(L);
}

// FIXME (v2): if we use the newer API the various pending checks can be adjusted.
static void _set_event(mcp_backend_t *be, struct event_base *base, int flags, struct timeval t, event_callback_fn callback) {
    // FIXME (v2): chicken and egg.
    // can't check if pending if the structure is was calloc'ed (sigh)
    // don't want to double test here. should be able to event_assign but
    // not add anything during initialization, but need the owner thread's
    // event base.
    int pending = 0;
    if (event_initialized(&be->event)) {
        pending = event_pending(&be->event, EV_READ|EV_WRITE|EV_TIMEOUT, NULL);
    }
    if ((pending & (EV_READ|EV_WRITE|EV_TIMEOUT)) != 0) {
            event_del(&be->event); // replace existing event.
    }

    // if we can't write, we could be connecting.
    // TODO (v2): always check for READ in case some commands were sent
    // successfully? The flags could be tracked on *be and reset in the
    // handler, perhaps?
    event_assign(&be->event, base, mcmc_fd(be->client),
            flags, callback, be);
    event_add(&be->event, &t);
}

// this resumes every yielded coroutine (and re-resumes if necessary).
// called from the worker thread after responses have been pulled from the
// network.
// Flow:
// - the response object should already be on the coroutine stack.
// - fix up the stack.
// - run coroutine.
// - if LUA_YIELD, we need to swap out the pending IO from its mc_resp then call for a queue
// again.
// - if LUA_OK finalize the response and return
// - else set error into mc_resp.
static int proxy_run_coroutine(lua_State *Lc, mc_resp *resp, io_pending_proxy_t *p, conn *c) {
    int nresults = 0;
    int cores = lua_resume(Lc, NULL, 1, &nresults);
    size_t rlen = 0;

    if (cores == LUA_OK) {
        int type = lua_type(Lc, -1);
        if (type == LUA_TUSERDATA) {
            mcp_resp_t *r = luaL_checkudata(Lc, -1, "mcp.response");
            LOGGER_LOG(NULL, LOG_RAWCMDS, LOGGER_PROXY_RAW, NULL, r->start, r->cmd, r->resp.type, r->resp.code);
            if (r->buf) {
                // response set from C.
                // FIXME (v2): write_and_free() ? it's a bit wrong for here.
                resp->write_and_free = r->buf;
                resp_add_iov(resp, r->buf, r->blen);
                r->buf = NULL;
            } else if (lua_getiuservalue(Lc, -1, 1) != LUA_TNIL) {
                // uservalue slot 1 is pre-created, so we get TNIL instead of
                // TNONE when nothing was set into it.
                const char *s = lua_tolstring(Lc, -1, &rlen);
                size_t l = rlen > WRITE_BUFFER_SIZE ? WRITE_BUFFER_SIZE : rlen;
                memcpy(resp->wbuf, s, l);
                resp_add_iov(resp, resp->wbuf, l);
                lua_pop(Lc, 1);
            } else if (r->status != MCMC_OK) {
                proxy_out_errstring(resp, "backend failure");
            } else {
                // Empty response: used for ascii multiget emulation.
            }
        } else if (type == LUA_TSTRING) {
            // response is a raw string from lua.
            const char *s = lua_tolstring(Lc, -1, &rlen);
            size_t l = rlen > WRITE_BUFFER_SIZE ? WRITE_BUFFER_SIZE : rlen;
            memcpy(resp->wbuf, s, l);
            resp_add_iov(resp, resp->wbuf, l);
            lua_pop(Lc, 1);
        } else {
            proxy_out_errstring(resp, "bad response");
        }
    } else if (cores == LUA_YIELD) {
        if (nresults == 1) {
            // TODO (v2): try harder to validate; but we have so few yield cases
            // that I'm going to shortcut this here. A single yielded result
            // means it's probably an await(), so attempt to process this.
            // FIXME (v2): if p, do we need to free it up from the resp?
            // resp should not have an IOP I think...
            assert(p == NULL);
            // coroutine object sitting on the _main_ VM right now, so we grab
            // the reference from there, which also pops it.
            int coro_ref = luaL_ref(c->thread->L, LUA_REGISTRYINDEX);
            mcplib_await_run(c, Lc, coro_ref);
        } else {
            // need to remove and free the io_pending, since c->resp owns it.
            // so we call mcp_queue_io() again and let it override the
            // mc_resp's io_pending object.

            int coro_ref = 0;
            mc_resp *resp;
            if (p != NULL) {
                coro_ref = p->coro_ref;
                resp = p->resp;
                c = p->c;
                do_cache_free(p->c->thread->io_cache, p);
                // *p is now dead.
            } else {
                // yielding from a top level call to the coroutine,
                // so we need to grab a reference to the coroutine thread.
                // TODO (v2): make this more explicit?
                // we only need to get the reference here, and error conditions
                // should instead drop it, but now it's not obvious to users that
                // we're reaching back into the main thread's stack.
                assert(c != NULL);
                coro_ref = luaL_ref(c->thread->L, LUA_REGISTRYINDEX);
                resp = c->resp;
            }
            // TODO (v2): c only used for cache alloc? push the above into the func?
            mcp_queue_io(c, resp, coro_ref, Lc);
        }
    } else {
        P_DEBUG("%s: Failed to run coroutine: %s\n", __func__, lua_tostring(Lc, -1));
        LOGGER_LOG(NULL, LOG_SYSEVENTS, LOGGER_PROXY_ERROR, NULL, lua_tostring(Lc, -1));
        proxy_out_errstring(resp, "lua failure");
    }

    return 0;
}

// NOTES:
// - mcp_backend_read: grab req_stack_head, do things
// read -> next, want_read -> next | read_end, etc.
// issue: want read back to read_end as necessary. special state?
//   - it's fine: p->client_resp->type.
// - mcp_backend_next: advance, consume, etc.
// TODO (v2): second argument with enum for a specific error.
// - probably just for logging. for app if any of these errors shouldn't
// result in killing the request stack!
static int proxy_backend_drive_machine(mcp_backend_t *be, int bread, char **rbuf, size_t *toread) {
    bool stop = false;
    io_pending_proxy_t *p = NULL;
    mcmc_resp_t tmp_resp; // helper for testing for GET's END marker.
    int flags = 0;

    p = STAILQ_FIRST(&be->io_head);
    if (p == NULL) {
        // got a read event, but nothing was queued.
        // probably means a disconnect event.
        // TODO (v2): could probably confirm this by attempting to read the
        // socket, getsockopt, or something else simply for logging or
        // statistical purposes.
        // In this case we know it's going to be a close so error.
        flags = -1;
        P_DEBUG("%s: read event but nothing in IO queue\n", __func__);
        return flags;
    }

    while (!stop) {
        mcp_resp_t *r;
        int res = 1;
        int remain = 0;
        char *newbuf = NULL;

    switch(be->state) {
        case mcp_backend_read:
            assert(p != NULL);
            P_DEBUG("%s: [read] bread: %d\n", __func__, bread);

            if (bread == 0) {
                // haven't actually done a read yet; figure out where/what.
                *rbuf = mcmc_read_prep(be->client, be->rbuf, READ_BUFFER_SIZE, toread);
                return EV_READ;
            } else {
                be->state = mcp_backend_parse;
            }
            break;
        case mcp_backend_parse:
            r = p->client_resp;
            r->status = mcmc_parse_buf(be->client, be->rbuf, bread, &r->resp);
            // FIXME (v2): Don't like how this mcmc API ended up.
            bread = 0; // only add the bread once per loop.
            if (r->status != MCMC_OK) {
                P_DEBUG("%s: mcmc_read failed [%d]\n", __func__, r->status);
                if (r->status == MCMC_WANT_READ) {
                    flags |= EV_READ;
                    be->state = mcp_backend_read;
                    stop = true;
                    break;
                } else {
                    flags = -1;
                    stop = true;
                    break;
                }
            }

            // we actually don't care about anything but the value length
            // TODO (v2): if vlen != vlen_read, pull an item and copy the data.
            int extra_space = 0;
            switch (r->resp.type) {
                case MCMC_RESP_GET:
                    // We're in GET mode. we only support one key per
                    // GET in the proxy backends, so we need to later check
                    // for an END.
                    extra_space = ENDLEN;
                    break;
                case MCMC_RESP_END:
                    // this is a MISS from a GET request
                    // or final handler from a STAT request.
                    assert(r->resp.vlen == 0);
                    break;
                case MCMC_RESP_META:
                    // we can handle meta responses easily since they're self
                    // contained.
                    break;
                case MCMC_RESP_GENERIC:
                case MCMC_RESP_NUMERIC:
                    break;
                // TODO (v2): No-op response?
                default:
                    P_DEBUG("%s: Unhandled response from backend: %d\n", __func__, r->resp.type);
                    // unhandled :(
                    flags = -1;
                    stop = true;
                    break;
            }

            if (res) {
                if (p->ascii_multiget && r->resp.type == MCMC_RESP_END) {
                    // Ascii multiget hack mode; consume END's
                    be->state = mcp_backend_next;
                    break;
                }

                // r->resp.reslen + r->resp.vlen is the total length of the response.
                // TODO (v2): need to associate a buffer with this response...
                // for now lets abuse write_and_free on mc_resp and simply malloc the
                // space we need, stuffing it into the resp object.

                r->blen = r->resp.reslen + r->resp.vlen;
                r->buf = malloc(r->blen + extra_space);
                if (r->buf == NULL) {
                    flags = -1; // TODO (v2): specific error.
                    stop = true;
                    break;
                }

                P_DEBUG("%s: r->status: %d, r->bread: %d, r->vlen: %lu\n", __func__, r->status, r->bread, r->resp.vlen);
                if (r->resp.vlen != r->resp.vlen_read) {
                    P_DEBUG("%s: got a short read, moving to want_read\n", __func__);
                    // copy the partial and advance mcmc's buffer digestion.
                    // FIXME (v2): should call this for both cases?
                    // special function for advancing mcmc's buffer for
                    // reading a value? perhaps a flag to skip the data copy
                    // when it's unnecessary?
                    memcpy(r->buf, be->rbuf, r->resp.reslen);
                    r->status = mcmc_read_value_buf(be->client, r->buf+r->resp.reslen, r->resp.vlen, &r->bread);
                    be->state = mcp_backend_want_read;
                    break;
                } else {
                    // mcmc's already counted the value as read if it fit in
                    // the original buffer...
                    memcpy(r->buf, be->rbuf, r->resp.reslen+r->resp.vlen_read);
                }
            } else {
                // TODO (v2): no response read?
                // nothing currently sets res to 0. should remove if that
                // never comes up and handle the error entirely above.
                P_DEBUG("%s: no response read from backend\n", __func__);
                flags = -1;
                stop = true;
                break;
            }

            if (r->resp.type == MCMC_RESP_GET) {
                // advance the buffer
                newbuf = mcmc_buffer_consume(be->client, &remain);
                if (remain != 0) {
                    // TODO (v2): don't need to shuffle buffer with better API
                    memmove(be->rbuf, newbuf, remain);
                }

                be->state = mcp_backend_read_end;
            } else {
                be->state = mcp_backend_next;
            }

            break;
        case mcp_backend_read_end:
            r = p->client_resp;
            // we need to ensure the next data in the stream is "END\r\n"
            // if not, the stack is desynced and we lose it.

            r->status = mcmc_parse_buf(be->client, be->rbuf, bread, &tmp_resp);
            P_DEBUG("%s [read_end]: r->status: %d, bread: %d resp.type:%d\n", __func__, r->status, bread, tmp_resp.type);
            if (r->status != MCMC_OK) {
                if (r->status == MCMC_WANT_READ) {
                    *rbuf = mcmc_read_prep(be->client, be->rbuf, READ_BUFFER_SIZE, toread);
                    return EV_READ;
                } else {
                    flags = -1; // TODO (v2): specific error.
                    stop = true;
                }
                break;
            } else if (tmp_resp.type != MCMC_RESP_END) {
                // TODO (v2): specific error about protocol desync
                flags = -1;
                stop = true;
                break;
            } else {
                // response is good.
                // FIXME (v2): copy what the server actually sent?
                if (!p->ascii_multiget) {
                    // sigh... if part of a multiget we need to eat the END
                    // markers down here.
                    memcpy(r->buf+r->blen, ENDSTR, ENDLEN);
                    r->blen += 5;
                }
            }

            be->state = mcp_backend_next;

            break;
        case mcp_backend_want_read:
            // Continuing a read from earlier
            r = p->client_resp;
            // take bread input and see if we're done reading the value,
            // else advance, set buffers, return next.
            if (bread > 0) {
                r->bread += bread;
                bread = 0;
            }
            P_DEBUG("%s: [want_read] r->bread: %d vlen: %lu\n", __func__, r->bread, r->resp.vlen);

            if (r->bread >= r->resp.vlen) {
                // all done copying data.
                if (r->resp.type == MCMC_RESP_GET) {
                    newbuf = mcmc_buffer_consume(be->client, &remain);
                    // Shouldn't be anything in the buffer if we had to run to
                    // want_read to read the value.
                    assert(remain == 0);
                    be->state = mcp_backend_read_end;
                } else {
                    be->state = mcp_backend_next;
                }
            } else {
                // signal to caller to issue a read.
                *rbuf = r->buf+r->resp.reslen+r->bread;
                *toread = r->resp.vlen - r->bread;
                // need to retry later.
                flags |= EV_READ;
                stop = true;
            }

            break;
        case mcp_backend_next:
            // set the head here. when we break the head will be correct.
            STAILQ_REMOVE_HEAD(&be->io_head, io_next);
            be->depth--;
            // have to do the q->count-- and == 0 and redispatch_conn()
            // stuff here. The moment we call return_io here we
            // don't own *p anymore.
            return_io_pending((io_pending_t *)p);

            if (STAILQ_EMPTY(&be->io_head)) {
                // TODO (v2): suspicious of this code. audit harder?
                stop = true;
            } else {
                p = STAILQ_FIRST(&be->io_head);
            }

            // mcmc_buffer_consume() - if leftover, keep processing
            // IO's.
            // if no more data in buffer, need to re-set stack head and re-set
            // event.
            remain = 0;
            // TODO (v2): do we need to yield every N reads?
            newbuf = mcmc_buffer_consume(be->client, &remain);
            P_DEBUG("%s: [next] remain: %d\n", __func__, remain);
            be->state = mcp_backend_read;
            if (remain != 0) {
                // data trailing in the buffer, for a different request.
                memmove(be->rbuf, newbuf, remain);
                be->state = mcp_backend_parse;
                P_DEBUG("read buffer remaining: %p %d\n", (void *)be, remain);
            } else {
                // need to read more data, buffer is empty.
                stop = true;
            }

            break;
        default:
            // TODO (v2): at some point (after v1?) this should attempt to recover,
            // though we should only get here from memory corruption and
            // bailing may be the right thing to do.
            fprintf(stderr, "%s: invalid backend state: %d\n", __func__, be->state);
            assert(false);
    } // switch
    } // while

    return flags;
}

// All we need to do here is schedule the backend to attempt to connect again.
static void proxy_backend_retry_handler(const int fd, const short which, void *arg) {
    mcp_backend_t *be = arg;
    assert(which & EV_TIMEOUT);
    struct timeval tmp_time = be->event_thread->tunables.retry;
    _set_event(be, be->event_thread->base, EV_WRITE|EV_TIMEOUT, tmp_time, proxy_backend_handler);
}

// currently just for timeouts, but certain errors should consider a backend
// to be "bad" as well.
// must be called before _reset_bad_backend(), so the backend is currently
// clear.
// TODO (v2): currently only notes for "bad backends" in cases of timeouts or
// connect failures. We need a specific connect() handler that executes a
// "version" call to at least check that the backend isn't speaking garbage.
// In theory backends can fail such that responses are constantly garbage,
// but it's more likely an app is doing something bad and culling the backend
// may prevent any other clients from talking to that backend. In
// that case we need to track if clients are causing errors consistently and
// block them instead. That's more challenging so leaving a note instead
// of doing this now :)
static void _backend_failed(mcp_backend_t *be) {
    struct timeval tmp_time = be->event_thread->tunables.retry;
    if (++be->failed_count > be->event_thread->tunables.backend_failure_limit) {
        P_DEBUG("%s: marking backend as bad\n", __func__);
        be->bad = true;
       _set_event(be, be->event_thread->base, EV_TIMEOUT, tmp_time, proxy_backend_retry_handler);
        STAT_INCR(be->event_thread->ctx, backend_marked_bad, 1);
    } else {
        STAT_INCR(be->event_thread->ctx, backend_failed, 1);
        _set_event(be, be->event_thread->base, EV_WRITE|EV_TIMEOUT, tmp_time, proxy_backend_handler);
    }
}

// TODO (v2): add a second argument for assigning a specific error to all pending
// IO's (ie; timeout).
// The backend has gotten into a bad state (timed out, protocol desync, or
// some other supposedly unrecoverable error: purge the queue and
// cycle the socket.
// Note that some types of errors may not require flushing the queue and
// should be fixed as they're figured out.
// _must_ be called from within the event thread.
static int _reset_bad_backend(mcp_backend_t *be) {
    io_pending_proxy_t *io = NULL;
    STAILQ_FOREACH(io, &be->io_head, io_next) {
        // TODO (v2): Unsure if this is the best way of surfacing errors to lua,
        // but will do for V1.
        io->client_resp->status = MCMC_ERR;
        return_io_pending((io_pending_t *)io);
    }

    STAILQ_INIT(&be->io_head);

    mcmc_disconnect(be->client);
    int status = mcmc_connect(be->client, be->ip, be->port, MCMC_OPTION_NONBLOCK);
    if (status == MCMC_CONNECTED) {
        // TODO (v2): unexpected but lets let it be here.
        be->connecting = false;
        be->can_write = true;
    } else if (status == MCMC_CONNECTING) {
        be->connecting = true;
        be->can_write = false;
    } else {
        // TODO (v2): failed to immediately re-establish the connection.
        // need to put the BE into a bad/retry state.
        // FIXME (v2): until we get an event to specifically handle connecting and
        // bad server handling, attempt to force a reconnect here the next
        // time a request comes through.
        // The event thread will attempt to write to the backend, fail, then
        // end up in this routine again.
        be->connecting = false;
        be->can_write = true;
    }

    return 0;
}

static int _prep_pending_write(mcp_backend_t *be, unsigned int *tosend) {
    struct iovec *iovs = be->write_iovs;
    io_pending_proxy_t *io = NULL;
    int iovused = 0;
    STAILQ_FOREACH(io, &be->io_head, io_next) {
        if (io->flushed)
            continue;

        if (io->iovcnt + iovused > BE_IOV_MAX) {
            // Signal to caller that we need to keep writing, if writeable.
            // FIXME (v2): can certainly refactor this to loop instead of waiting
            // for a writeable event.
            *tosend += 1;
            break;
        }

        memcpy(&iovs[iovused], io->iov, sizeof(struct iovec)*io->iovcnt);
        iovused += io->iovcnt;
        *tosend += io->iovbytes;
    }
    return iovused;
}

static int _flush_pending_write(mcp_backend_t *be) {
    int flags = 0;
    unsigned int tosend = 0;
    int iovcnt = _prep_pending_write(be, &tosend);

    ssize_t sent = writev(mcmc_fd(be->client), be->write_iovs, iovcnt);
    if (sent > 0) {
        io_pending_proxy_t *io = NULL;
        if (sent < tosend) {
            flags |= EV_WRITE;
        }

        STAILQ_FOREACH(io, &be->io_head, io_next) {
            bool flushed = true;
            if (io->flushed)
                continue;

            if (sent >= io->iovbytes) {
                // short circuit for common case.
                sent -= io->iovbytes;
            } else {
                for (int x = 0; x < io->iovcnt; x++) {
                    struct iovec *iov = &io->iov[x];
                    if (sent >= iov->iov_len) {
                        sent -= iov->iov_len;
                        iov->iov_len = 0;
                    } else {
                        iov->iov_len -= sent;
                        sent = 0;
                        flushed = false;
                        break;
                    }
                }
            }
            io->flushed = flushed;

            if (flushed) {
                flags |= EV_READ;
            }
            if (sent <= 0) {
                // really shouldn't be negative, though.
                assert(sent >= 0);
                break;
            }
        } // STAILQ_FOREACH
    } else if (sent == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            be->can_write = false;
            flags |= EV_WRITE;
        } else {
            flags = -1;
        }
    }

    return flags;
}

// The libevent backend callback handler.
// If we end up resetting a backend, it will get put back into a connecting
// state.
static void proxy_backend_handler(const int fd, const short which, void *arg) {
    mcp_backend_t *be = arg;
    int flags = EV_TIMEOUT;
    struct timeval tmp_time = be->event_thread->tunables.read;

    if (which & EV_TIMEOUT) {
        P_DEBUG("%s: timeout received, killing backend queue\n", __func__);
        _reset_bad_backend(be);
        _backend_failed(be);
        return;
    }

    if (which & EV_WRITE) {
        be->can_write = true;
        // TODO (v2): move connect routine to its own function?
        // - hard to do right now because we can't (easily?) edit libevent
        // events.
        if (be->connecting) {
            int err = 0;
            // We were connecting, now ensure we're properly connected.
            if (mcmc_check_nonblock_connect(be->client, &err) != MCMC_OK) {
                // kick the bad backend, clear the queue, retry later.
                // FIXME (v2): if a connect fails, anything currently in the queue
                // should be safe to hold up until their timeout.
                _reset_bad_backend(be);
                _backend_failed(be);
                P_DEBUG("%s: backend failed to connect\n", __func__);
                return;
            }
            P_DEBUG("%s: backend connected\n", __func__);
            be->connecting = false;
            be->state = mcp_backend_read;
            be->bad = false;
            be->failed_count = 0;
        }
        int res = _flush_pending_write(be);
        if (res == -1) {
            _reset_bad_backend(be);
            return;
        }
    }

    if (which & EV_READ) {
        // We do the syscall here before diving into the state machine to allow a
        // common code path for io_uring/epoll
        int res = 1;
        int read = 0;
        while (res > 0) {
            char *rbuf = NULL;
            size_t toread = 0;
            // need to input how much was read since last call
            // needs _output_ of the buffer to read into and how much.
            res = proxy_backend_drive_machine(be, read, &rbuf, &toread);
            P_DEBUG("%s: res: %d toread: %lu\n", __func__, res, toread);

            if (res > 0) {
                read = recv(mcmc_fd(be->client), rbuf, toread, 0);
                P_DEBUG("%s: read: %d\n", __func__, read);
                if (read == 0) {
                    // not connected or error.
                    _reset_bad_backend(be);
                    return;
                } else if (read == -1) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        break; // sit on epoll again.
                    } else {
                        _reset_bad_backend(be);
                        return;
                    }
                }
            } else if (res == -1) {
                _reset_bad_backend(be);
                return;
            } else {
                break;
            }
        }

#ifdef PROXY_DEBUG
        if (!STAILQ_EMPTY(&be->io_head)) {
            P_DEBUG("backend has leftover IOs: %d\n", be->depth);
        }
#endif
    }

    // Still pending requests to read or write.
    if (!STAILQ_EMPTY(&be->io_head)) {
        flags |= EV_READ; // FIXME (v2): might not be necessary here, but ensures we get a disconnect event.
        _set_event(be, be->event_thread->base, flags, tmp_time, proxy_backend_handler);
    }
}

static void proxy_process_command(conn *c, char *command, size_t cmdlen, bool multiget) {
    assert(c != NULL);
    LIBEVENT_THREAD *thr = c->thread;
    struct proxy_hook *hooks = thr->proxy_hooks;
    lua_State *L = thr->L;
    mcp_parser_t pr = {0};

    // Avoid doing resp_start() here, instead do it a bit later or as-needed.
    // This allows us to hop over to the internal text protocol parser, which
    // also calls resp_start().
    // Tighter integration later should obviate the need for this, it is not a
    // permanent solution.
    int ret = process_request(&pr, command, cmdlen);
    if (ret != 0) {
        WSTAT_INCR(c, proxy_conn_errors, 1);
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }
        proxy_out_errstring(c->resp, "parsing request");
        if (ret == -2) {
            // Kill connection on more critical parse failure.
            conn_set_state(c, conn_closing);
        }
        return;
    }

    struct proxy_hook *hook = &hooks[pr.command];

    if (!hook->is_lua) {
        // need to pass our command string into the internal handler.
        // to minimize the code change, this means allowing it to tokenize the
        // full command. The proxy's indirect parser should be built out to
        // become common code for both proxy and ascii handlers.
        // For now this means we have to null-terminate the command string,
        // then call into text protocol handler.
        // FIXME (v2): use a ptr or something; don't like this code.
        if (cmdlen > 1 && command[cmdlen-2] == '\r') {
            command[cmdlen-2] = '\0';
        } else {
            command[cmdlen-1] = '\0';
        }
        // lets nread_proxy know we're in ascii mode.
        c->proxy_coro_ref = 0;
        process_command_ascii(c, command);
        return;
    }

    // Count requests handled by proxy vs local.
    WSTAT_INCR(c, proxy_conn_requests, 1);

    // If ascii multiget, we turn this into a self-calling loop :(
    // create new request with next key, call this func again, then advance
    // original string.
    // might be better to split this function; the below bits turn into a
    // function call, then we don't re-process the above bits in the same way?
    // The way this is detected/passed on is very fragile.
    if (!multiget && pr.cmd_type == CMD_TYPE_GET && pr.has_space) {
        uint32_t keyoff = pr.tokens[pr.keytoken];
        while (pr.klen != 0) {
            char temp[KEY_MAX_LENGTH + 30];
            char *cur = temp;
            // Core daemon can abort the entire command if one key is bad, but
            // we cannot from the proxy. Instead we have to inject errors into
            // the stream. This should, thankfully, be rare at least.
            if (pr.klen > KEY_MAX_LENGTH) {
                if (!resp_start(c)) {
                    conn_set_state(c, conn_closing);
                    return;
                }
                proxy_out_errstring(c->resp, "key too long");
            } else {
                // copy original request up until the original key token.
                memcpy(cur, pr.request, pr.tokens[pr.keytoken]);
                cur += pr.tokens[pr.keytoken];

                // now copy in our "current" key.
                memcpy(cur, &pr.request[keyoff], pr.klen);
                cur += pr.klen;

                memcpy(cur, "\r\n", 2);
                cur += 2;

                *cur = '\0';
                P_DEBUG("%s: new multiget sub request: %s [%u/%u]\n", __func__, temp, keyoff, pr.klen);
                proxy_process_command(c, temp, cur - temp, PROCESS_MULTIGET);
            }

            // now advance to the next key.
            keyoff = _process_request_next_key(&pr);
        }

        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }

        // The above recursions should have created c->resp's in dispatch
        // order.
        // So now we add another one at the end to create the capping END
        // string.
        memcpy(c->resp->wbuf, ENDSTR, ENDLEN);
        resp_add_iov(c->resp, c->resp->wbuf, ENDLEN);

        return;
    }

    // We test the command length all the way down here because multigets can
    // be very long, and they're chopped up by now.
    if (cmdlen >= MCP_REQUEST_MAXLEN) {
        WSTAT_INCR(c, proxy_conn_errors, 1);
        if (!resp_start(c)) {
            conn_set_state(c, conn_closing);
            return;
        }
        proxy_out_errstring(c->resp, "request too long");
        conn_set_state(c, conn_closing);
        return;
    }

    if (!resp_start(c)) {
        conn_set_state(c, conn_closing);
        return;
    }

    // start a coroutine.
    // TODO (v2): This can pull a thread from a cache.
    lua_newthread(L);
    lua_State *Lc = lua_tothread(L, -1);
    // leave the thread first on the stack, so we can reference it if needed.
    // pull the lua hook function onto the stack.
    lua_rawgeti(Lc, LUA_REGISTRYINDEX, hook->lua_ref);

    mcp_request_t *rq = mcp_new_request(Lc, &pr, command, cmdlen);
    if (multiget) {
        rq->ascii_multiget = true;
    }
    // TODO (v2): lift this to a post-processor?
    if (rq->pr.vlen != 0) {
        // relying on temporary malloc's not succumbing as poorly to
        // fragmentation.
        c->item = malloc(rq->pr.vlen);
        if (c->item == NULL) {
            lua_settop(L, 0);
            proxy_out_errstring(c->resp, "out of memory");
            return;
        }
        c->item_malloced = true;
        c->ritem = c->item;
        c->rlbytes = rq->pr.vlen;
        c->proxy_coro_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops coroutine.

        conn_set_state(c, conn_nread);
        return;
    }

    proxy_run_coroutine(Lc, c->resp, NULL, c);

    lua_settop(L, 0); // clear anything remaining on the main thread.
}

// analogue for storage_get_item(); add a deferred IO object to the current
// connection's response object. stack enough information to write to the
// server on the submit callback, and enough to resume the lua state on the
// completion callback.
static void mcp_queue_io(conn *c, mc_resp *resp, int coro_ref, lua_State *Lc) {
    io_queue_t *q = conn_io_queue_get(c, IO_QUEUE_PROXY);

    // stack: request, hash selector. latter just to hold a reference.

    mcp_request_t *rq = luaL_checkudata(Lc, -1, "mcp.request");
    mcp_backend_t *be = rq->be;

    // Then we push a response object, which we'll re-use later.
    // reserve one uservalue for a lua-supplied response.
    mcp_resp_t *r = lua_newuserdatauv(Lc, sizeof(mcp_resp_t), 1);
    // FIXME (v2): is this memset still necessary? I was using it for
    // debugging.
    memset(r, 0, sizeof(mcp_resp_t));
    r->buf = NULL;
    r->blen = 0;
    r->start = rq->start; // need to inherit the original start time.
    int x;
    int end = rq->pr.reqlen-2 > RESP_CMD_MAX ? RESP_CMD_MAX : rq->pr.reqlen-2;
    for (x = 0; x < end; x++) {
        if (rq->pr.request[x] == ' ') {
            break;
        }
        r->cmd[x] = rq->pr.request[x];
    }
    r->cmd[x] = '\0';

    luaL_getmetatable(Lc, "mcp.response");
    lua_setmetatable(Lc, -2);

    io_pending_proxy_t *p = do_cache_alloc(c->thread->io_cache);
    if (p == NULL) {
        WSTAT_INCR(c, proxy_conn_oom, 1);
        proxy_lua_error(Lc, "out of memory allocating from IO cache");
        return;
    }

    // this is a re-cast structure, so assert that we never outsize it.
    assert(sizeof(io_pending_t) >= sizeof(io_pending_proxy_t));
    memset(p, 0, sizeof(io_pending_proxy_t));
    // set up back references.
    p->io_queue_type = IO_QUEUE_PROXY;
    p->thread = c->thread;
    p->c = c;
    p->resp = resp;
    p->client_resp = r;
    p->flushed = false;
    p->ascii_multiget = rq->ascii_multiget;
    resp->io_pending = (io_pending_t *)p;

    // top of the main thread should be our coroutine.
    // lets grab a reference to it and pop so it doesn't get gc'ed.
    p->coro_ref = coro_ref;

    // we'll drop the pointer to the coro on here to save some CPU
    // on re-fetching it later. The pointer shouldn't change.
    p->coro = Lc;

    // The direct backend object. Lc is holding the reference in the stack
    p->backend = be;

    mcp_request_attach(Lc, rq, p);

    // link into the batch chain.
    p->next = q->stack_ctx;
    q->stack_ctx = p;

    return;
}

/******** LUA INTERFACE FUNCTIONS ******/

__attribute__((unused)) static void dump_stack(lua_State *L) {
    int top = lua_gettop(L);
    int i = 1;
    fprintf(stderr, "--TOP OF STACK [%d]\n", top);
    for (; i < top + 1; i++) {
        int type = lua_type(L, i);
        // lets find the metatable of this userdata to identify it.
        if (lua_getmetatable(L, i) != 0) {
            lua_pushstring(L, "__name");
            if (lua_rawget(L, -2) != LUA_TNIL) {
                fprintf(stderr, "--|%d| [%s] (%s)\n", i, lua_typename(L, type), lua_tostring(L, -1));
                lua_pop(L, 2);
                continue;
            }
            lua_pop(L, 2);
        }
        if (type == LUA_TSTRING) {
            fprintf(stderr, "--|%d| [%s] | %s\n", i, lua_typename(L, type), lua_tostring(L, i));
        } else {
            fprintf(stderr, "--|%d| [%s]\n", i, lua_typename(L, type));
        }
    }
    fprintf(stderr, "-----------------\n");
}

// func prototype example:
// static int fname (lua_State *L)
// normal library open:
// int luaopen_mcp(lua_State *L) { }

// resp:ok()
static int mcplib_response_ok(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->status == MCMC_OK) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int mcplib_response_hit(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    if (r->status == MCMC_OK && r->resp.code != MCMC_CODE_MISS) {
        lua_pushboolean(L, 1);
    } else {
        lua_pushboolean(L, 0);
    }

    return 1;
}

static int mcplib_response_gc(lua_State *L) {
    mcp_resp_t *r = luaL_checkudata(L, -1, "mcp.response");

    // On error/similar we might be holding the read buffer.
    // If the buf is handed off to mc_resp for return, this pointer is NULL
    if (r->buf != NULL) {
        free(r->buf);
    }

    return 0;
}

// NOTE: backends are global objects owned by pool objects.
// Each pool has a "proxy pool object" distributed to each worker VM.
// proxy pool objects are held at the same time as any request exists on a
// backend, in the coroutine stack during yield()
// To free a backend: All proxies for a pool are collected, then the central
// pool is collected, which releases backend references, which allows backend
// to be collected.
static int mcplib_backend_gc(lua_State *L) {
    mcp_backend_t *be = luaL_checkudata(L, -1, "mcp.backend");

    assert(STAILQ_EMPTY(&be->io_head));

    mcmc_disconnect(be->client);
    free(be->client);

    return 0;
}

static int mcplib_backend(lua_State *L) {
    luaL_checkstring(L, -4); // label for indexing backends.
    const char *ip = luaL_checkstring(L, -3);
    const char *port = luaL_checkstring(L, -2);
    double weight = luaL_checknumber(L, -1);

    // first check our reference table to compare.
    lua_pushvalue(L, -4);
    int ret = lua_gettable(L, lua_upvalueindex(MCP_BACKEND_UPVALUE));
    if (ret != LUA_TNIL) {
        mcp_backend_t *be_orig = luaL_checkudata(L, -1, "mcp.backend");
        if (strncmp(be_orig->ip, ip, MAX_IPLEN) == 0
                && strncmp(be_orig->port, port, MAX_PORTLEN) == 0
                && be_orig->weight == weight) {
            // backend is the same, return it.
            return 1;
        } else {
            // backend not the same, pop from stack and make new one.
            lua_pop(L, 1);
        }
    } else {
        lua_pop(L, 1);
    }

    // This might shift to internal objects?
    mcp_backend_t *be = lua_newuserdatauv(L, sizeof(mcp_backend_t), 0);
    if (be == NULL) {
        proxy_lua_error(L, "out of memory allocating backend");
        return 0;
    }

    // FIXME (v2): remove some of the excess zero'ing below?
    memset(be, 0, sizeof(mcp_backend_t));
    strncpy(be->ip, ip, MAX_IPLEN);
    strncpy(be->port, port, MAX_PORTLEN);
    be->weight = weight;
    be->depth = 0;
    be->rbuf = NULL;
    be->failed_count = 0;
    STAILQ_INIT(&be->io_head);
    be->state = mcp_backend_read;
    be->connecting = false;
    be->can_write = false;
    be->stacked = false;
    be->bad = false;

    // this leaves a permanent buffer on the backend, which is fine
    // unless you have billions of backends.
    // we can later optimize for pulling buffers from idle backends.
    be->rbuf = malloc(READ_BUFFER_SIZE);
    if (be->rbuf == NULL) {
        proxy_lua_error(L, "out of memory allocating backend");
        return 0;
    }

    // initialize libevent.
    memset(&be->event, 0, sizeof(be->event));

    // initialize the client
    be->client = malloc(mcmc_size(MCMC_OPTION_BLANK));
    if (be->client == NULL) {
        proxy_lua_error(L, "out of memory allocating backend");
        return 0;
    }
    // TODO (v2): connect elsewhere. When there're multiple backend owners, or
    // sockets per backend, etc. We'll want to kick off connects as use time.
    int status = mcmc_connect(be->client, be->ip, be->port, MCMC_OPTION_NONBLOCK);
    if (status == MCMC_CONNECTED) {
        // FIXME (v2): is this possible? do we ever want to allow blocking
        // connections?
        proxy_lua_ferror(L, "unexpectedly connected to backend early: %s:%s\n", be->ip, be->port);
        return 0;
    } else if (status == MCMC_CONNECTING) {
        be->connecting = true;
        be->can_write = false;
    } else {
        proxy_lua_ferror(L, "failed to connect to backend: %s:%s\n", be->ip, be->port);
        return 0;
    }

    luaL_getmetatable(L, "mcp.backend");
    lua_setmetatable(L, -2); // set metatable to userdata.

    lua_pushvalue(L, 1); // put the label at the top for settable later.
    lua_pushvalue(L, -2); // copy the backend reference to the top.
    // set our new backend object into the reference table.
    lua_settable(L, lua_upvalueindex(MCP_BACKEND_UPVALUE));
    // stack is back to having backend on the top.

    return 1;
}

static int mcplib_pool_gc(lua_State *L) {
    mcp_pool_t *p = luaL_checkudata(L, -1, "mcp.pool");
    assert(p->refcount == 0);
    pthread_mutex_destroy(&p->lock);

    for (int x = 0; x < p->pool_size; x++) {
        if (p->pool[x].ref) {
            luaL_unref(L, LUA_REGISTRYINDEX, p->pool[x].ref);
        }
    }

    return 0;
}

// Looks for a short string in a key to separate which part gets hashed vs
// sent to the backend node.
// ie: "foo:bar|#|restofkey" - only "foo:bar" gets hashed.
static const char *mcp_key_hash_filter_stop(const char *conf, const char *key, size_t klen, size_t *newlen) {
    char temp[KEY_MAX_LENGTH+1];
    *newlen = klen;
    if (klen > KEY_MAX_LENGTH) {
        // Hedging against potential bugs.
        return key;
    }

    memcpy(temp, key, klen);
    temp[klen+1] = '\0';

    // TODO (v2): memmem would avoid the temp key and memcpy here, but it's
    // not technically portable. An easy improvement would be to detect
    // memmem() in `configure` and only use strstr/copy as a fallback.
    // Since keys are short it's unlikely this would be a major performance
    // win.
    char *found = strstr(temp, conf);

    if (found) {
        *newlen = found - temp;
    }

    // hash stop can't change where keys start.
    return key;
}

// Takes a two character "tag", ie; "{}", or "$$", searches string for the
// first then second character. Only hashes the portion within these tags.
// *conf _must_ be two characters.
static const char *mcp_key_hash_filter_tag(const char *conf, const char *key, size_t klen, size_t *newlen) {
    *newlen = klen;

    const char *t1 = memchr(key, conf[0], klen);
    if (t1) {
        size_t remain = klen - (t1 - key);
        // must be at least one character inbetween the tags to hash.
        if (remain > 1) {
            const char *t2 = memchr(t1, conf[1], remain);

            if (t2) {
                *newlen = t2 - t1 - 1;
                return t1+1;
            }
        }
    }

    return key;
}

static void _mcplib_pool_dist(lua_State *L, mcp_pool_t *p) {
    luaL_checktype(L, -1, LUA_TTABLE);
    if (lua_getfield(L, -1, "new") != LUA_TFUNCTION) {
        proxy_lua_error(L, "key distribution object missing 'new' function");
        return;
    }

    // - now create the copy pool table
    lua_createtable(L, p->pool_size, 0); // give the new pool table a sizing hint.
    for (int x = 1; x <= p->pool_size; x++) {
        mcp_backend_t *be = p->pool[x-1].be;
        lua_createtable(L, 0, 4);
        // stack = [p, h, f, optN, newpool, backend]
        // the key should be fine for id? maybe don't need to duplicate
        // this?
        lua_pushinteger(L, x);
        lua_setfield(L, -2, "id");
        // we don't use the hostname for ketama hashing
        // so passing ip for hostname is fine
        lua_pushstring(L, be->ip);
        // FIXME: hostname should probably work...
        lua_setfield(L, -2, "hostname");
        lua_pushstring(L, be->ip);
        lua_setfield(L, -2, "addr");
        lua_pushstring(L, be->port);
        lua_setfield(L, -2, "port");
        // TODO (v2): weight/etc?

        // set the backend table into the new pool table.
        lua_rawseti(L, -2, x);
    }

    // we can either use lua_insert() or possibly _rotate to shift
    // things into the right place, but simplest is to just copy the
    // option arg to the end of the stack.
    lua_pushvalue(L, 2);
    //   - stack should be: pool, opts, func, pooltable, opts

    // call the dist new function.
    int res = lua_pcall(L, 2, 2, 0);

    if (res != LUA_OK) {
        lua_error(L); // error should be on the stack already.
        return;
    }

    // -1 is lightuserdata ptr to the struct (which must be owned by the
    // userdata), which is later used for internal calls.
    struct proxy_hash_caller *phc;

    luaL_checktype(L, -1, LUA_TLIGHTUSERDATA);
    luaL_checktype(L, -2, LUA_TUSERDATA);
    phc = lua_touserdata(L, -1);
    memcpy(&p->phc, phc, sizeof(*phc));
    lua_pop(L, 1);
    // -2 was userdata we need to hold a reference to
    p->phc_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    // UD now popped from stack.
}

// p = mcp.pool(backends, { dist = f, hashfilter = f, seed = "a", hash = f })
static int mcplib_pool(lua_State *L) {
    int argc = lua_gettop(L);
    luaL_checktype(L, 1, LUA_TTABLE);
    int n = luaL_len(L, 1); // get length of array table

    size_t plen = sizeof(mcp_pool_t) + sizeof(mcp_pool_be_t) * n;
    mcp_pool_t *p = lua_newuserdatauv(L, plen, 0);
    // Zero the memory before use, so we can realibly use __gc to clean up
    memset(p, 0, plen);
    p->pool_size = n;
    // TODO (v2): Nicer if this is fetched from mcp.default_key_hash
    p->key_hasher = XXH3_64bits_withSeed;
    pthread_mutex_init(&p->lock, NULL);
    p->ctx = settings.proxy_ctx; // TODO (v2): store ctx in upvalue.

    luaL_setmetatable(L, "mcp.pool");

    lua_pushvalue(L, -1); // dupe self for reference.
    p->self_ref = luaL_ref(L, LUA_REGISTRYINDEX);

    // remember lua arrays are 1 indexed.
    for (int x = 1; x <= n; x++) {
        mcp_pool_be_t *s = &p->pool[x-1];
        lua_geti(L, 1, x); // get next server into the stack.
        // If we bail here, the pool _gc() should handle releasing any backend
        // references we made so far.
        s->be = luaL_checkudata(L, -1, "mcp.backend");
        s->ref = luaL_ref(L, LUA_REGISTRYINDEX); // references and pops object.
    }

    if (argc == 1) {
        lua_getglobal(L, "mcp");
        // TODO (v2): decide on a mcp.default_dist and use that instead
        if (lua_getfield(L, -1, "dist_jump_hash") != LUA_TNIL) {
            _mcplib_pool_dist(L, p);
            lua_pop(L, 1); // pop "dist_jump_hash" value.
        } else {
            lua_pop(L, 1);
        }
        lua_pop(L, 1); // pop "mcp"
        return 1;
    }

    // Supplied with an options table. We inspect this table to decorate the
    // pool, then pass it along to the a constructor if necessary.
    luaL_checktype(L, 2, LUA_TTABLE);

    // stack: backends, options, mcp.pool
    if (lua_getfield(L, 2, "dist") != LUA_TNIL) {
        // overriding the distribution function.
        _mcplib_pool_dist(L, p);
        lua_pop(L, 1); // remove the dist table from stack.
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (lua_getfield(L, 2, "filter") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TSTRING);
        const char *f_type = lua_tostring(L, -1);
        if (strcmp(f_type, "stop") == 0) {
            p->key_filter = mcp_key_hash_filter_stop;
        } else if (strcmp(f_type, "tags") == 0) {
            p->key_filter = mcp_key_hash_filter_tag;
        } else {
            proxy_lua_ferror(L, "unknown hash filter specified: %s\n", f_type);
        }

        lua_pop(L, 1); // pops "filter" value.

        if (lua_getfield(L, 2, "filter_conf") == LUA_TSTRING) {
            size_t len = 0;
            const char *conf = lua_tolstring(L, -1, &len);
            if (len < 2 || len > KEY_HASH_FILTER_MAX) {
                proxy_lua_ferror(L, "hash filter conf must be between 2 and %d characters", KEY_HASH_FILTER_MAX);
            }

            memcpy(p->key_filter_conf, conf, len);
            p->key_filter_conf[len+1] = '\0';
        } else {
            proxy_lua_error(L, "hash filter requires 'filter_conf' string");
        }
        lua_pop(L, 1); // pops "filter_conf" value.
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (lua_getfield(L, 2, "hash") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TLIGHTUSERDATA);
        struct proxy_hash_func *phf = lua_touserdata(L, -1);
        p->key_hasher = phf->func;
        lua_pop(L, 1);
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (lua_getfield(L, 2, "seed") != LUA_TNIL) {
        luaL_checktype(L, -1, LUA_TSTRING);
        size_t seedlen;
        const char *seedstr = lua_tolstring(L, -1, &seedlen);
        // Note: the custom hasher for a dist may be "weird" in some cases, so
        // we use a standard hash method for the seed here.
        // I'm open to changing this (ie; mcp.pool_seed_hasher = etc)
        p->hash_seed = XXH3_64bits(seedstr, seedlen);

        lua_pop(L, 1);
    } else {
        lua_pop(L, 1); // pop the nil.
    }

    if (p->phc.selector_func == NULL) {
        proxy_lua_error(L, "cannot create pool missing 'dist' argument");
    }

    return 1;
}

static int mcplib_pool_proxy_gc(lua_State *L) {
    mcp_pool_proxy_t *pp = luaL_checkudata(L, -1, "mcp.pool_proxy");
    mcp_pool_t *p = pp->main;
    pthread_mutex_lock(&p->lock);
    p->refcount--;
    if (p->refcount == 0) {
        proxy_ctx_t *ctx = p->ctx;
        pthread_mutex_lock(&ctx->manager_lock);
        STAILQ_INSERT_TAIL(&ctx->manager_head, p, next);
        pthread_cond_signal(&ctx->manager_cond);
        pthread_mutex_unlock(&ctx->manager_lock);
    }
    pthread_mutex_unlock(&p->lock);

    return 0;
}

static mcp_backend_t *_mcplib_pool_proxy_call_helper(lua_State *L, mcp_pool_t *p, const char *key, size_t len) {
    if (p->key_filter) {
        key = p->key_filter(p->key_filter_conf, key, len, &len);
        P_DEBUG("%s: filtered key for hashing (%.*s)\n", __func__, (int)len, key);
    }
    uint64_t hash = p->key_hasher(key, len, p->hash_seed);
    uint32_t lookup = p->phc.selector_func(hash, p->phc.ctx);

    assert(p->phc.ctx != NULL);
    // attach the backend to the request object.
    // the lua modules should "think" in 1 based indexes, so we need to
    // subtract one here.
    if (lookup >= p->pool_size) {
        proxy_lua_error(L, "key dist hasher tried to use out of bounds index");
    }

    return p->pool[lookup].be;
}

// hashfunc(request) -> backend(request)
// needs key from request object.
static int mcplib_pool_proxy_call(lua_State *L) {
    // internal args are the hash selector (self)
    mcp_pool_proxy_t *pp = luaL_checkudata(L, -2, "mcp.pool_proxy");
    mcp_pool_t *p = pp->main;
    // then request object.
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");

    // we have a fast path to the key/length.
    if (!rq->pr.keytoken) {
        proxy_lua_error(L, "cannot route commands without key");
        return 0;
    }
    const char *key = MCP_PARSER_KEY(rq->pr);
    size_t len = rq->pr.klen;
    rq->be = _mcplib_pool_proxy_call_helper(L, p, key, len);

    // now yield request, pool up.
    return lua_yield(L, 2);
}

static int mcplib_backend_failure_limit(lua_State *L) {
    int limit = luaL_checkinteger(L, -1);
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    if (limit < 0) {
        proxy_lua_error(L, "backend_failure_limit must be >= 0");
        return 0;
    }

    STAT_L(ctx);
    ctx->tunables.backend_failure_limit = limit;
    STAT_UL(ctx);

    return 0;
}

// sad, I had to look this up...
#define NANOSECONDS(x) ((x) * 1E9 + 0.5)
#define MICROSECONDS(x) ((x) * 1E6 + 0.5)

static int mcplib_backend_connect_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    STAT_L(ctx);
    ctx->tunables.connect.tv_sec = secondsi;
    ctx->tunables.connect.tv_usec = MICROSECONDS(subseconds);
#ifdef HAVE_LIBURING
    ctx->tunables.connect_ur.tv_sec = secondsi;
    ctx->tunables.connect_ur.tv_nsec = NANOSECONDS(subseconds);
#endif
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_retry_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    STAT_L(ctx);
    ctx->tunables.retry.tv_sec = secondsi;
    ctx->tunables.retry.tv_usec = MICROSECONDS(subseconds);
#ifdef HAVE_LIBURING
    ctx->tunables.retry_ur.tv_sec = secondsi;
    ctx->tunables.retry_ur.tv_nsec = NANOSECONDS(subseconds);
#endif
    STAT_UL(ctx);

    return 0;
}

static int mcplib_backend_read_timeout(lua_State *L) {
    lua_Number secondsf = luaL_checknumber(L, -1);
    lua_Integer secondsi = (lua_Integer) secondsf;
    lua_Number subseconds = secondsf - secondsi;
    proxy_ctx_t *ctx = settings.proxy_ctx; // FIXME (v2): get global ctx reference in thread/upvalue.

    STAT_L(ctx);
    ctx->tunables.read.tv_sec = secondsi;
    ctx->tunables.read.tv_usec = MICROSECONDS(subseconds);
#ifdef HAVE_LIBURING
    ctx->tunables.read_ur.tv_sec = secondsi;
    ctx->tunables.read_ur.tv_nsec = NANOSECONDS(subseconds);
#endif
    STAT_UL(ctx);

    return 0;
}

// mcp.attach(mcp.HOOK_NAME, function)
// fill hook structure: if lua function, use luaL_ref() to store the func
static int mcplib_attach(lua_State *L) {
    // Pull the original worker thread out of the shared mcplib upvalue.
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));

    int hook = luaL_checkinteger(L, -2);
    // pushvalue to dupe func and etc.
    // can leave original func on stack afterward because it'll get cleared.
    int loop_end = 0;
    int loop_start = 1;
    if (hook == CMD_ANY) {
        // if CMD_ANY we need individually set loop 1 to CMD_SIZE.
        loop_end = CMD_SIZE;
    } else if (hook == CMD_ANY_STORAGE) {
        // if CMD_ANY_STORAGE we only override get/set/etc.
        loop_end = CMD_END_STORAGE;
    } else {
        loop_start = hook;
        loop_end = hook + 1;
    }

    if (lua_isfunction(L, -1)) {
        struct proxy_hook *hooks = t->proxy_hooks;

        for (int x = loop_start; x < loop_end; x++) {
            struct proxy_hook *h = &hooks[x];
            lua_pushvalue(L, -1); // duplicate the function for the ref.
            if (h->lua_ref) {
                // remove existing reference.
                luaL_unref(L, LUA_REGISTRYINDEX, h->lua_ref);
            }

            // pops the function from the stack and leaves us a ref. for later.
            h->lua_ref = luaL_ref(L, LUA_REGISTRYINDEX);
            h->is_lua = true;
        }
    } else {
        proxy_lua_error(L, "Must pass a function to mcp.attach");
        return 0;
    }

    return 0;
}

static void proxy_register_defines(lua_State *L) {
#define X(x) \
    lua_pushinteger(L, x); \
    lua_setfield(L, -2, #x);

    X(P_OK);
    X(CMD_ANY);
    X(CMD_ANY_STORAGE);
    CMD_FIELDS
#undef X
}

/*** REQUEST PARSER AND OBJECT ***/

#define PARSER_MAXLEN USHRT_MAX-1

// Find the starting offsets of each token; ignoring length.
// This creates a fast small (<= cacheline) index into the request,
// where we later scan or directly feed data into API's.
static int _process_tokenize(mcp_parser_t *pr, const size_t max) {
    const char *s = pr->request;
    int len = pr->reqlen - 2;

    // since multigets can be huge, we can't purely judge reqlen against this
    // limit, but we also can't index past it since the tokens are shorts.
    if (len > PARSER_MAXLEN) {
        len = PARSER_MAXLEN;
    }
    const char *end = s + len;
    int curtoken = 0;

    int state = 0;
    while (s != end) {
        switch (state) {
            case 0:
                if (*s != ' ') {
                    pr->tokens[curtoken] = s - pr->request;
                    if (++curtoken == max) {
                        goto endloop;
                    }
                    state = 1;
                }
                s++;
                break;
            case 1:
                if (*s != ' ') {
                    s++;
                } else {
                    state = 0;
                }
                break;
        }
    }
endloop:

    pr->ntokens = curtoken;
    P_DEBUG("%s: cur_tokens: %d\n", __func__, curtoken);

    return 0;
}

static int _process_token_len(mcp_parser_t *pr, size_t token) {
    const char *cur = pr->request + pr->tokens[token];
    int remain = pr->reqlen - pr->tokens[token] - 2; // CRLF

    const char *s = memchr(cur, ' ', remain);
    return (s != NULL) ? s - cur : remain;
}

static int _process_request_key(mcp_parser_t *pr) {
    pr->klen = _process_token_len(pr, pr->keytoken);
    // advance the parser in case of multikey.
    pr->parsed = pr->tokens[pr->keytoken] + pr->klen + 1;

    if (pr->request[pr->parsed-1] == ' ') {
        P_DEBUG("%s: request_key found extra space\n", __func__);
        pr->has_space = true;
    } else {
        pr->has_space = false;
    }
    return 0;
}

// Just for ascii multiget: search for next "key" beyond where we stopped
// tokenizing before.
// Returns the offset for the next key.
static size_t _process_request_next_key(mcp_parser_t *pr) {
    const char *cur = pr->request + pr->parsed;
    int remain = pr->reqlen - pr->parsed - 2;

    // chew off any leading whitespace.
    while (remain) {
        if (*cur == ' ') {
            remain--;
            cur++;
            pr->parsed++;
        } else {
            break;
        }
    }

    const char *s = memchr(cur, ' ', remain);
    if (s != NULL) {
        pr->klen = s - cur;
        pr->parsed += s - cur;
    } else {
        pr->klen = remain;
        pr->parsed += remain;
    }

    return cur - pr->request;
}

// for fast testing of existence of meta flags.
// meta has all flags as final tokens
static int _process_request_metaflags(mcp_parser_t *pr, int token) {
    if (pr->ntokens <= token) {
        pr->t.meta.flags = 0; // no flags found.
        return 0;
    }
    const char *cur = pr->request + pr->tokens[token];
    const char *end = pr->request + pr->reqlen - 2;

    // We blindly convert flags into bits, since the range of possible
    // flags is deliberately < 64.
    int state = 0;
    while (cur != end) {
        switch (state) {
            case 0:
                if (*cur == ' ') {
                    cur++;
                } else {
                    if (*cur < 65 || *cur > 122) {
                        return -1;
                    }
                    P_DEBUG("%s: setting meta flag: %d\n", __func__, *cur - 65);
                    pr->t.meta.flags |= 1 << (*cur - 65);
                    state = 1;
                }
                break;
            case 1:
                if (*cur != ' ') {
                    cur++;
                } else {
                    state = 0;
                }
                break;
        }
    }

    return 0;
}

// All meta commands are of form: "cm key f l a g S100"
static int _process_request_meta(mcp_parser_t *pr) {
    _process_tokenize(pr, PARSER_MAX_TOKENS);
    if (pr->ntokens < 2) {
        P_DEBUG("%s: not enough tokens for meta command: %d\n", __func__, pr->ntokens);
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    // pass the first flag token.
    return _process_request_metaflags(pr, 2);
}

// ms <key> <datalen> <flags>*\r\n
static int _process_request_mset(mcp_parser_t *pr) {
    _process_tokenize(pr, PARSER_MAX_TOKENS);
    if (pr->ntokens < 3) {
        P_DEBUG("%s: not enough tokens for meta set command: %d\n", __func__, pr->ntokens);
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    const char *cur = pr->request + pr->tokens[2];

    errno = 0;
    char *n = NULL;
    int vlen = strtol(cur, &n, 10);
    if ((errno == ERANGE) || (cur == n)) {
        return -1;
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
       return -1;
    }
    vlen += 2;

    pr->vlen = vlen;

    // pass the first flag token
    return _process_request_metaflags(pr, 3);
}

// gat[s] <exptime> <key>*\r\n
static int _process_request_gat(mcp_parser_t *pr) {
    _process_tokenize(pr, 3);
    if (pr->ntokens < 3) {
        P_DEBUG("%s: not enough tokens for GAT: %d\n", __func__, pr->ntokens);
        return -1;
    }

    pr->keytoken = 2;
    _process_request_key(pr);
    return 0;
}

// we need t find the bytes supplied immediately so we can read the request
// from the client properly.
// set <key> <flags> <exptime> <bytes> [noreply]\r\n
static int _process_request_storage(mcp_parser_t *pr, size_t max) {
    _process_tokenize(pr, max);
    if (pr->ntokens < 5) {
        P_DEBUG("%s: not enough tokens to storage command: %d\n", __func__, pr->ntokens);
        return -1;
    }
    pr->keytoken = 1;
    _process_request_key(pr);

    errno = 0;
    char *n = NULL;
    const char *cur = pr->request + pr->tokens[4];

    int vlen = strtol(cur, &n, 10);
    if ((errno == ERANGE) || (cur == n)) {
        return -1;
    }

    if (vlen < 0 || vlen > (INT_MAX - 2)) {
       return -1;
    }
    vlen += 2;

    pr->vlen = vlen;

    return 0;
}

// common request with key: <cmd> <key> <args>
static int _process_request_simple(mcp_parser_t *pr, const size_t max) {
    _process_tokenize(pr, max);
    pr->keytoken = 1; // second token is usually the key... stupid GAT.

    _process_request_key(pr);
    return 0;
}

// TODO: return code ENUM with error types.
// FIXME: the mcp_parser_t bits have ended up being more fragile than I hoped.
// careful zero'ing is required. revisit?
// I think this mostly refers to recursive work (maybe just multiget?)
// Is a parser object run throgh process_request() twice, ever?
static int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen) {
    // we want to "parse in place" as much as possible, which allows us to
    // forward an unmodified request without having to rebuild it.

    const char *cm = command;
    size_t cl = 0;
    // min command length is 2, plus the "\r\n"
    if (cmdlen < 4) {
        return -1;
    }

    const char *s = memchr(command, ' ', cmdlen-2);
    if (s != NULL) {
        cl = s - command;
    } else {
        cl = cmdlen - 2;
    }
    pr->keytoken = 0;
    pr->has_space = false;
    pr->parsed = cl + 1;
    pr->request = command;
    pr->reqlen = cmdlen;
    int token_max = PARSER_MAX_TOKENS;

    int cmd = -1;
    int type = CMD_TYPE_GENERIC;
    int ret = 0;

    switch (cl) {
        case 0:
        case 1:
            // falls through with cmd as -1. should error.
            break;
        case 2:
            if (cm[0] == 'm') {
                switch (cm[1]) {
                    case 'g':
                        cmd = CMD_MG;
                        ret = _process_request_meta(pr);
                        break;
                    case 's':
                        cmd = CMD_MS;
                        ret = _process_request_mset(pr);
                        break;
                    case 'd':
                        cmd = CMD_MD;
                        ret = _process_request_meta(pr);
                        break;
                    case 'n':
                        // TODO: do we route/handle NOP's at all?
                        // they should simply reflect to the client.
                        cmd = CMD_MN;
                        break;
                    case 'a':
                        cmd = CMD_MA;
                        ret = _process_request_meta(pr);
                        break;
                    case 'e':
                        cmd = CMD_ME;
                        // TODO: not much special processing here; binary keys
                        ret = _process_request_meta(pr);
                        break;
                }
            }
            break;
        case 3:
            if (cm[0] == 'g') {
                if (cm[1] == 'e' && cm[2] == 't') {
                    cmd = CMD_GET;
                    type = CMD_TYPE_GET;
                    token_max = 2; // don't chew through multigets.
                    ret = _process_request_simple(pr, 2);
                }
                if (cm[1] == 'a' && cm[2] == 't') {
                    type = CMD_TYPE_GET;
                    cmd = CMD_GAT;
                    token_max = 2; // don't chew through multigets.
                    ret = _process_request_gat(pr);
                }
            } else if (cm[0] == 's' && cm[1] == 'e' && cm[2] == 't') {
                cmd = CMD_SET;
                ret = _process_request_storage(pr, token_max);
            } else if (cm[0] == 'a' && cm[1] == 'd' && cm[2] == 'd') {
                cmd = CMD_ADD;
                ret = _process_request_storage(pr, token_max);
            } else if (cm[0] == 'c' && cm[1] == 'a' && cm[2] == 's') {
                cmd = CMD_CAS;
                ret = _process_request_storage(pr, token_max);
            }
            break;
        case 4:
            if (strncmp(cm, "gets", 4) == 0) {
                cmd = CMD_GETS;
                type = CMD_TYPE_GET;
                token_max = 2; // don't chew through multigets.
                ret = _process_request_simple(pr, 2);
            } else if (strncmp(cm, "incr", 4) == 0) {
                cmd = CMD_INCR;
                ret = _process_request_simple(pr, 4);
            } else if (strncmp(cm, "decr", 4) == 0) {
                cmd = CMD_DECR;
                ret = _process_request_simple(pr, 4);
            } else if (strncmp(cm, "gats", 4) == 0) {
                cmd = CMD_GATS;
                type = CMD_TYPE_GET;
                ret = _process_request_gat(pr);
            } else if (strncmp(cm, "quit", 4) == 0) {
                cmd = CMD_QUIT;
            }
            break;
        case 5:
            if (strncmp(cm, "touch", 5) == 0) {
                cmd = CMD_TOUCH;
                ret = _process_request_simple(pr, 4);
            } else if (strncmp(cm, "stats", 5) == 0) {
                cmd = CMD_STATS;
                // Don't process a key; fetch via arguments.
                _process_tokenize(pr, token_max);
            } else if (strncmp(cm, "watch", 5) == 0) {
                cmd = CMD_WATCH;
                _process_tokenize(pr, token_max);
            }
            break;
        case 6:
            if (strncmp(cm, "delete", 6) == 0) {
                cmd = CMD_DELETE;
                ret = _process_request_simple(pr, 4);
            } else if (strncmp(cm, "append", 6) == 0) {
                cmd = CMD_APPEND;
                ret = _process_request_storage(pr, token_max);
            }
            break;
        case 7:
            if (strncmp(cm, "replace", 7) == 0) {
                cmd = CMD_REPLACE;
                ret = _process_request_storage(pr, token_max);
            } else if (strncmp(cm, "prepend", 7) == 0) {
                cmd = CMD_PREPEND;
                ret = _process_request_storage(pr, token_max);
            } else if (strncmp(cm, "version", 7) == 0) {
                cmd = CMD_VERSION;
                _process_tokenize(pr, token_max);
            }
            break;
    }

    // TODO: log more specific error code.
    if (cmd == -1 || ret != 0) {
        return -1;
    }

    pr->command = cmd;
    pr->cmd_type = type;

    return 0;
}

// FIXME (v2): any reason to pass in command/cmdlen separately?
static mcp_request_t *mcp_new_request(lua_State *L, mcp_parser_t *pr, const char *command, size_t cmdlen) {
    // reserving an upvalue for key.
    mcp_request_t *rq = lua_newuserdatauv(L, sizeof(mcp_request_t) + MCP_REQUEST_MAXLEN * 2 + KEY_MAX_LENGTH, 1);
    // TODO (v2): memset only the non-data part? as the rest gets memcpy'd
    // over.
    memset(rq, 0, sizeof(mcp_request_t));
    memcpy(&rq->pr, pr, sizeof(*pr));

    memcpy(rq->request, command, cmdlen);
    rq->pr.request = rq->request;
    rq->pr.reqlen = cmdlen;
    gettimeofday(&rq->start, NULL);

    luaL_getmetatable(L, "mcp.request");
    lua_setmetatable(L, -2);

    // at this point we should know if we have to bounce through _nread to
    // get item data or not.
    return rq;
}

// TODO (v2):
// if modified, this will re-serialize every time it's accessed.
// a simple opt could copy back over the original space
// a "better" one could A/B the request ptr and clear the modified state
// each time it gets serialized.
static void mcp_request_attach(lua_State *L, mcp_request_t *rq, io_pending_proxy_t *p) {
    mcp_parser_t *pr = &rq->pr;
    char *r = (char *) pr->request;
    size_t len = pr->reqlen;

    // one or more of the tokens were changed
    if (rq->was_modified) {
        assert(rq->tokent_ref);
        // option table to top of stack.
        lua_rawgeti(L, LUA_REGISTRYINDEX, rq->tokent_ref);

        // space was reserved in case of modification.
        char *nr = rq->request + MCP_REQUEST_MAXLEN;
        r = nr;
        char *or = NULL;

        for (int x = 0; x < pr->ntokens; x++) {
            const char *newtok = NULL;
            size_t newlen = 0;
            if (x != 0 && x != pr->keytoken) {
                int type = lua_rawgeti(L, -1, x+1);
                if (type != LUA_TNIL) {
                    newtok = lua_tolstring(L, -1, &newlen);
                    memcpy(nr, newtok, newlen);
                    nr += newlen;
                }
                lua_pop(L, 1);
            }

            if (newtok == NULL) {
                // TODO (v2): if we add an extra "end" token that's just reqlen we can
                // memcpy... however most args are short and that may not be worth
                // it.
                or = rq->request + pr->tokens[x];
                // will walk past the end without the \r test.
                // if we add the end token trick this can be changed.
                while (*or != ' ' && *or != '\r' && *or != '\n') {
                    *nr = *or;
                    nr++;
                    or++;
                }
            }
            *nr = ' ';
            nr++;
        }
        // tag the end bits.
        memcpy(nr-1, "\r\n\0", 3);
        nr++;

        len = nr - (rq->request + MCP_REQUEST_MAXLEN);
        lua_pop(L, 1); // pop the table
    }

    // The stringified request. This is also referencing into the coroutine
    // stack, which should be safe from gc.
    p->iov[0].iov_base = r;
    p->iov[0].iov_len = len;
    p->iovcnt = 1;
    p->iovbytes = len;
    if (pr->vlen != 0) {
        p->iov[1].iov_base = pr->vbuf;
        p->iov[1].iov_len = pr->vlen;
        p->iovcnt = 2;
        p->iovbytes += pr->vlen;
    }

}

// second argument is optional, for building set requests.
// TODO: append the \r\n for the VAL?
static int mcplib_request(lua_State *L) {
    size_t len = 0;
    size_t vlen = 0;
    mcp_parser_t pr = {0};
    const char *cmd = luaL_checklstring(L, 1, &len);
    const char *val = luaL_optlstring(L, 2, NULL, &vlen);

    // FIXME (v2): if we inline the userdata we can avoid memcpy'ing the parser
    // structure from the stack? but causes some code duplication.
    if (process_request(&pr, cmd, len) != 0) {
        proxy_lua_error(L, "failed to parse request");
        return 0;
    }
    mcp_request_t *rq = mcp_new_request(L, &pr, cmd, len);

    if (val != NULL) {
        rq->pr.vlen = vlen;
        rq->pr.vbuf = malloc(vlen);
        if (rq->pr.vbuf == NULL) {
            // Note: without *c we can't tick the appropriate counter.
            // However, in practice raw malloc's are nearly never going to
            // fail.
            // TODO(v2): we can stack values into the request objects or use
            // the slabber memory, so this isn't necessary anyway.
            proxy_lua_error(L, "failed to allocate value memory for request object");
        }
        memcpy(rq->pr.vbuf, val, vlen);
    }
    gettimeofday(&rq->start, NULL);

    // rq is now created, parsed, and on the stack.
    return 1;
}

static int mcplib_request_key(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    lua_pushlstring(L, MCP_PARSER_KEY(rq->pr), rq->pr.klen);
    return 1;
}

// NOTE: I've mixed up const/non-const strings in the request. During parsing
// we want it to be const, but after that's done the request is no longer
// const. It might be better to just remove the const higher up the chain, but
// I'd rather not. So for now these functions will be dumping the const to
// modify the string.
static int mcplib_request_ltrimkey(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -2, "mcp.request");
    int totrim = luaL_checkinteger(L, -1);
    char *key = (char *) MCP_PARSER_KEY(rq->pr);

    if (totrim > rq->pr.klen) {
        proxy_lua_error(L, "ltrimkey cannot zero out key");
        return 0;
    } else {
        memset(key, ' ', totrim);
        rq->pr.klen -= totrim;
        rq->pr.tokens[rq->pr.keytoken] += totrim;
    }
    return 1;
}

static int mcplib_request_rtrimkey(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -2, "mcp.request");
    int totrim = luaL_checkinteger(L, -1);
    char *key = (char *) MCP_PARSER_KEY(rq->pr);

    if (totrim > rq->pr.klen) {
        proxy_lua_error(L, "rtrimkey cannot zero out key");
        return 0;
    } else {
        memset(key + (rq->pr.klen - totrim), ' ', totrim);
        rq->pr.klen -= totrim;
        // don't need to change the key token.
    }
    return 1;
}

// Virtual table operations on the request.
static int mcplib_request_token(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    int argc = lua_gettop(L);

    if (argc == 1) {
        lua_pushnil(L);
        return 1;
    }

    int token = luaL_checkinteger(L, 2);

    if (token < 1 || token > rq->pr.ntokens) {
        // maybe an error?
        lua_pushnil(L);
        return 1;
    }

    // we hold overwritten or parsed tokens in a lua table.
    if (rq->tokent_ref == 0) {
        // create a presized table that can hold our tokens.
        lua_createtable(L, rq->pr.ntokens, 0);
        // duplicate value to set back
        lua_pushvalue(L, -1);
        rq->tokent_ref = luaL_ref(L, LUA_REGISTRYINDEX);
    } else {
        lua_rawgeti(L, LUA_REGISTRYINDEX, rq->tokent_ref);
    }
    // top of stack should be token table.

    size_t vlen = 0;
    if (argc > 2) {
        // overwriting a token.
        luaL_checklstring(L, 3, &vlen);
        lua_pushvalue(L, 3); // copy to top of stack
        lua_rawseti(L, -2, token);
        rq->was_modified = true;
        return 0;
    } else {
        // fetching a token.
        if (lua_rawgeti(L, -1, token) != LUA_TSTRING) {
            lua_pop(L, 1); // got a nil, drop it.

            // token not uploaded yet. find the len.
            char *s = (char *) &rq->pr.request[rq->pr.tokens[token-1]];
            char *e = s;
            while (*e != ' ') {
                e++;
            }
            vlen = e - s;

            P_DEBUG("%s: pushing token of len: %lu\n", __func__, vlen);
            lua_pushlstring(L, s, vlen);
            lua_pushvalue(L, -1); // copy

            lua_rawseti(L, -3, token); // pops copy.
        }

        // return fetched token or copy of new token.
        return 1;
    }

    return 0;
}

static int mcplib_request_ntokens(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    lua_pushinteger(L, rq->pr.ntokens);
    return 1;
}

static int mcplib_request_command(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    lua_pushinteger(L, rq->pr.command);
    return 1;
}

static int mcplib_request_gc(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, -1, "mcp.request");
    // During nread c->item is the malloc'ed buffer. not yet put into
    // rq->buf - this gets freed because we've also set c->item_malloced if
    // the connection closes before finishing nread.
    if (rq->pr.vbuf != NULL) {
        free(rq->pr.vbuf);
    }

    if (rq->tokent_ref != 0) {
        luaL_unref(L, LUA_REGISTRYINDEX, rq->tokent_ref);
    }
    return 0;
}

// TODO (v2): check what lua does when it calls a function with a string argument
// stored from a table/similar (ie; the prefix check code).
// If it's not copying anything, we can add request-side functions to do most
// forms of matching and avoid copying the key to lua space.

/*** END REQUET PARSER AND OBJECT ***/

/*** START jump consistent hash library ***/
// TODO (v2): easy candidate for splitting to another .c, but I want this built in
// instead of as a .so so make sure it's linked directly.

typedef struct {
    struct proxy_hash_caller phc; // passed back to proxy API
    unsigned int buckets;
} mcplib_jump_hash_t;

static uint32_t mcplib_dist_jump_hash_get_server(uint64_t hash, void *ctx) {
    mcplib_jump_hash_t *jh = ctx;

    int64_t b = -1, j = 0;
    while (j < jh->buckets) {
        b = j;
        hash = hash * 2862933555777941757ULL + 1;
        j = (b + 1) * ((double)(1LL << 31) / (double)((hash >> 33) + 1));
    }
    return b;
}

// stack = [pool, option]
static int mcplib_dist_jump_hash_new(lua_State *L) {
    luaL_checktype(L, 1, LUA_TTABLE);
    lua_Unsigned buckets = lua_rawlen(L, 1);

    mcplib_jump_hash_t *jh = lua_newuserdatauv(L, sizeof(mcplib_jump_hash_t), 0);

    // don't need to loop through the table at all, just need its length.
    // could optimize startup time by adding hints to the module for how to
    // format pool (ie; just a total count or the full table)
    jh->buckets = buckets;
    jh->phc.ctx = jh;
    jh->phc.selector_func = mcplib_dist_jump_hash_get_server;

    lua_pushlightuserdata(L, &jh->phc);

    // - return [UD, lightuserdata]
    return 2;
}

static int mcplib_open_dist_jump_hash(lua_State *L) {
    const struct luaL_Reg jump_f[] = {
        {"new", mcplib_dist_jump_hash_new},
        {NULL, NULL},
    };

    luaL_newlib(L, jump_f);

    return 1;
}

/*** END jump consistent hash library ***/

/*** START lua interface to user stats ***/

// mcp.add_stat(index, name)
// creates a custom lua stats counter
static int mcplib_add_stat(lua_State *L) {
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));
    if (t != NULL) {
        proxy_lua_error(L, "add_stat must be called from config_pools");
        return 0;
    }
    int idx = luaL_checkinteger(L, -2);
    const char *name = luaL_checkstring(L, -1);

    if (idx < 1) {
        proxy_lua_error(L, "stat index must be 1 or higher");
        return 0;
    }
    // max user counters? 1024? some weird number.
    if (idx > 1024) {
        proxy_lua_error(L, "stat index must be 1024 or less");
        return 0;
    }
    // max name length? avoids errors if something huge gets thrown in.
    if (strlen(name) > STAT_KEY_LEN - 6) {
        // we prepend "user_" to the output. + null byte.
        proxy_lua_ferror(L, "stat name too long: %s\n", name);
        return 0;
    }
    // restrict characters, at least no spaces/newlines.
    for (int x = 0; x < strlen(name); x++) {
        if (isspace(name[x])) {
            proxy_lua_error(L, "stat cannot contain spaces or newlines");
            return 0;
        }
    }

    proxy_ctx_t *ctx = settings.proxy_ctx; // TODO (v2): store ctx in upvalue.

    STAT_L(ctx);
    struct proxy_user_stats *us = &ctx->user_stats;

    // if num_stats is 0 we need to init sizes.
    // TODO (v2): malloc fail checking. (should be rare/impossible)
    if (us->num_stats < idx) {
        // don't allocate counters memory for the global ctx.
        char **nnames = calloc(idx, sizeof(char *));
        if (us->names != NULL) {
            for (int x = 0; x < us->num_stats; x++) {
                nnames[x] = us->names[x];
            }
            free(us->names);
        }
        us->names = nnames;
        us->num_stats = idx;
    }

    idx--; // real slot start as 0.
    // if slot has string in it, free first
    if (us->names[idx] != NULL) {
        free(us->names[idx]);
    }
    // strdup name into string slot
    // TODO (v2): malloc failure.
    us->names[idx] = strdup(name);
    STAT_UL(ctx);

    return 0;
}

static int mcplib_stat(lua_State *L) {
    LIBEVENT_THREAD *t = lua_touserdata(L, lua_upvalueindex(MCP_THREAD_UPVALUE));
    if (t == NULL) {
        proxy_lua_error(L, "stat must be called from router handlers");
        return 0;
    }

    struct proxy_user_stats *tus = t->proxy_stats;
    if (tus == NULL) {
        proxy_lua_error(L, "no stats counters initialized");
        return 0;
    }

    int idx = luaL_checkinteger(L, -2);
    int change = luaL_checkinteger(L, -1);

    if (idx < 1 || idx > tus->num_stats) {
        proxy_lua_error(L, "stat index out of range");
        return 0;
    }

    idx--; // actual array is 0 indexed.
    WSTAT_L(t);
    tus->counters[idx] += change;
    WSTAT_UL(t);

    return 0;
}

/*** END lua interface to user stats ***/

/*** START lua await() object interface ***/

typedef struct mcp_await_s {
    int pending;
    int wait_for;
    int req_ref;
    int argtable_ref; // need to hold refs to any potential hash selectors
    int restable_ref; // table of result objects
    int coro_ref; // reference to parent coroutine
    bool completed; // have we completed the parent coroutine or not
    mcp_request_t *rq;
    mc_resp *resp; // the top level mc_resp to fill in (as if we were an iop)
} mcp_await_t;

// local restable = mcp.await(request, pools, num_wait)
// NOTE: need to hold onto the pool objects since those hold backend
// references. Here we just keep a reference to the argument table.
static int mcplib_await(lua_State *L) {
    mcp_request_t *rq = luaL_checkudata(L, 1, "mcp.request");
    luaL_checktype(L, 2, LUA_TTABLE);
    int n = luaL_len(L, 2); // length of hash selector table
    int wait_for = 0; // 0 means wait for all responses

    if (n <= 0) {
        proxy_lua_error(L, "mcp.await arguments must have at least one pool");
    }
    if (lua_isnumber(L, 3)) {
        wait_for = lua_tointeger(L, 3);
        lua_pop(L, 1);
        if (wait_for > n) {
            wait_for = n;
        }
    }

    // TODO (v2): quickly loop table once and ensure they're all pools?
    int argtable_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops the arg table
    int req_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pops request object.

    // stack will be only the await object now
    mcp_await_t *aw = lua_newuserdatauv(L, sizeof(mcp_await_t), 0);
    memset(aw, 0, sizeof(mcp_await_t));
    aw->wait_for = wait_for;
    aw->pending = n;
    aw->argtable_ref = argtable_ref;
    aw->rq = rq;
    aw->req_ref = req_ref;
    P_DEBUG("%s: about to yield [HS len: %d]\n", __func__, n);
    //dump_stack(L);

    return lua_yield(L, 1);
}

static void mcp_queue_await_io(conn *c, lua_State *Lc, mcp_request_t *rq, int await_ref) {
    io_queue_t *q = conn_io_queue_get(c, IO_QUEUE_PROXY);

    mcp_backend_t *be = rq->be;

    // Then we push a response object, which we'll re-use later.
    // reserve one uservalue for a lua-supplied response.
    mcp_resp_t *r = lua_newuserdatauv(Lc, sizeof(mcp_resp_t), 1);
    if (r == NULL) {
        proxy_lua_error(Lc, "out of memory allocating response");
        return;
    }
    memset(r, 0, sizeof(mcp_resp_t));
    r->buf = NULL;
    r->blen = 0;
    r->start = rq->start;
    int x;
    int end = rq->pr.reqlen-2 > RESP_CMD_MAX ? RESP_CMD_MAX : rq->pr.reqlen-2;
    for (x = 0; x < end; x++) {
        if (rq->pr.request[x] == ' ') {
            break;
        }
        r->cmd[x] = rq->pr.request[x];
    }
    r->cmd[x] = '\0';

    luaL_getmetatable(Lc, "mcp.response");
    lua_setmetatable(Lc, -2);

    io_pending_proxy_t *p = do_cache_alloc(c->thread->io_cache);
    if (p == NULL) {
        WSTAT_INCR(c, proxy_conn_oom, 1);
        proxy_lua_error(Lc, "out of memory allocating from IO cache");
        return;
    }

    // this is a re-cast structure, so assert that we never outsize it.
    assert(sizeof(io_pending_t) >= sizeof(io_pending_proxy_t));
    memset(p, 0, sizeof(io_pending_proxy_t));
    // set up back references.
    p->io_queue_type = IO_QUEUE_PROXY;
    p->thread = c->thread;
    p->c = c;
    p->resp = NULL;
    p->client_resp = r;
    p->flushed = false;
    p->ascii_multiget = rq->ascii_multiget;

    // io_p needs to hold onto its own response reference, because we may or
    // may not include it in the final await() result.
    p->mcpres_ref = luaL_ref(Lc, LUA_REGISTRYINDEX); // pops mcp.response

    // avoiding coroutine reference for sub-IO
    p->coro_ref = 0;
    p->coro = NULL;

    // await specific
    p->is_await = true;
    p->await_ref = await_ref;

    // The direct backend object. await object is holding reference
    p->backend = be;

    mcp_request_attach(Lc, rq, p);

    // link into the batch chain.
    p->next = q->stack_ctx;
    q->stack_ctx = p;
    P_DEBUG("%s: queued\n", __func__);

    return;
}

static int mcplib_await_run(conn *c, lua_State *L, int coro_ref) {
    P_DEBUG("%s: start\n", __func__);
    mcp_await_t *aw = lua_touserdata(L, -1);
    int await_ref = luaL_ref(L, LUA_REGISTRYINDEX); // await is popped.
    assert(aw != NULL);
    lua_rawgeti(L, LUA_REGISTRYINDEX, aw->argtable_ref); // -> 1
    //dump_stack(L);
    P_DEBUG("%s: argtable len: %d\n", __func__, (int)lua_rawlen(L, -1));
    mcp_request_t *rq = aw->rq;
    aw->coro_ref = coro_ref;

    // create result table
    lua_newtable(L); // -> 2
    aw->restable_ref = luaL_ref(L, LUA_REGISTRYINDEX); // pop the result table

    // prepare the request key
    const char *key = MCP_PARSER_KEY(rq->pr);
    size_t len = rq->pr.klen;
    // loop arg table and run each hash selector
    lua_pushnil(L); // -> 3
    while (lua_next(L, 1) != 0) {
        P_DEBUG("%s: top of loop\n", __func__);
        // (key, -2), (val, -1)
        mcp_pool_proxy_t *pp = luaL_testudata(L, -1, "mcp.pool_proxy");
        if (pp == NULL) {
            proxy_lua_error(L, "mcp.await must be supplied with a pool");
        }
        mcp_pool_t *p = pp->main;

        // NOTE: rq->be is only held to help pass the backend into the IOP in
        // mcp_queue call. Could be a local variable and an argument too.
        rq->be = _mcplib_pool_proxy_call_helper(L, p, key, len);

        mcp_queue_await_io(c, L, rq, await_ref);

        // pop value, keep key.
        lua_pop(L, 1);
    }

    lua_pop(L, 1); // remove table key.
    aw->resp = c->resp; // cuddle the current mc_resp to fill later

    // we count the await as the "response pending" since it covers a single
    // response object. the sub-IO's don't count toward the redispatch of *c
    io_queue_t *q = conn_io_queue_get(c, IO_QUEUE_PROXY);
    q->count++;

    P_DEBUG("%s\n", __func__);
    //dump_stack(L); // should be empty

    return 0;
}

//lua_rawseti(L, -2, x++);
static int mcplib_await_return(io_pending_proxy_t *p) {
    mcp_await_t *aw;
    lua_State *L = p->thread->L; // use the main VM coroutine for work
    bool cleanup = false;
    bool valid = false;
    bool completing = false;

    // TODO (v2): just push the await ptr into *p?
    lua_rawgeti(L, LUA_REGISTRYINDEX, p->await_ref);
    aw = lua_touserdata(L, -1);
    lua_pop(L, 1); // remove AW object from stack
    assert(aw != NULL);
    P_DEBUG("%s: start [pending: %d]\n", __func__, aw->pending);
    //dump_stack(L);

    aw->pending--;
    // Await not yet satisfied.
    // If wait_for != 0 check for response success
    // if success and wait_for is *now* 0, we complete.
    // add successful response to response table
    // Also, if no wait_for, add response to response table
    if (!aw->completed) {
        if (aw->wait_for > 0) {
            if (p->client_resp->status == MCMC_OK && p->client_resp->resp.code != MCMC_CODE_MISS) {
                valid = true;
            }
            aw->wait_for--;

            if (aw->wait_for == 0) {
                completing = true;
            }
        } else {
            valid = true;
        }
    }

    // note that post-completion, we stop gathering responses into the
    // resposne table... because it's already been returned.
    // So "valid" can only be true if also !completed
    if (aw->pending == 0) {
        if (!aw->completed) {
            // were waiting for all responses.
            completing = true;
        }
        cleanup = true;
        P_DEBUG("%s: pending == 0\n", __func__);
    }

    // a valid response to add to the result table.
    if (valid) {
        P_DEBUG("%s: valid\n", __func__);
        lua_rawgeti(L, LUA_REGISTRYINDEX, aw->restable_ref); // -> 1
        lua_rawgeti(L, LUA_REGISTRYINDEX, p->mcpres_ref); // -> 2
        // couldn't find a table.insert() equivalent; so this is
        // inserting into the length + 1 position manually.
        //dump_stack(L);
        lua_rawseti(L, 1, lua_rawlen(L, 1) + 1); // pops mcpres
        lua_pop(L, 1); // pops restable
    }

    // lose our internal mcpres reference regardless.
    luaL_unref(L, LUA_REGISTRYINDEX, p->mcpres_ref);
    // our await_ref is shared, so we don't need to release it.

    if (completing) {
        P_DEBUG("%s: completing\n", __func__);
        aw->completed = true;
        // if we haven't completed yet, the connection reference is still
        // valid. So now we pull it, reduce count, and readd if necessary.
        // here is also the point where we resume the coroutine.
        lua_rawgeti(L, LUA_REGISTRYINDEX, aw->coro_ref);
        lua_State *Lc = lua_tothread(L, -1);
        lua_rawgeti(Lc, LUA_REGISTRYINDEX, aw->restable_ref); // -> 1
        proxy_run_coroutine(Lc, aw->resp, NULL, p->c);
        luaL_unref(L, LUA_REGISTRYINDEX, aw->coro_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, aw->restable_ref);

        io_queue_t *q = conn_io_queue_get(p->c, p->io_queue_type);
        q->count--;
        if (q->count == 0) {
            // call re-add directly since we're already in the worker thread.
            conn_worker_readd(p->c);
        }

    }

    if (cleanup) {
        P_DEBUG("%s: cleanup [completed: %d]\n", __func__, aw->completed);
        luaL_unref(L, LUA_REGISTRYINDEX, aw->argtable_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, aw->req_ref);
        luaL_unref(L, LUA_REGISTRYINDEX, p->await_ref);
    }

    // Just remove anything we could have left on the primary VM stack
    lua_settop(L, 0);

    // always return free this sub-IO object.
    do_cache_free(p->thread->io_cache, p);

    return 0;
}

/*** END lua await() object interface ***/

/*** START xxhash module ***/

static struct proxy_hash_func mcplib_hash_xxhash = {
    XXH3_64bits_withSeed,
};

static int mcplib_open_hash_xxhash(lua_State *L) {
    lua_pushlightuserdata(L, &mcplib_hash_xxhash);
    return 1;
}

/*** END xxhash module ***/

// Creates and returns the top level "mcp" module
int proxy_register_libs(LIBEVENT_THREAD *t, void *ctx) {
    lua_State *L = ctx;

    const struct luaL_Reg mcplib_backend_m[] = {
        {"set", NULL},
        {"__gc", mcplib_backend_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_request_m[] = {
        {"command", mcplib_request_command},
        {"key", mcplib_request_key},
        {"ltrimkey", mcplib_request_ltrimkey},
        {"rtrimkey", mcplib_request_rtrimkey},
        {"token", mcplib_request_token},
        {"ntokens", mcplib_request_ntokens},
        {"__tostring", NULL},
        {"__gc", mcplib_request_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_response_m[] = {
        {"ok", mcplib_response_ok},
        {"hit", mcplib_response_hit},
        {"__gc", mcplib_response_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_pool_m[] = {
        {"__gc", mcplib_pool_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_pool_proxy_m[] = {
        {"__call", mcplib_pool_proxy_call},
        {"__gc", mcplib_pool_proxy_gc},
        {NULL, NULL}
    };

    const struct luaL_Reg mcplib_f [] = {
        {"pool", mcplib_pool},
        {"backend", mcplib_backend},
        {"request", mcplib_request},
        {"attach", mcplib_attach},
        {"add_stat", mcplib_add_stat},
        {"stat", mcplib_stat},
        {"await", mcplib_await},
        {"backend_connect_timeout", mcplib_backend_connect_timeout},
        {"backend_retry_timeout", mcplib_backend_retry_timeout},
        {"backend_read_timeout", mcplib_backend_read_timeout},
        {"backend_failure_limit", mcplib_backend_failure_limit},
        {NULL, NULL}
    };

    // TODO (v2): function + loop.
    luaL_newmetatable(L, "mcp.backend");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_backend_m, 0); // register methods
    lua_pop(L, 1);

    luaL_newmetatable(L, "mcp.request");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_request_m, 0); // register methods
    lua_pop(L, 1);

    luaL_newmetatable(L, "mcp.response");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_response_m, 0); // register methods
    lua_pop(L, 1);

    luaL_newmetatable(L, "mcp.pool");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_pool_m, 0); // register methods
    lua_pop(L, 1); // drop the hash selector metatable

    luaL_newmetatable(L, "mcp.pool_proxy");
    lua_pushvalue(L, -1); // duplicate metatable.
    lua_setfield(L, -2, "__index"); // mt.__index = mt
    luaL_setfuncs(L, mcplib_pool_proxy_m, 0); // register methods
    lua_pop(L, 1); // drop the hash selector metatable

    // create main library table.
    //luaL_newlib(L, mcplib_f);
    // TODO (v2): luaL_newlibtable() just pre-allocs the exact number of things
    // here.
    // can replace with createtable and add the num. of the constant
    // definitions.
    luaL_newlibtable(L, mcplib_f);
    proxy_register_defines(L);

    mcplib_open_hash_xxhash(L);
    lua_setfield(L, -2, "hash_xxhash");
    // hash function for selectors.
    // have to wrap the function in a struct because function pointers aren't
    // pointer pointers :)
    mcplib_open_dist_jump_hash(L);
    lua_setfield(L, -2, "dist_jump_hash");

    lua_pushlightuserdata(L, (void *)t); // upvalue for original thread
    lua_newtable(L); // upvalue for mcp.attach() table.

    // create weak table for storing backends by label.
    lua_newtable(L); // {}
    lua_newtable(L); // {}, {} for metatable
    lua_pushstring(L, "v"); // {}, {}, "v" for weak values.
    lua_setfield(L, -2, "__mode"); // {}, {__mode = "v"}
    lua_setmetatable(L, -2); // {__mt = {__mode = "v"} }

    luaL_setfuncs(L, mcplib_f, 3); // store upvalues.

    lua_setglobal(L, "mcp"); // set the lib table to mcp global.
    return 1;
}

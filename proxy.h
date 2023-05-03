#ifndef PROXY_H
#define PROXY_H

#include "memcached.h"
#include "extstore.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

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
#define WSTAT_INCR(t, stat, amount) { \
    pthread_mutex_lock(&t->stats.mutex); \
    t->stats.stat += amount; \
    pthread_mutex_unlock(&t->stats.mutex); \
}
#define WSTAT_DECR(t, stat, amount) { \
    pthread_mutex_lock(&t->stats.mutex); \
    t->stats.stat -= amount; \
    pthread_mutex_unlock(&t->stats.mutex); \
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

#define MCP_BACKEND_UPVALUE 1

#define MCP_YIELD_POOL 1
#define MCP_YIELD_AWAIT 2
#define MCP_YIELD_LOCAL 3

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
    CMD_FINAL, // end cap for convenience.
};
#undef X

// certain classes of ascii commands have similar parsing (ie;
// get/gets/gat/gats). Use types so we don't have to test a ton of them.
enum proxy_cmd_types {
    CMD_TYPE_GENERIC = 0,
    CMD_TYPE_GET, // get/gets/gat/gats
    CMD_TYPE_META, // m*'s.
};

typedef struct _io_pending_proxy_t io_pending_proxy_t;
typedef struct proxy_event_thread_s proxy_event_thread_t;

#ifdef HAVE_LIBURING
// TODO: pass in cqe->res instead of cqe?
typedef void (*proxy_event_cb)(void *udata, struct io_uring_cqe *cqe);
typedef struct {
    void *udata;
    proxy_event_cb cb;
    bool set; // NOTE: not sure if necessary if code structured properly
} proxy_event_t;

void *proxy_event_thread_ur(void *arg);
#endif

// Note: This ends up wasting a few counters, but simplifies the rest of the
// process for handling internal worker stats.
struct proxy_int_stats {
    uint64_t counters[CMD_FINAL];
};

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
    bool tcp_keepalive;
};

typedef STAILQ_HEAD(pool_head_s, mcp_pool_s) pool_head_t;
typedef struct {
    lua_State *proxy_state;
    void *proxy_code;
    proxy_event_thread_t *proxy_io_thread;
    uint64_t active_req_limit; // max total in-flight requests
    uint64_t buffer_memory_limit; // max bytes for send/receive buffers.
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
    bool loading; // bool indicating an active config load.
    struct proxy_global_stats global_stats;
    struct proxy_user_stats user_stats;
    struct proxy_tunables tunables; // NOTE: updates covered by stats_lock
    pthread_mutex_t stats_lock; // used for rare global counters
} proxy_ctx_t;

#define PROXY_GET_THR_CTX(L) ((*(LIBEVENT_THREAD **)lua_getextraspace(L))->proxy_ctx)
#define PROXY_GET_THR(L) (*(LIBEVENT_THREAD **)lua_getextraspace(L))
// Operations from the config VM don't have a libevent thread.
#define PROXY_GET_CTX(L) (*(proxy_ctx_t **)lua_getextraspace(L))

struct proxy_hook_tagged {
    uint64_t tag;
    int lua_ref;
};

struct proxy_hook {
    int lua_ref;
    int tagcount;
    struct proxy_hook_tagged *tagged; // array of possible tagged hooks.
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
    mcp_backend_next_close, // complete current request, then close socket
};

typedef struct mcp_backend_wrap_s mcp_backend_wrap_t;
typedef struct mcp_backend_label_s mcp_backend_label_t;
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
    bool noreply; // if quiet/noreply mode is set.
    union {
        struct mcp_parser_meta_s meta;
    } t;
};

#define MCP_PARSER_KEY(pr) (&pr.request[pr.tokens[pr.keytoken]])

#define MAX_REQ_TOKENS 2
struct mcp_request_s {
    mcp_parser_t pr; // non-lua-specific parser handling.
    mcp_backend_t *be; // backend handling this request.
    bool ascii_multiget; // ascii multiget mode. (hide errors/END)
    char request[];
};

typedef STAILQ_HEAD(io_head_s, _io_pending_proxy_t) io_head_t;
#define MAX_LABELLEN 512
#define MAX_NAMELEN 255
#define MAX_PORTLEN 6
// TODO (v2): IOV_MAX tends to be 1000+ which would allow for more batching but we
// don't have a good temporary space and don't want to malloc/free on every
// write. transmit() uses the stack but we can't do that for uring's use case.
#if (IOV_MAX > 1024)
#define BE_IOV_MAX 1024
#else
#define BE_IOV_MAX IOV_MAX
#endif
// lua descriptor object: passed to pools, which create wrappers.
struct mcp_backend_label_s {
    char name[MAX_NAMELEN+1];
    char port[MAX_PORTLEN+1];
    char label[MAX_LABELLEN+1];
    size_t llen; // cache label length for small speedup in pool creation.
    struct proxy_tunables tunables;
};

// lua object wrapper meant to own a malloc'ed conn structure
// when this object is created, it ships its connection to the real owner
// (worker, IO thread, etc)
// when this object is garbage collected, it ships a notice to the owner
// thread to stop using and free the backend conn memory.
struct mcp_backend_wrap_s {
    mcp_backend_t *be;
};

// FIXME: inline the mcmc client data.
// TODO: event_thread -> something? union of owner type?
struct mcp_backend_s {
    int depth; // total number of requests in queue
    int pending_read; // number of requests written to socket, pending read.
    int failed_count; // number of fails (timeouts) in a row
    proxy_event_thread_t *event_thread; // event thread owning this backend.
    void *client; // mcmc client
    STAILQ_ENTRY(mcp_backend_s) be_next; // stack for backends
    STAILQ_ENTRY(mcp_backend_s) beconn_next; // stack for connecting conns
    io_head_t io_head; // stack of requests.
    io_pending_proxy_t *io_next; // next request to write.
    char *rbuf; // statically allocated read buffer.
    size_t rbufused; // currently active bytes in the buffer
    struct event main_event; // libevent: changes role, mostly for main read events
    struct event write_event; // libevent: only used when socket wbuf full
    struct event timeout_event; // libevent: alarm for pending reads
    struct proxy_tunables tunables;
#ifdef HAVE_LIBURING
    proxy_event_t ur_rd_ev; // liburing.
    proxy_event_t ur_wr_ev; // need a separate event/cb for writing/polling
    proxy_event_t ur_te_ev; // for timeout handling
#endif
    enum mcp_backend_states state; // readback state machine
    int connect_flags; // flags to pass to mcmc_connect
    bool transferred; // if beconn has been shipped to owner thread.
    bool connecting; // in the process of an asynch connection.
    bool validating; // in process of validating a new backend connection.
    bool can_write; // recently got a WANT_WRITE or are connecting.
    bool stacked; // if backend already queued for syscalls.
    bool bad; // timed out, marked as bad.
    bool use_io_thread; // note if this backend is worker-local or not.
    struct iovec write_iovs[BE_IOV_MAX]; // iovs to stage batched writes
    char name[MAX_NAMELEN+1];
    char port[MAX_PORTLEN+1];
};
typedef STAILQ_HEAD(be_head_s, mcp_backend_s) be_head_t;
typedef STAILQ_HEAD(beconn_head_s, mcp_backend_s) beconn_head_t;

struct proxy_event_thread_s {
    pthread_t thread_id;
    struct event_base *base;
    struct event notify_event; // listen event for the notify pipe/eventfd.
    struct event beconn_event; // listener for backends in connect state
#ifdef HAVE_LIBURING
    struct io_uring ring;
    proxy_event_t ur_notify_event; // listen on eventfd.
    proxy_event_t ur_benotify_event; // listen on eventfd for backend connections.
    eventfd_t event_counter;
    eventfd_t beevent_counter;
    bool use_uring;
#endif
    pthread_mutex_t mutex; // covers stack.
    pthread_cond_t cond; // condition to wait on while stack drains.
    io_head_t io_head_in; // inbound requests to process.
    be_head_t be_head; // stack of backends for processing.
    beconn_head_t beconn_head_in; // stack of backends for connection processing.
#ifdef USE_EVENTFD
    int event_fd; // for request ingestion
    int be_event_fd; // for backend ingestion
#else
    int notify_receive_fd;
    int notify_send_fd;
    int be_notify_receive_fd;
    int be_notify_send_fd;
#endif
    proxy_ctx_t *ctx; // main context.
};

enum mcp_resp_mode {
    RESP_MODE_NORMAL = 0,
    RESP_MODE_NOREPLY,
    RESP_MODE_METAQUIET
};

#define RESP_CMD_MAX 8
typedef struct {
    mcmc_resp_t resp;
    char *buf; // response line + potentially value.
    mc_resp *cresp; // client mc_resp object during extstore fetches.
    LIBEVENT_THREAD *thread; // cresp's owner thread needed for extstore cleanup.
    size_t blen; // total size of the value to read.
    struct timeval start; // time this object was created.
    long elapsed; // time elapsed once handled.
    int status; // status code from mcmc_read()
    int bread; // amount of bytes read into value so far.
    uint8_t cmd; // from parser (pr.command)
    enum mcp_resp_mode mode; // reply mode (for noreply fixing)
    char be_name[MAX_NAMELEN+1];
    char be_port[MAX_PORTLEN+1];
} mcp_resp_t;

// re-cast an io_pending_t into this more descriptive structure.
// the first few items _must_ match the original struct.
#define IO_PENDING_TYPE_PROXY 0
#define IO_PENDING_TYPE_EXTSTORE 1
struct _io_pending_proxy_t {
    int io_queue_type;
    LIBEVENT_THREAD *thread;
    conn *c;
    mc_resp *resp;
    io_queue_cb return_cb; // called on worker thread.
    io_queue_cb finalize_cb; // called back on the worker thread.
    // original struct ends here

    int io_type; // extstore IO or backend IO
    int coro_ref; // lua registry reference to the coroutine
    lua_State *coro; // pointer directly to the coroutine
    union {
        // extstore IO.
        struct {
            obj_io eio;
            item *hdr_it;
            mc_resp *tresp; // temporary mc_resp for storage to fill.
            int gettype;
            int iovec_data;
            bool miss;
            bool badcrc;
            bool active;
        };
        // backend request IO
        struct {
            struct _io_pending_proxy_t *next; // stack for IO submission
            STAILQ_ENTRY(_io_pending_proxy_t) io_next; // stack for backends
            int mcpres_ref; // mcp.res reference used for await()
            mcp_backend_t *backend; // backend server to request from
            struct iovec iov[2]; // request string + tail buffer
            int iovcnt; // 1 or 2...
            unsigned int iovbytes; // total bytes in the iovec
            int await_ref; // lua reference if we were an await object
            mcp_resp_t *client_resp; // reference (currently pointing to a lua object)
            bool flushed; // whether we've fully written this request to a backend.
            bool ascii_multiget; // passed on from mcp_r_t
            bool is_await; // are we an await object?
            bool await_first; // are we the main route for an await object?
            bool await_background; // dummy IO for backgrounded awaits
        };
    };
};

// Note: does *be have to be a sub-struct? how stable are userdata pointers?
// https://stackoverflow.com/questions/38718475/lifetime-of-lua-userdata-pointers
// - says no.
typedef struct {
    int ref; // luaL_ref reference of backend_wrap_t obj.
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
    char beprefix[MAX_LABELLEN+1]; // TODO: should probably be shorter.
    uint64_t hash_seed; // calculated from a string.
    int refcount;
    int phc_ref;
    int self_ref; // TODO (v2): double check that this is needed.
    int pool_size;
    bool use_iothread;
    mcp_pool_be_t pool[];
};

typedef struct {
    mcp_pool_t *main; // ptr to original
    mcp_pool_be_t *pool; // ptr to main->pool starting offset for owner thread.
} mcp_pool_proxy_t;

// utils
bool proxy_bufmem_checkadd(LIBEVENT_THREAD *t, int len);

// networking interface
void proxy_init_event_thread(proxy_event_thread_t *t, proxy_ctx_t *ctx, struct event_base *base);
void *proxy_event_thread(void *arg);
void proxy_run_backend_queue(be_head_t *head);

// await interface
enum mcp_await_e {
    AWAIT_GOOD = 0, // looks for OK + NOT MISS
    AWAIT_ANY, // any response, including errors,
    AWAIT_OK, // any non-error response
    AWAIT_FIRST, // return the result from the first pool
    AWAIT_FASTGOOD, // returns on first hit or majority non-error
    AWAIT_BACKGROUND, // returns as soon as background jobs are dispatched
};
int mcplib_await(lua_State *L);
int mcplib_await_logerrors(lua_State *L);
int mcplib_await_run(conn *c, mc_resp *resp, lua_State *L, int coro_ref);
int mcplib_await_return(io_pending_proxy_t *p);

// internal request interface
int mcplib_internal(lua_State *L);
int mcplib_internal_run(lua_State *L, conn *c, mc_resp *top_resp, int coro_ref);

// user stats interface
int mcplib_add_stat(lua_State *L);
int mcplib_stat(lua_State *L);
size_t _process_request_next_key(mcp_parser_t *pr);
int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen);
mcp_request_t *mcp_new_request(lua_State *L, mcp_parser_t *pr, const char *command, size_t cmdlen);

// request interface
int mcplib_request(lua_State *L);
int mcplib_request_command(lua_State *L);
int mcplib_request_key(lua_State *L);
int mcplib_request_ltrimkey(lua_State *L);
int mcplib_request_rtrimkey(lua_State *L);
int mcplib_request_token(lua_State *L);
int mcplib_request_ntokens(lua_State *L);
int mcplib_request_has_flag(lua_State *L);
int mcplib_request_flag_token(lua_State *L);
int mcplib_request_gc(lua_State *L);

int mcplib_open_dist_jump_hash(lua_State *L);
int mcplib_open_dist_ring_hash(lua_State *L);

int proxy_run_coroutine(lua_State *Lc, mc_resp *resp, io_pending_proxy_t *p, conn *c);
mcp_backend_t *mcplib_pool_proxy_call_helper(lua_State *L, mcp_pool_proxy_t *pp, const char *key, size_t len);
void mcp_request_attach(lua_State *L, mcp_request_t *rq, io_pending_proxy_t *p);
int mcp_request_render(mcp_request_t *rq, int idx, const char *tok, size_t len);
void proxy_lua_error(lua_State *L, const char *s);
void proxy_lua_ferror(lua_State *L, const char *fmt, ...);
#define PROXY_SERVER_ERROR "SERVER_ERROR "
#define PROXY_CLIENT_ERROR "CLIENT_ERROR "
void proxy_out_errstring(mc_resp *resp, char *type, const char *str);
int _start_proxy_config_threads(proxy_ctx_t *ctx);
int proxy_thread_loadconf(proxy_ctx_t *ctx, LIBEVENT_THREAD *thr);

// TODO (v2): more .h files, perhaps?
int mcplib_open_hash_xxhash(lua_State *L);

__attribute__((unused)) void dump_stack(lua_State *L);
#endif

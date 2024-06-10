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

enum mcp_memprofile_types {
    mcp_memp_free = 0,
    mcp_memp_string,
    mcp_memp_table,
    mcp_memp_func,
    mcp_memp_userdata,
    mcp_memp_thread,
    mcp_memp_default,
    mcp_memp_realloc,
};

struct mcp_memprofile {
    struct timespec last_status; // for per-second prints on status
    int id;
    uint64_t allocs[8];
    uint64_t alloc_bytes[8];
};

// for various time conversion functions
#define NANOSECONDS(x) ((x) * 1E9 + 0.5)
#define MICROSECONDS(x) ((x) * 1E6 + 0.5)

// Note: value created from thin air. Could be shorter.
#define MCP_REQUEST_MAXLEN KEY_MAX_LENGTH * 2

#define ENDSTR "END\r\n"
#define ENDLEN sizeof(ENDSTR)-1

#define MCP_BACKEND_UPVALUE 1

#define MCP_YIELD_POOL 1
#define MCP_YIELD_AWAIT 2
#define MCP_YIELD_INTERNAL 3
#define MCP_YIELD_WAITCOND 4
#define MCP_YIELD_WAITHANDLE 5
#define MCP_YIELD_SLEEP 6

#define SHAREDVM_FGEN_IDX 1
#define SHAREDVM_FGENSLOT_IDX 2
#define SHAREDVM_BACKEND_IDX 3

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
    uint64_t vm_gc_runs;
    uint64_t vm_memory_kb;
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
    uint64_t config_cron_runs;
    uint64_t config_cron_fails;
    uint64_t backend_total;
    uint64_t backend_marked_bad; // backend set to autofail
    uint64_t backend_failed; // an error caused a backend reset
    uint64_t request_failed_depth; // requests fast-failed due to be depth
};

struct proxy_tunables {
    struct timeval connect;
    struct timeval retry; // wait time before retrying a dead backend
    struct timeval read;
    struct timeval flap; // need to stay connected this long or it's flapping
    float flap_backoff_ramp; // factorial for retry time
    uint32_t flap_backoff_max; // don't backoff longer than this.
    int backend_depth_limit; // requests fast fail once depth over this limit
    int backend_failure_limit;
    int max_ustats; // limit the ustats index.
    bool tcp_keepalive;
    bool use_iothread; // default for using the bg io thread.
    bool use_tls; // whether or not be should use TLS
    bool down; // backend is forced into a down/bad state.
};

typedef STAILQ_HEAD(globalobj_head_s, mcp_globalobj_s) globalobj_head_t;
typedef struct {
    lua_State *proxy_state; // main configuration vm
    lua_State *proxy_sharedvm; // sub VM for short-lock global events/data
    void *proxy_code;
    proxy_event_thread_t *proxy_io_thread;
    uint64_t active_req_limit; // max total in-flight requests
    uint64_t buffer_memory_limit; // max bytes for send/receive buffers.
#ifdef PROXY_TLS
    void *tls_ctx;
#endif
    pthread_mutex_t config_lock;
    pthread_cond_t config_cond;
    pthread_t config_tid;
    pthread_mutex_t worker_lock;
    pthread_cond_t worker_cond;
    pthread_t manager_tid; // deallocation management thread
    pthread_mutex_t manager_lock;
    pthread_cond_t manager_cond;
    pthread_mutex_t sharedvm_lock; // protect statevm above
    globalobj_head_t manager_head; // stack for pool deallocation.
    int config_generation; // counter tracking config reloads
    int cron_ref; // reference to lua cron table
    int cron_next; // next cron to sleep to / execute
    bool worker_done; // signal variable for the worker lock/cond system.
    bool worker_failed; // covered by worker_lock as well.
    bool use_uring; // use IO_URING for backend connections.
    bool loading; // bool indicating an active config load.
    bool memprofile; // indicate if we want to profile lua memory.
    uint8_t memprofile_thread_counter;
    struct proxy_global_stats global_stats;
    struct proxy_user_stats user_stats;
    struct proxy_tunables tunables; // NOTE: updates covered by stats_lock
    pthread_mutex_t stats_lock; // used for rare global counters
} proxy_ctx_t;

#define PROXY_GET_THR_CTX(L) ((*(LIBEVENT_THREAD **)lua_getextraspace(L))->proxy_ctx)
#define PROXY_GET_THR(L) (*(LIBEVENT_THREAD **)lua_getextraspace(L))
// Operations from the config VM don't have a libevent thread.
#define PROXY_GET_CTX(L) (*(proxy_ctx_t **)lua_getextraspace(L))

struct proxy_hook_ref {
    int lua_ref;
    void *ctx; // if we're a generator based function.
};

struct proxy_hook_tagged {
    uint64_t tag;
    struct proxy_hook_ref ref;
};

struct proxy_hook {
    struct proxy_hook_ref ref;
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

typedef struct mcp_cron_s mcp_cron_t;
typedef struct mcp_backend_wrap_s mcp_backend_wrap_t;
typedef struct mcp_backend_label_s mcp_backend_label_t;
typedef struct mcp_backend_s mcp_backend_t;
typedef struct mcp_request_s mcp_request_t;
typedef struct mcp_parser_s mcp_parser_t;
typedef struct mcp_rcontext_s mcp_rcontext_t;
typedef struct mcp_funcgen_s mcp_funcgen_t;

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
    uint32_t endlen; // index to the start of \r\n or \n
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
    bool ascii_multiget; // ascii multiget mode. (hide errors/END)
    char request[];
};

struct mcp_cron_s {
    uint32_t gen;
    uint32_t next;
    uint32_t every;
    bool repeat;
};

typedef STAILQ_HEAD(io_head_s, _io_pending_proxy_t) io_head_t;
#define MAX_LABELLEN 512
#define MAX_NAMELEN 255
#define MAX_PORTLEN 6
// TODO (v2): IOV_MAX tends to be 1000+ which would allow for more batching but we
// don't have a good temporary space and don't want to malloc/free on every
// write. transmit() uses the stack but we can't do that for uring's use case.
#if MEMCACHED_DEBUG
#define BE_IOV_MAX 128 // let bench tests trigger max condition easily
#elif (IOV_MAX > 1024)
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
    int conncount; // number of sockets to make.
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

struct mcp_backendconn_s {
    mcp_backend_t *be_parent; // find the wrapper.
    int self; // our index into the parent array.
    int depth; // total number of requests in queue
    int pending_read; // number of requests written to socket, pending read.
    int failed_count; // number of fails (timeouts) in a row
    int flap_count; // number of times we've "flapped" into bad state.
    proxy_event_thread_t *event_thread; // event thread owning this backend.
    void *client; // mcmc client
#ifdef PROXY_TLS
    void *ssl;
#endif
    io_head_t io_head; // stack of requests.
    io_pending_proxy_t *io_next; // next request to write.
    char *rbuf; // statically allocated read buffer.
    size_t rbufused; // currently active bytes in the buffer
    struct event main_event; // libevent: changes role, mostly for main read events
    struct event write_event; // libevent: only used when socket wbuf full
    struct event timeout_event; // libevent: alarm for pending reads
    struct proxy_tunables tunables;
    struct timeval last_failed; // time the backend was last reset.
    enum mcp_backend_states state; // readback state machine
    int connect_flags; // flags to pass to mcmc_connect
    bool connecting; // in the process of an asynch connection.
    bool validating; // in process of validating a new backend connection.
    bool can_write; // recently got a WANT_WRITE or are connecting.
    bool bad; // timed out, marked as bad.
#ifndef PROXY_TLS
    bool ssl;
#endif
    struct iovec write_iovs[BE_IOV_MAX]; // iovs to stage batched writes
};

// TODO: move depth and flags to a second top level array so we can make index
// decisions from fewer memory stalls.
struct mcp_backend_s {
    int conncount; // total number of connections managed.
    int depth; // temporary depth counter for io_head
    bool transferred; // if beconn has been shipped to owner thread.
    bool use_io_thread; // note if this backend is worker-local or not.
    bool stacked; // if backend already queued for syscalls.
    STAILQ_ENTRY(mcp_backend_s) beconn_next; // stack for connecting conns
    STAILQ_ENTRY(mcp_backend_s) be_next; // stack for backends
    io_head_t io_head; // stack of inbound requests.
    char name[MAX_NAMELEN+1];
    char port[MAX_PORTLEN+1];
    char label[MAX_LABELLEN+1];
    struct proxy_tunables tunables; // this gets copied a few times for speed.
    struct mcp_backendconn_s be[];
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
#ifdef PROXY_TLS
    char *tls_wbuf;
    size_t tls_wbuf_size;
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
    unsigned int blen; // total size of the value to read.
    struct timeval start; // time this object was created.
    long elapsed; // time elapsed once handled.
    int status; // status code from mcmc_read()
    int bread; // amount of bytes read into value so far.
    uint8_t cmd; // from parser (pr.command)
    uint8_t extra; // ascii multiget hack for memory accounting. extra blen.
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
    STAILQ_ENTRY(io_pending_t) iop_next; // queue chain.
    // original struct ends here

    mcp_rcontext_t *rctx; // pointer to request context.
    int queue_handle; // queue slot to return this result to
    bool ascii_multiget; // passed on from mcp_r_t
    uint8_t io_type; // extstore IO or backend IO
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
            // FIXME: use top level next chain
            struct _io_pending_proxy_t *next; // stack for IO submission
            STAILQ_ENTRY(_io_pending_proxy_t) io_next; // stack for backends
            mcp_backend_t *backend; // backend server to request from
            struct iovec iov[2]; // request string + tail buffer
            int iovcnt; // 1 or 2...
            unsigned int iovbytes; // total bytes in the iovec
            int mcpres_ref; // mcp.res reference used for await()
            int await_ref; // lua reference if we were an await object
            mcp_resp_t *client_resp; // reference (currently pointing to a lua object)
            bool flushed; // whether we've fully written this request to a backend.
            bool is_await; // are we an await object?
            bool await_first; // are we the main route for an await object?
            bool await_background; // dummy IO for backgrounded awaits
            bool qcount_incr; // HACK.
        };
    };
};

struct mcp_globalobj_s {
    pthread_mutex_t lock; // protects refcount/object.
    STAILQ_ENTRY(mcp_globalobj_s) next;
    int refcount;
    int self_ref;
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
    proxy_ctx_t *ctx; // main context.
    char key_filter_conf[KEY_HASH_FILTER_MAX+1];
    struct mcp_globalobj_s g;
    char beprefix[MAX_LABELLEN+1]; // TODO: should probably be shorter.
    uint64_t hash_seed; // calculated from a string.
    int pool_size;
    int pool_be_total; // can be different from pool size for worker IO
    int phc_ref;
    bool use_iothread;
    mcp_pool_be_t pool[];
};

typedef struct {
    mcp_pool_t *main; // ptr to original
    mcp_pool_be_t *pool; // ptr to main->pool starting offset for owner thread.
} mcp_pool_proxy_t;

// utils
bool proxy_bufmem_checkadd(LIBEVENT_THREAD *t, int len);
void mcp_sharedvm_delta(proxy_ctx_t *ctx, int tidx, const char *name, int delta);
void mcp_sharedvm_remove(proxy_ctx_t *ctx, int tidx, const char *name);

void mcp_gobj_ref(lua_State *L, struct mcp_globalobj_s *g);
void mcp_gobj_unref(proxy_ctx_t *ctx, struct mcp_globalobj_s *g);
void mcp_gobj_finalize(struct mcp_globalobj_s *g);

// networking interface
void proxy_init_event_thread(proxy_event_thread_t *t, proxy_ctx_t *ctx, struct event_base *base);
void *proxy_event_thread(void *arg);
void proxy_run_backend_queue(be_head_t *head);
struct mcp_backendconn_s *proxy_choose_beconn(mcp_backend_t *be);
mcp_resp_t *mcp_prep_resobj(lua_State *L, mcp_request_t *rq, mcp_backend_t *be, LIBEVENT_THREAD *t);
mcp_resp_t *mcp_prep_bare_resobj(lua_State *L, LIBEVENT_THREAD *t);
io_pending_proxy_t *mcp_queue_rctx_io(mcp_rcontext_t *rctx, mcp_request_t *rq, mcp_backend_t *be, mcp_resp_t *r);

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
int mcplib_await_run_rctx(mcp_rcontext_t *rctx);
int mcplib_await_return(io_pending_proxy_t *p);

// internal request interface
int mcplib_internal(lua_State *L);
int mcplib_internal_run(mcp_rcontext_t *rctx);

// user stats interface
#define MAX_USTATS_DEFAULT 1024
int mcplib_add_stat(lua_State *L);
int mcplib_stat(lua_State *L);
size_t _process_request_next_key(mcp_parser_t *pr);
int process_request(mcp_parser_t *pr, const char *command, size_t cmdlen);
mcp_request_t *mcp_new_request(lua_State *L, mcp_parser_t *pr, const char *command, size_t cmdlen);
void mcp_set_request(mcp_parser_t *pr, mcp_request_t *r, const char *command, size_t cmdlen);

// rate limit interfaces
int mcplib_ratelim_tbf(lua_State *L);
int mcplib_ratelim_tbf_call(lua_State *L);
int mcplib_ratelim_global_tbf(lua_State *L);
int mcplib_ratelim_proxy_tbf_call(lua_State *L);
int mcp_ratelim_proxy_tbf(lua_State *from, lua_State *to);
int mcplib_ratelim_global_tbf_gc(lua_State *L);
int mcplib_ratelim_proxy_tbf_gc(lua_State *L);

// request function generator interface
void proxy_return_rctx_cb(io_pending_t *pending);
void proxy_finalize_rctx_cb(io_pending_t *pending);

enum mcp_rqueue_e {
    QWAIT_IDLE = 0,
    QWAIT_ANY,
    QWAIT_OK,
    QWAIT_GOOD,
    QWAIT_FASTGOOD,
    QWAIT_HANDLE,
    QWAIT_SLEEP,
};

enum mcp_funcgen_router_e {
    FGEN_ROUTER_NONE = 0,
    FGEN_ROUTER_SHORTSEP,
    FGEN_ROUTER_LONGSEP,
    FGEN_ROUTER_ANCHORSM,
    FGEN_ROUTER_ANCHORBIG,
};

struct mcp_router_long_s {
    char start[KEY_HASH_FILTER_MAX+1];
    char stop[KEY_HASH_FILTER_MAX+1];
};

struct mcp_funcgen_router {
    enum mcp_funcgen_router_e type;
    union {
        char sep;
        char lsep[KEY_HASH_FILTER_MAX+1];
        char anchorsm[2]; // short anchored mode.
        struct mcp_router_long_s big;
    } conf;
    mcp_funcgen_t *def_fgen; // default route
    int map_ref;
};

#define FGEN_NAME_MAXLEN 80
struct mcp_funcgen_s {
    LIBEVENT_THREAD *thread; // worker thread that created this funcgen.
    int generator_ref; // reference to the generator function.
    int self_ref; // self-reference if we're attached anywhere
    int argument_ref; // reference to an argument to pass to generator
    int max_queues; // how many queue slots rctx's have
    unsigned int refcount; // reference counter
    unsigned int total; // total contexts managed
    unsigned int free; // free contexts
    unsigned int free_max; // size of list below.
    unsigned int free_pressure; // "pressure" for when to early release rctx
    unsigned int routecount; // total routes if this fgen is a router.
    bool closed; // the hook holding this fgen has been replaced
    bool ready; // if we're locked down or not.
    mcp_rcontext_t **list;
    struct mcp_rqueue_s *queue_list;
    struct mcp_funcgen_router router;
    char name[FGEN_NAME_MAXLEN+1]; // string name for the generator.
};

#define RQUEUE_TYPE_NONE 0
#define RQUEUE_TYPE_POOL 1
#define RQUEUE_TYPE_FGEN 2
#define RQUEUE_ASSIGNED (1<<0)
#define RQUEUE_R_RESUME (1<<1)
#define RQUEUE_R_GOOD (1<<3)
#define RQUEUE_R_OK (1<<4)
#define RQUEUE_R_ANY (1<<5)
#define RQUEUE_R_ERROR (1<<7)

enum mcp_rqueue_state {
    RQUEUE_IDLE = 0,
    RQUEUE_QUEUED,
    RQUEUE_ACTIVE,
    RQUEUE_COMPLETE,
    RQUEUE_WAITED
};

struct mcp_rqueue_s {
    int obj_ref; // reference to pool/func/etc object
    int cb_ref; // if a lua callback was specified
    int req_ref; // reference to associated request object.
    int res_ref; // reference to lua response object.
    void *obj; // direct pointer to the object for fast access.
    mcp_request_t *rq; // request set to this slot
    mcp_resp_t *res_obj; // pointer to result object
    enum mcp_rqueue_state state; // queued/active/etc
    uint8_t obj_type; // what the obj_ref actually is.
    uint8_t flags; // bit flags for various states
};

struct mcp_rcontext_s {
    int self_ref; // reference to our own object
    int request_ref; // top level request for this context.
    int function_ref; // ref to the created route function.
    int coroutine_ref; // ref to our encompassing coroutine.
    unsigned int async_pending; // legacy async handling
    int pending_reqs; // pending requests and sub-requests
    unsigned int wait_count;
    unsigned int wait_done; // TODO: change these variables to uint8's
    int wait_handle; // waiting on a specific queue slot
    int parent_handle; // queue slot in parent rctx
    int conn_fd; // fd of the originating client, as *c can become invalid
    enum mcp_rqueue_e wait_mode;
    uint8_t lua_narg; // number of responses to push when yield resuming.
    bool first_queue; // HACK
    lua_State *Lc; // coroutine thread pointer.
    mcp_request_t *request; // ptr to the above reference.
    mcp_rcontext_t *parent; // parent rctx in the call graph
    conn *c; // associated client object.
    mc_resp *resp; // top level response object to fill.
    mcp_funcgen_t *fgen; // parent function generator context.
    struct event timeout_event; // for *_wait_timeout() and sleep() calls
    struct mcp_rqueue_s qslots[]; // queueable slots.
};

void mcp_run_rcontext_handle(mcp_rcontext_t *rctx, int handle);
void mcp_process_rctx_wait(mcp_rcontext_t *rctx, int handle);
int mcp_process_rqueue_return(mcp_rcontext_t *rctx, int handle, mcp_resp_t *res);
int mcplib_rcontext_handle_set_cb(lua_State *L);
int mcplib_rcontext_enqueue(lua_State *L);
int mcplib_rcontext_wait_cond(lua_State *L);
int mcplib_rcontext_wait_handle(lua_State *L);
int mcplib_rcontext_enqueue_and_wait(lua_State *L);
int mcplib_rcontext_res_good(lua_State *L);
int mcplib_rcontext_res_any(lua_State *L);
int mcplib_rcontext_res_ok(lua_State *L);
int mcplib_rcontext_result(lua_State *L);
int mcplib_rcontext_cfd(lua_State *L);
int mcplib_rcontext_sleep(lua_State *L);
int mcplib_funcgenbare_new(lua_State *L);
int mcplib_funcgen_new(lua_State *L);
int mcplib_funcgen_new_handle(lua_State *L);
int mcplib_funcgen_ready(lua_State *L);
int mcplib_router_new(lua_State *L);
mcp_rcontext_t *mcp_funcgen_start(lua_State *L, mcp_funcgen_t *fgen, mcp_parser_t *pr);
mcp_rcontext_t *mcp_funcgen_get_rctx(lua_State *L, int fgen_ref, mcp_funcgen_t *fgen);
void mcp_funcgen_return_rctx(mcp_rcontext_t *rctx);
int mcplib_funcgen_gc(lua_State *L);
void mcp_funcgen_reference(lua_State *L);
void mcp_funcgen_dereference(lua_State *L, mcp_funcgen_t *fgen);
void mcp_rcontext_push_rqu_res(lua_State *L, mcp_rcontext_t *rctx, int handle);


int mcplib_factory_command_new(lua_State *L);

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
int mcplib_request_flag_add(lua_State *L);
int mcplib_request_flag_set(lua_State *L);
int mcplib_request_flag_replace(lua_State *L);
int mcplib_request_flag_del(lua_State *L);
int mcplib_request_gc(lua_State *L);
int mcplib_request_match_res(lua_State *L);
void mcp_request_cleanup(LIBEVENT_THREAD *t, mcp_request_t *rq);

// response interface
void mcp_response_cleanup(LIBEVENT_THREAD *t, mcp_resp_t *r);
void mcp_set_resobj(mcp_resp_t *r, mcp_request_t *rq, mcp_backend_t *be, LIBEVENT_THREAD *t);

int mcplib_open_dist_jump_hash(lua_State *L);
int mcplib_open_dist_ring_hash(lua_State *L);

int proxy_run_rcontext(mcp_rcontext_t *rctx);
mcp_backend_t *mcplib_pool_proxy_call_helper(mcp_pool_proxy_t *pp, const char *key, size_t len);
void mcp_request_attach(mcp_request_t *rq, io_pending_proxy_t *p);
int mcp_request_render(mcp_request_t *rq, int idx, char flag, const char *tok, size_t len);
int mcp_request_append(mcp_request_t *rq, const char flag, const char *tok, size_t len);
int mcp_request_find_flag_index(mcp_request_t *rq, const char flag);
int mcp_request_find_flag_token(mcp_request_t *rq, const char flag, const char **token, size_t *len);
void proxy_lua_error(lua_State *L, const char *s);
#define proxy_lua_ferror(L, fmt, ...) \
    do { \
        lua_pushfstring(L, fmt, __VA_ARGS__); \
        lua_error(L); \
    } while (0)

#define PROXY_SERVER_ERROR "SERVER_ERROR "
#define PROXY_CLIENT_ERROR "CLIENT_ERROR "
void proxy_out_errstring(mc_resp *resp, char *type, const char *str);
int _start_proxy_config_threads(proxy_ctx_t *ctx);
int proxy_thread_loadconf(proxy_ctx_t *ctx, LIBEVENT_THREAD *thr);

// TODO (v2): more .h files, perhaps?
int mcplib_open_hash_xxhash(lua_State *L);

__attribute__((unused)) void dump_stack(lua_State *L, const char *msg);
__attribute__((unused)) void dump_registry(lua_State *L, const char *msg);
#endif

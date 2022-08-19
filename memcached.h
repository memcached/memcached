/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

/** \file
 * The main memcached header holding commonly used data
 * structures and function prototypes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <event.h>
#include <netdb.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <grp.h>
#include <signal.h>
/* need this to get IOV_MAX on some platforms. */
#ifndef __need_IOV_MAX
#define __need_IOV_MAX
#endif
#include <limits.h>
/* FreeBSD 4.x doesn't have IOV_MAX exposed. */
#ifndef IOV_MAX
#if defined(__FreeBSD__) || defined(__APPLE__) || defined(__GNU__)
# define IOV_MAX 1024
/* GNU/Hurd don't set MAXPATHLEN
 * http://www.gnu.org/software/hurd/hurd/porting/guidelines.html#PATH_MAX_tt_MAX_PATH_tt_MAXPATHL */
#ifndef MAXPATHLEN
#define MAXPATHLEN 4096
#endif
#endif
#endif

#if defined(__linux__)
# define SOCK_COOKIE_ID SO_MARK
#elif defined(__FreeBSD__)
# define SOCK_COOKIE_ID SO_USER_COOKIE
#elif defined(__OpenBSD__)
# define SOCK_COOKIE_ID SO_RTABLE
#endif

#include "itoa_ljust.h"
#include "protocol_binary.h"
#include "cache.h"
#include "logger.h"

#ifdef EXTSTORE
#include "crc32c.h"
#endif

#include "sasl_defs.h"
#ifdef TLS
#include <openssl/ssl.h>
#endif

/* for NAPI pinning feature */
#ifndef SO_INCOMING_NAPI_ID
#define SO_INCOMING_NAPI_ID 56
#endif

/** Maximum length of a key. */
#define KEY_MAX_LENGTH 250

/** Maximum length of a uri encoded key. */
#define KEY_MAX_URI_ENCODED_LENGTH (KEY_MAX_LENGTH  * 3 + 1)

/** Size of an incr buf. */
#define INCR_MAX_STORAGE_LEN 24

#define WRITE_BUFFER_SIZE 1024
#define READ_BUFFER_SIZE 16384
#define READ_BUFFER_CACHED 0
#define UDP_READ_BUFFER_SIZE 65536
#define UDP_MAX_PAYLOAD_SIZE 1400
#define UDP_HEADER_SIZE 8
#define UDP_DATA_SIZE 1392 // UDP_MAX_PAYLOAD_SIZE - UDP_HEADER_SIZE
#define MAX_SENDBUF_SIZE (256 * 1024 * 1024)

/* Binary protocol stuff */
#define BIN_MAX_EXTLEN 20 // length of the _incr command is currently the longest.

/* Initial power multiplier for the hash table */
#define HASHPOWER_DEFAULT 16
#define HASHPOWER_MAX 32

/*
 * We only reposition items in the LRU queue if they haven't been repositioned
 * in this many seconds. That saves us from churning on frequently-accessed
 * items.
 */
#define ITEM_UPDATE_INTERVAL 60

/*
 * Valid range of the maximum size of an item, in bytes.
 */
#define ITEM_SIZE_MAX_LOWER_LIMIT 1024
#define ITEM_SIZE_MAX_UPPER_LIMIT 1024 * 1024 * 1024


/* unistd.h is here */
#if HAVE_UNISTD_H
# include <unistd.h>
#endif

/* Slab sizing definitions. */
#define POWER_SMALLEST 1
#define POWER_LARGEST  256 /* actual cap is 255 */
#define SLAB_GLOBAL_PAGE_POOL 0 /* magic slab class for storing pages for reassignment */
#define CHUNK_ALIGN_BYTES 8
/* slab class max is a 6-bit number, -1. */
#define MAX_NUMBER_OF_SLAB_CLASSES (63 + 1)

/** How long an object can reasonably be assumed to be locked before
    harvesting it on a low memory condition. Default: disabled. */
#define TAIL_REPAIR_TIME_DEFAULT 0

/* warning: don't use these macros with a function, as it evals its arg twice */
#define ITEM_get_cas(i) (((i)->it_flags & ITEM_CAS) ? \
        (i)->data->cas : (uint64_t)0)

#define ITEM_set_cas(i,v) { \
    if ((i)->it_flags & ITEM_CAS) { \
        (i)->data->cas = v; \
    } \
}

#define ITEM_key(item) (((char*)&((item)->data)) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_suffix(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_data(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_ntotal(item) (sizeof(struct _stritem) + (item)->nkey + 1 \
         + (item)->nbytes \
         + (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))

#define ITEM_clsid(item) ((item)->slabs_clsid & ~(3<<6))
#define ITEM_lruid(item) ((item)->slabs_clsid & (3<<6))

#define STAT_KEY_LEN 128
#define STAT_VAL_LEN 128

/** Append a simple stat with a stat name, value format and value */
#define APPEND_STAT(name, fmt, val) \
    append_stat(name, add_stats, c, fmt, val);

/** Append an indexed stat with a stat name (with format), value format
    and value */
#define APPEND_NUM_FMT_STAT(name_fmt, num, name, fmt, val)          \
    klen = snprintf(key_str, STAT_KEY_LEN, name_fmt, num, name);    \
    vlen = snprintf(val_str, STAT_VAL_LEN, fmt, val);               \
    add_stats(key_str, klen, val_str, vlen, c);

/** Common APPEND_NUM_FMT_STAT format. */
#define APPEND_NUM_STAT(num, name, fmt, val) \
    APPEND_NUM_FMT_STAT("%d:%s", num, name, fmt, val)

/** Item client flag conversion */
#define FLAGS_CONV(it, flag) { \
    if ((it)->it_flags & ITEM_CFLAGS) { \
        flag = *((uint32_t *)ITEM_suffix((it))); \
    } else { \
        flag = 0; \
    } \
}

#define FLAGS_SIZE(item) (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0)

/**
 * Callback for any function producing stats.
 *
 * @param key the stat's key
 * @param klen length of the key
 * @param val the stat's value in an ascii form (e.g. text form of a number)
 * @param vlen length of the value
 * @parm cookie magic callback cookie
 */
typedef void (*ADD_STAT)(const char *key, const uint16_t klen,
                         const char *val, const uint32_t vlen,
                         const void *cookie);

/*
 * NOTE: If you modify this table you _MUST_ update the function state_text
 */
/**
 * Possible states of a connection.
 */
enum conn_states {
    conn_listening,  /**< the socket which listens for connections */
    conn_new_cmd,    /**< Prepare connection for next command */
    conn_waiting,    /**< waiting for a readable socket */
    conn_read,       /**< reading in a command line */
    conn_parse_cmd,  /**< try to parse a command from the input buffer */
    conn_write,      /**< writing out a simple response */
    conn_nread,      /**< reading in a fixed number of bytes */
    conn_swallow,    /**< swallowing unnecessary bytes w/o storing */
    conn_closing,    /**< closing this connection */
    conn_mwrite,     /**< writing out many items sequentially */
    conn_closed,     /**< connection is closed */
    conn_watch,      /**< held by the logger thread as a watcher */
    conn_io_queue,   /**< wait on async. process to get response object */
    conn_max_state   /**< Max state value (used for assertion) */
};

enum bin_substates {
    bin_no_state,
    bin_reading_set_header,
    bin_reading_cas_header,
    bin_read_set_value,
    bin_reading_get_key,
    bin_reading_stat,
    bin_reading_del_header,
    bin_reading_incr_header,
    bin_read_flush_exptime,
    bin_reading_sasl_auth,
    bin_reading_sasl_auth_data,
    bin_reading_touch_key,
};

enum protocol {
    ascii_prot = 3, /* arbitrary value. */
    binary_prot,
    negotiating_prot, /* Discovering the protocol */
#ifdef PROXY
    proxy_prot,
#endif
};

enum network_transport {
    local_transport, /* Unix sockets*/
    tcp_transport,
    udp_transport
};

enum pause_thread_types {
    PAUSE_WORKER_THREADS = 0,
    PAUSE_ALL_THREADS,
    RESUME_ALL_THREADS,
    RESUME_WORKER_THREADS
};

enum stop_reasons {
    NOT_STOP,
    GRACE_STOP,
    EXIT_NORMALLY
};

enum close_reasons {
    ERROR_CLOSE,
    NORMAL_CLOSE,
    IDLE_TIMEOUT_CLOSE,
    SHUTDOWN_CLOSE,
};

#define IS_TCP(x) (x == tcp_transport)
#define IS_UDP(x) (x == udp_transport)

#define NREAD_ADD 1
#define NREAD_SET 2
#define NREAD_REPLACE 3
#define NREAD_APPEND 4
#define NREAD_PREPEND 5
#define NREAD_CAS 6

enum store_item_type {
    NOT_STORED=0, STORED, EXISTS, NOT_FOUND, TOO_LARGE, NO_MEMORY
};

enum delta_result_type {
    OK, NON_NUMERIC, EOM, DELTA_ITEM_NOT_FOUND, DELTA_ITEM_CAS_MISMATCH
};

/** Time relative to server start. Smaller than time_t on 64-bit systems. */
// TODO: Move to sub-header. needed in logger.h
//typedef unsigned int rel_time_t;

/** Use X macros to avoid iterating over the stats fields during reset and
 * aggregation. No longer have to add new stats in 3+ places.
 */

#define SLAB_STATS_FIELDS \
    X(set_cmds) \
    X(get_hits) \
    X(touch_hits) \
    X(delete_hits) \
    X(cas_hits) \
    X(cas_badval) \
    X(incr_hits) \
    X(decr_hits)

/** Stats stored per slab (and per thread). */
struct slab_stats {
#define X(name) uint64_t    name;
    SLAB_STATS_FIELDS
#undef X
};

#define THREAD_STATS_FIELDS \
    X(get_cmds) \
    X(get_misses) \
    X(get_expired) \
    X(get_flushed) \
    X(touch_cmds) \
    X(touch_misses) \
    X(delete_misses) \
    X(incr_misses) \
    X(decr_misses) \
    X(cas_misses) \
    X(meta_cmds) \
    X(bytes_read) \
    X(bytes_written) \
    X(flush_cmds) \
    X(conn_yields) /* # of yields for connections (-R option)*/ \
    X(auth_cmds) \
    X(auth_errors) \
    X(idle_kicks) /* idle connections killed */ \
    X(response_obj_oom) \
    X(response_obj_count) \
    X(response_obj_bytes) \
    X(read_buf_oom) \
    X(store_too_large) \
    X(store_no_memory)

#ifdef EXTSTORE
#define EXTSTORE_THREAD_STATS_FIELDS \
    X(get_extstore) \
    X(get_aborted_extstore) \
    X(get_oom_extstore) \
    X(recache_from_extstore) \
    X(miss_from_extstore) \
    X(badcrc_from_extstore)
#endif

#ifdef PROXY
#define PROXY_THREAD_STATS_FIELDS \
    X(proxy_conn_requests) \
    X(proxy_conn_errors) \
    X(proxy_conn_oom) \
    X(proxy_req_active)
#endif

/**
 * Stats stored per-thread.
 */
struct thread_stats {
    pthread_mutex_t   mutex;
#define X(name) uint64_t    name;
    THREAD_STATS_FIELDS
#ifdef EXTSTORE
    EXTSTORE_THREAD_STATS_FIELDS
#endif
#ifdef PROXY
    PROXY_THREAD_STATS_FIELDS
#endif
#undef X
    struct slab_stats slab_stats[MAX_NUMBER_OF_SLAB_CLASSES];
    uint64_t lru_hits[POWER_LARGEST];
    uint64_t read_buf_count;
    uint64_t read_buf_bytes;
    uint64_t read_buf_bytes_free;
};

/**
 * Global stats. Only resettable stats should go into this structure.
 */
struct stats {
    uint64_t      total_items;
    uint64_t      total_conns;
    uint64_t      rejected_conns;
    uint64_t      malloc_fails;
    uint64_t      listen_disabled_num;
    uint64_t      slabs_moved;       /* times slabs were moved around */
    uint64_t      slab_reassign_rescues; /* items rescued during slab move */
    uint64_t      slab_reassign_evictions_nomem; /* valid items lost during slab move */
    uint64_t      slab_reassign_inline_reclaim; /* valid items lost during slab move */
    uint64_t      slab_reassign_chunk_rescues; /* chunked-item chunks recovered */
    uint64_t      slab_reassign_busy_items; /* valid temporarily unmovable */
    uint64_t      slab_reassign_busy_deletes; /* refcounted items killed */
    uint64_t      lru_crawler_starts; /* Number of item crawlers kicked off */
    uint64_t      lru_maintainer_juggles; /* number of LRU bg pokes */
    uint64_t      time_in_listen_disabled_us;  /* elapsed time in microseconds while server unable to process new connections */
    uint64_t      log_worker_dropped; /* logs dropped by worker threads */
    uint64_t      log_worker_written; /* logs written by worker threads */
    uint64_t      log_watcher_skipped; /* logs watchers missed */
    uint64_t      log_watcher_sent; /* logs sent to watcher buffers */
#ifdef EXTSTORE
    uint64_t      extstore_compact_lost; /* items lost because they were locked */
    uint64_t      extstore_compact_rescues; /* items re-written during compaction */
    uint64_t      extstore_compact_skipped; /* unhit items skipped during compaction */
#endif
#ifdef TLS
    uint64_t      ssl_handshake_errors; /* TLS failures at accept/handshake time */
    uint64_t      ssl_new_sessions; /* successfully negotiated new (non-reused) TLS sessions */
#endif
    struct timeval maxconns_entered;  /* last time maxconns entered */
    uint64_t      unexpected_napi_ids;  /* see doc/napi_ids.txt */
    uint64_t      round_robin_fallback; /* see doc/napi_ids.txt */
};

/**
 * Global "state" stats. Reflects state that shouldn't be wiped ever.
 * Ordered for some cache line locality for commonly updated counters.
 */
struct stats_state {
    uint64_t      curr_items;
    uint64_t      curr_bytes;
    uint64_t      curr_conns;
    uint64_t      hash_bytes;       /* size used for hash tables */
    unsigned int  conn_structs;
    unsigned int  reserved_fds;
    unsigned int  hash_power_level; /* Better hope it's not over 9000 */
    unsigned int  log_watchers; /* number of currently active watchers */
    bool          hash_is_expanding; /* If the hash table is being expanded */
    bool          accepting_conns;  /* whether we are currently accepting */
    bool          slab_reassign_running; /* slab reassign in progress */
    bool          lru_crawler_running; /* crawl in progress */
};

#define MAX_VERBOSITY_LEVEL 2

/* When adding a setting, be sure to update process_stat_settings */
/**
 * Globally accessible settings as derived from the commandline.
 */
struct settings {
    size_t maxbytes;
    int maxconns;
    int port;
    int udpport;
    char *inter;
    int verbose;
    rel_time_t oldest_live; /* ignore existing items older than this */
    uint64_t oldest_cas; /* ignore existing items with CAS values lower than this */
    int evict_to_free;
    char *socketpath;   /* path to unix socket if using local socket */
    char *auth_file;    /* path to user authentication file */
    int access;  /* access mask (a la chmod) for unix domain socket */
    double factor;          /* chunk size growth factor */
    int chunk_size;
    int num_threads;        /* number of worker (without dispatcher) libevent threads to run */
    int num_threads_per_udp; /* number of worker threads serving each udp socket */
    char prefix_delimiter;  /* character that marks a key prefix (for stats) */
    int detail_enabled;     /* nonzero if we're collecting detailed stats */
    int reqs_per_event;     /* Maximum number of io to process on each
                               io-event. */
    bool use_cas;
    enum protocol binding_protocol;
    int backlog;
    int item_size_max;        /* Maximum item size */
    int slab_chunk_size_max;  /* Upper end for chunks within slab pages. */
    int slab_page_size;     /* Slab's page units. */
    volatile sig_atomic_t sig_hup;  /* a HUP signal was received but not yet handled */
    bool sasl;              /* SASL on/off */
    bool maxconns_fast;     /* Whether or not to early close connections */
    bool lru_crawler;        /* Whether or not to enable the autocrawler thread */
    bool lru_maintainer_thread; /* LRU maintainer background thread */
    bool lru_segmented;     /* Use split or flat LRU's */
    bool slab_reassign;     /* Whether or not slab reassignment is allowed */
    int slab_automove;     /* Whether or not to automatically move slabs */
    double slab_automove_ratio; /* youngest must be within pct of oldest */
    unsigned int slab_automove_window; /* window mover for algorithm */
    int hashpower_init;     /* Starting hash power level */
    bool shutdown_command; /* allow shutdown command */
    int tail_repair_time;   /* LRU tail refcount leak repair time */
    bool flush_enabled;     /* flush_all enabled */
    bool dump_enabled;      /* whether cachedump/metadump commands work */
    char *hash_algorithm;     /* Hash algorithm in use */
    int lru_crawler_sleep;  /* Microsecond sleep between items */
    uint32_t lru_crawler_tocrawl; /* Number of items to crawl per run */
    int hot_lru_pct; /* percentage of slab space for HOT_LRU */
    int warm_lru_pct; /* percentage of slab space for WARM_LRU */
    double hot_max_factor; /* HOT tail age relative to COLD tail */
    double warm_max_factor; /* WARM tail age relative to COLD tail */
    int crawls_persleep; /* Number of LRU crawls to run before sleeping */
    bool temp_lru; /* TTL < temporary_ttl uses TEMP_LRU */
    uint32_t temporary_ttl; /* temporary LRU threshold */
    int idle_timeout;       /* Number of seconds to let connections idle */
    unsigned int logger_watcher_buf_size; /* size of logger's per-watcher buffer */
    unsigned int logger_buf_size; /* size of per-thread logger buffer */
    unsigned int read_buf_mem_limit; /* total megabytes allowable for net buffers */
    bool drop_privileges;   /* Whether or not to drop unnecessary process privileges */
    bool watch_enabled; /* allows watch commands to be dropped */
    bool relaxed_privileges;   /* Relax process restrictions when running testapp */
    bool meta_response_old; /* use "OK" instead of "HD". for response code TEMPORARY! */
#ifdef EXTSTORE
    unsigned int ext_io_threadcount; /* number of IO threads to run. */
    unsigned int ext_page_size; /* size in megabytes of storage pages. */
    unsigned int ext_item_size; /* minimum size of items to store externally */
    unsigned int ext_item_age; /* max age of tail item before storing ext. */
    unsigned int ext_low_ttl; /* remaining TTL below this uses own pages */
    unsigned int ext_recache_rate; /* counter++ % recache_rate == 0 > recache */
    unsigned int ext_wbuf_size; /* read only note for the engine */
    unsigned int ext_compact_under; /* when fewer than this many pages, compact */
    unsigned int ext_drop_under; /* when fewer than this many pages, drop COLD items */
    unsigned int ext_max_sleep; /* maximum sleep time for extstore bg threads, in us */
    double ext_max_frag; /* ideal maximum page fragmentation */
    double slab_automove_freeratio; /* % of memory to hold free as buffer */
    bool ext_drop_unread; /* skip unread items during compaction */
    /* start flushing to extstore after memory below this */
    unsigned int ext_global_pool_min;
#endif
#ifdef TLS
    bool ssl_enabled; /* indicates whether SSL is enabled */
    SSL_CTX *ssl_ctx; /* holds the SSL server context which has the server certificate */
    char *ssl_chain_cert; /* path to the server SSL chain certificate */
    char *ssl_key; /* path to the server key */
    int ssl_verify_mode; /* client certificate verify mode */
    int ssl_keyformat; /* key format , default is PEM */
    char *ssl_ciphers; /* list of SSL ciphers */
    char *ssl_ca_cert; /* certificate with CAs. */
    rel_time_t ssl_last_cert_refresh_time; /* time of the last server certificate refresh */
    unsigned int ssl_wbuf_size; /* size of the write buffer used by ssl_sendmsg method */
    bool ssl_session_cache; /* enable SSL server session caching */
    bool ssl_kernel_tls; /* enable server kTLS */
    int ssl_min_version; /* minimum SSL protocol version to accept */
#endif
    int num_napi_ids;   /* maximum number of NAPI IDs */
    char *memory_file;  /* warm restart memory file path */
#ifdef PROXY
    bool proxy_enabled;
    bool proxy_uring; /* if the proxy should use io_uring */
    char *proxy_startfile; /* lua file to run when workers start */
    void *proxy_ctx; /* proxy's state context */
#endif
#ifdef SOCK_COOKIE_ID
    uint32_t sock_cookie_id;
#endif
};

extern struct stats stats;
extern struct stats_state stats_state;
extern time_t process_started;
extern struct settings settings;

#define ITEM_LINKED 1
#define ITEM_CAS 2

/* temp */
#define ITEM_SLABBED 4

/* Item was fetched at least once in its lifetime */
#define ITEM_FETCHED 8
/* Appended on fetch, removed on LRU shuffling */
#define ITEM_ACTIVE 16
/* If an item's storage are chained chunks. */
#define ITEM_CHUNKED 32
#define ITEM_CHUNK 64
/* ITEM_data bulk is external to item */
#define ITEM_HDR 128
/* additional 4 bytes for item client flags */
#define ITEM_CFLAGS 256
/* item has sent out a token already */
#define ITEM_TOKEN_SENT 512
/* reserved, in case tokens should be a 2-bit count in future */
#define ITEM_TOKEN_RESERVED 1024
/* if item has been marked as a stale value */
#define ITEM_STALE 2048
/* if item key was sent in binary */
#define ITEM_KEY_BINARY 4096

/**
 * Structure for storing items within memcached.
 */
typedef struct _stritem {
    /* Protected by LRU locks */
    struct _stritem *next;
    struct _stritem *prev;
    /* Rest are protected by an item lock */
    struct _stritem *h_next;    /* hash chain next */
    rel_time_t      time;       /* least recent access */
    rel_time_t      exptime;    /* expire time */
    int             nbytes;     /* size of data */
    unsigned short  refcount;
    uint16_t        it_flags;   /* ITEM_* above */
    uint8_t         slabs_clsid;/* which slab class we're in */
    uint8_t         nkey;       /* key length, w/terminating null and padding */
    /* this odd type prevents type-punning issues when we do
     * the little shuffle to save space when not using CAS. */
    union {
        uint64_t cas;
        char end;
    } data[];
    /* if it_flags & ITEM_CAS we have 8 bytes CAS */
    /* then null-terminated key */
    /* then " flags length\r\n" (no terminating null) */
    /* then data with terminating \r\n (no terminating null; it's binary!) */
} item;

// TODO: If we eventually want user loaded modules, we can't use an enum :(
enum crawler_run_type {
    CRAWLER_AUTOEXPIRE=0, CRAWLER_EXPIRED, CRAWLER_METADUMP
};

typedef struct {
    struct _stritem *next;
    struct _stritem *prev;
    struct _stritem *h_next;    /* hash chain next */
    rel_time_t      time;       /* least recent access */
    rel_time_t      exptime;    /* expire time */
    int             nbytes;     /* size of data */
    unsigned short  refcount;
    uint16_t        it_flags;   /* ITEM_* above */
    uint8_t         slabs_clsid;/* which slab class we're in */
    uint8_t         nkey;       /* key length, w/terminating null and padding */
    uint32_t        remaining;  /* Max keys to crawl per slab per invocation */
    uint64_t        reclaimed;  /* items reclaimed during this crawl. */
    uint64_t        unfetched;  /* items reclaimed unfetched during this crawl. */
    uint64_t        checked;    /* items examined during this crawl. */
} crawler;

/* Header when an item is actually a chunk of another item. */
typedef struct _strchunk {
    struct _strchunk *next;     /* points within its own chain. */
    struct _strchunk *prev;     /* can potentially point to the head. */
    struct _stritem  *head;     /* always points to the owner chunk */
    int              size;      /* available chunk space in bytes */
    int              used;      /* chunk space used */
    int              nbytes;    /* used. */
    unsigned short   refcount;  /* used? */
    uint16_t         it_flags;  /* ITEM_* above. */
    uint8_t          slabs_clsid; /* Same as above. */
    uint8_t          orig_clsid; /* For obj hdr chunks slabs_clsid is fake. */
    char data[];
} item_chunk;

#ifdef NEED_ALIGN
static inline char *ITEM_schunk(item *it) {
    int offset = it->nkey + 1
        + ((it->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0)
        + ((it->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0);
    int remain = offset % 8;
    if (remain != 0) {
        offset += 8 - remain;
    }
    return ((char *) &(it->data)) + offset;
}
#else
#define ITEM_schunk(item) ((char*) &((item)->data) + (item)->nkey + 1 \
         + (((item)->it_flags & ITEM_CFLAGS) ? sizeof(uint32_t) : 0) \
         + (((item)->it_flags & ITEM_CAS) ? sizeof(uint64_t) : 0))
#endif

#ifdef EXTSTORE
typedef struct {
    unsigned int page_version; /* from IO header */
    unsigned int offset; /* from IO header */
    unsigned short page_id; /* from IO header */
} item_hdr;
#endif

#define IO_QUEUE_COUNT 3

#define IO_QUEUE_NONE 0
#define IO_QUEUE_EXTSTORE 1
#define IO_QUEUE_PROXY 2

typedef struct _io_pending_t io_pending_t;
typedef struct io_queue_s io_queue_t;
typedef void (*io_queue_stack_cb)(io_queue_t *q);
typedef void (*io_queue_cb)(io_pending_t *pending);
// this structure's ownership gets passed between threads:
// - owned normally by the worker thread.
// - multiple queues can be submitted at the same time.
// - each queue can be sent to different background threads.
// - each submitted queue needs to know when to return to the worker.
// - the worker needs to know when all queues have returned so it can process.
//
// io_queue_t's count field is owned by worker until submitted. Then owned by
// side thread until returned.
// conn->io_queues_submitted is always owned by the worker thread. it is
// incremented as the worker submits queues, and decremented as it gets pinged
// for returned threads.
//
// All of this is to avoid having to hit a mutex owned by the connection
// thread that gets pinged for each thread (or an equivalent atomic).
struct io_queue_s {
    void *ctx; // duplicated from io_queue_cb_t
    void *stack_ctx; // module-specific context to be batch-submitted
    int count; // ios to process before returning. only accessed by queue processor once submitted
    int type; // duplicated from io_queue_cb_t
};

typedef struct io_queue_cb_s {
    void *ctx; // untouched ptr for specific context
    io_queue_stack_cb submit_cb; // callback given a full stack of pending IO's at once.
    io_queue_stack_cb complete_cb;
    io_queue_cb return_cb; // called on worker thread.
    io_queue_cb finalize_cb; // called back on the worker thread.
    int type;
} io_queue_cb_t;

typedef struct _mc_resp_bundle mc_resp_bundle;
typedef struct {
    pthread_t thread_id;        /* unique ID of this thread */
    struct event_base *base;    /* libevent handle this thread uses */
    struct event notify_event;  /* listen event for notify pipe */
#ifdef HAVE_EVENTFD
    int notify_event_fd;        /* notify counter */
#else
    int notify_receive_fd;      /* receiving end of notify pipe */
    int notify_send_fd;         /* sending end of notify pipe */
#endif
    struct thread_stats stats;  /* Stats generated by this thread */
    io_queue_cb_t io_queues[IO_QUEUE_COUNT];
    struct conn_queue *ev_queue; /* Worker/conn event queue */
    cache_t *rbuf_cache;        /* static-sized read buffers */
    mc_resp_bundle *open_bundle;
    cache_t *io_cache;          /* IO objects */
#ifdef EXTSTORE
    void *storage;              /* data object for storage system */
#endif
    logger *l;                  /* logger buffer */
    void *lru_bump_buf;         /* async LRU bump buffer */
#ifdef TLS
    char   *ssl_wbuf;
#endif
    int napi_id;                /* napi id associated with this thread */
#ifdef PROXY
    void *L;
    void *proxy_hooks;
    void *proxy_user_stats;
    void *proxy_int_stats;
    uint32_t proxy_rng[4]; // fast per-thread rng for lua.
    // TODO: add ctx object so we can attach to queue.
#endif
} LIBEVENT_THREAD;

/**
 * Response objects
 */
#define MC_RESP_IOVCOUNT 4
typedef struct _mc_resp {
    mc_resp_bundle *bundle; // ptr back to bundle
    struct _mc_resp *next; // choo choo.
    int wbytes; // bytes to write out of wbuf: might be able to nuke this.
    int tosend; // total bytes to send for this response
    void *write_and_free; /** free this memory after finishing writing */
    io_pending_t *io_pending; /* pending IO descriptor for this response */

    item *item; /* item associated with this response object, with reference held */
    struct iovec iov[MC_RESP_IOVCOUNT]; /* built-in iovecs to simplify network code */
    int chunked_total; /* total amount of chunked item data to send. */
    uint8_t iovcnt;
    uint8_t chunked_data_iov; /* this iov is a pointer to chunked data header */

    /* instruct transmit to skip this response object. used by storage engines
     * to asynchronously kill an object that was queued to write
     */
    bool skip;
    bool free; // double free detection.
    // UDP bits. Copied in from the client.
    uint16_t    request_id; /* Incoming UDP request ID, if this is a UDP "connection" */
    uint16_t    udp_sequence; /* packet counter when transmitting result */
    uint16_t    udp_total; /* total number of packets in sequence */
    struct sockaddr_in6 request_addr; /* udp: Who sent this request */
    socklen_t request_addr_size;

    char wbuf[WRITE_BUFFER_SIZE];
} mc_resp;

#define MAX_RESP_PER_BUNDLE ((READ_BUFFER_SIZE - sizeof(mc_resp_bundle)) / sizeof(mc_resp))
struct _mc_resp_bundle {
    uint8_t refcount;
    uint8_t next_check; // next object to check on assignment.
    struct _mc_resp_bundle *next;
    struct _mc_resp_bundle *prev;
    mc_resp r[];
};

typedef struct conn conn;

struct _io_pending_t {
    int io_queue_type; // matches one of IO_QUEUE_*
    LIBEVENT_THREAD *thread;
    conn *c;
    mc_resp *resp; // associated response object
    char data[120];
};

/**
 * The structure representing a connection into memcached.
 */
struct conn {
    sasl_conn_t *sasl_conn;
    int    sfd;
    bool sasl_started;
    bool authenticated;
    bool set_stale;
    bool mset_res; /** uses mset format for return code */
    bool close_after_write; /** flush write then move to close connection */
    bool rbuf_malloced; /** read buffer was malloc'ed for ascii mget, needs free() */
    bool item_malloced; /** item for conn_nread state is a temporary malloc */
#ifdef TLS
    SSL    *ssl;
    char   *ssl_wbuf;
    bool ssl_enabled;
#endif
    enum conn_states  state;
    enum bin_substates substate;
    rel_time_t last_cmd_time;
    struct event event;
    short  ev_flags;
    short  which;   /** which events were just triggered */

    char   *rbuf;   /** buffer to read commands into */
    char   *rcurr;  /** but if we parsed some already, this is where we stopped */
    int    rsize;   /** total allocated size of rbuf */
    int    rbytes;  /** how much data, starting from rcur, do we have unparsed */

    mc_resp *resp; // tail response.
    mc_resp *resp_head; // first response in current stack.
    char   *ritem;  /** when we read in an item's value, it goes here */
    int    rlbytes;

    /**
     * item is used to hold an item structure created after reading the command
     * line of set/add/replace commands, but before we finished reading the actual
     * data. The data is read into ITEM_data(item) to avoid extra copying.
     */

    void   *item;     /* for commands set/add/replace  */

    /* data for the swallow state */
    int    sbytes;    /* how many bytes to swallow */

    int io_queues_submitted; /* see notes on io_queue_t */
    io_queue_t io_queues[IO_QUEUE_COUNT]; /* set of deferred IO queues. */
#ifdef PROXY
    unsigned int proxy_coro_ref; /* lua reference for active coroutine */
#endif
#ifdef EXTSTORE
    unsigned int recache_counter;
#endif
    enum protocol protocol;   /* which protocol this connection speaks */
    enum network_transport transport; /* what transport is used by this connection */
    enum close_reasons close_reason; /* reason for transition into conn_closing */

    /* data for UDP clients */
    int    request_id; /* Incoming UDP request ID, if this is a UDP "connection" */
    struct sockaddr_in6 request_addr; /* udp: Who sent the most recent request */
    socklen_t request_addr_size;

    bool   noreply;   /* True if the reply should not be sent. */
    /* current stats command */
    struct {
        char *buffer;
        size_t size;
        size_t offset;
    } stats;

    /* Binary protocol stuff */
    /* This is where the binary header goes */
    protocol_binary_request_header binary_header;
    uint64_t cas; /* the cas to return */
    uint64_t tag; /* listener stocket tag */
    short cmd; /* current command being processed */
    int opaque;
    int keylen;
    conn   *next;     /* Used for generating a list of conn structures */
    LIBEVENT_THREAD *thread; /* Pointer to the thread object serving this connection */
    int (*try_read_command)(conn *c); /* pointer for top level input parser */
    ssize_t (*read)(conn  *c, void *buf, size_t count);
    ssize_t (*sendmsg)(conn *c, struct msghdr *msg, int flags);
    ssize_t (*write)(conn *c, void *buf, size_t count);
};

/* array of conn structures, indexed by file descriptor */
extern conn **conns;

/* current time of day (updated periodically) */
extern volatile rel_time_t current_time;

#ifdef MEMCACHED_DEBUG
extern volatile bool is_paused;
extern volatile int64_t delta;
#endif

/* TODO: Move to slabs.h? */
extern volatile int slab_rebalance_signal;

struct slab_rebalance {
    void *slab_start;
    void *slab_end;
    void *slab_pos;
    int s_clsid;
    int d_clsid;
    uint32_t busy_items;
    uint32_t rescues;
    uint32_t evictions_nomem;
    uint32_t inline_reclaim;
    uint32_t chunk_rescues;
    uint32_t busy_deletes;
    uint32_t busy_loops;
    uint8_t done;
    uint8_t *completed;
};

extern struct slab_rebalance slab_rebal;
#ifdef EXTSTORE
extern void *ext_storage;
#endif
/*
 * Functions
 */
void do_accept_new_conns(const bool do_accept);
enum delta_result_type do_add_delta(conn *c, const char *key,
                                    const size_t nkey, const bool incr,
                                    const int64_t delta, char *buf,
                                    uint64_t *cas, const uint32_t hv,
                                    item **it_ret);
enum store_item_type do_store_item(item *item, int comm, conn* c, const uint32_t hv);
void thread_io_queue_add(LIBEVENT_THREAD *t, int type, void *ctx, io_queue_stack_cb cb, io_queue_stack_cb com_cb, io_queue_cb ret_cb, io_queue_cb fin_cb);
void conn_io_queue_setup(conn *c);
io_queue_t *conn_io_queue_get(conn *c, int type);
io_queue_cb_t *thread_io_queue_get(LIBEVENT_THREAD *t, int type);
void conn_io_queue_return(io_pending_t *io);
conn *conn_new(const int sfd, const enum conn_states init_state, const int event_flags, const int read_buffer_size,
    enum network_transport transport, struct event_base *base, void *ssl, uint64_t conntag, enum protocol bproto);

void conn_worker_readd(conn *c);
extern int daemonize(int nochdir, int noclose);

#define mutex_lock(x) pthread_mutex_lock(x)
#define mutex_unlock(x) pthread_mutex_unlock(x)

#include "stats_prefix.h"
#include "slabs.h"
#include "assoc.h"
#include "items.h"
#include "crawler.h"
#include "trace.h"
#include "hash.h"
#include "util.h"

/*
 * Functions such as the libevent-related calls that need to do cross-thread
 * communication in multithreaded mode (rather than actually doing the work
 * in the current thread) are called via "dispatch_" frontends, which are
 * also #define-d to directly call the underlying code in singlethreaded mode.
 */
void memcached_thread_init(int nthreads, void *arg);
void redispatch_conn(conn *c);
void timeout_conn(conn *c);
#ifdef PROXY
void proxy_reload_notify(LIBEVENT_THREAD *t);
#endif
void return_io_pending(io_pending_t *io);
void dispatch_conn_new(int sfd, enum conn_states init_state, int event_flags, int read_buffer_size,
    enum network_transport transport, void *ssl, uint64_t conntag, enum protocol bproto);
void sidethread_conn_close(conn *c);

/* Lock wrappers for cache functions that are called from main loop. */
enum delta_result_type add_delta(conn *c, const char *key,
                                 const size_t nkey, bool incr,
                                 const int64_t delta, char *buf,
                                 uint64_t *cas);
void accept_new_conns(const bool do_accept);
void  conn_close_idle(conn *c);
void  conn_close_all(void);
item *item_alloc(char *key, size_t nkey, int flags, rel_time_t exptime, int nbytes);
#define DO_UPDATE true
#define DONT_UPDATE false
item *item_get(const char *key, const size_t nkey, conn *c, const bool do_update);
item *item_get_locked(const char *key, const size_t nkey, conn *c, const bool do_update, uint32_t *hv);
item *item_touch(const char *key, const size_t nkey, uint32_t exptime, conn *c);
int   item_link(item *it);
void  item_remove(item *it);
int   item_replace(item *it, item *new_it, const uint32_t hv);
void  item_unlink(item *it);

void item_lock(uint32_t hv);
void *item_trylock(uint32_t hv);
void item_trylock_unlock(void *arg);
void item_unlock(uint32_t hv);
void pause_threads(enum pause_thread_types type);
void stop_threads(void);
int stop_conn_timeout_thread(void);
#define refcount_incr(it) ++(it->refcount)
#define refcount_decr(it) --(it->refcount)
void STATS_LOCK(void);
void STATS_UNLOCK(void);
#define THR_STATS_LOCK(c) pthread_mutex_lock(&c->thread->stats.mutex)
#define THR_STATS_UNLOCK(c) pthread_mutex_unlock(&c->thread->stats.mutex)
void threadlocal_stats_reset(void);
void threadlocal_stats_aggregate(struct thread_stats *stats);
void slab_stats_aggregate(struct thread_stats *stats, struct slab_stats *out);
LIBEVENT_THREAD *get_worker_thread(int id);

/* Stat processing functions */
void append_stat(const char *name, ADD_STAT add_stats, conn *c,
                 const char *fmt, ...);

enum store_item_type store_item(item *item, int comm, conn *c);

/* Protocol related code */
void out_string(conn *c, const char *str);
#define REALTIME_MAXDELTA 60*60*24*30
/* Negative exptimes can underflow and end up immortal. realtime() will
   immediately expire values that are greater than REALTIME_MAXDELTA, but less
   than process_started, so lets aim for that. */
#define EXPTIME_TO_POSITIVE_TIME(exptime) (exptime < 0) ? \
        REALTIME_MAXDELTA + 1 : exptime
rel_time_t realtime(const time_t exptime);
item* limited_get(char *key, size_t nkey, conn *c, uint32_t exptime, bool should_touch, bool do_update, bool *overflow);
item* limited_get_locked(char *key, size_t nkey, conn *c, bool do_update, uint32_t *hv, bool *overflow);
// Read/Response object handlers.
void resp_reset(mc_resp *resp);
void resp_add_iov(mc_resp *resp, const void *buf, int len);
void resp_add_chunked_iov(mc_resp *resp, const void *buf, int len);
bool resp_start(conn *c);
mc_resp* resp_finish(conn *c, mc_resp *resp);
bool resp_has_stack(conn *c);
bool rbuf_switch_to_malloc(conn *c);
void conn_release_items(conn *c);
void conn_set_state(conn *c, enum conn_states state);
void out_of_memory(conn *c, char *ascii_error);
void out_errstring(conn *c, const char *str);
void write_and_free(conn *c, char *buf, int bytes);
void server_stats(ADD_STAT add_stats, conn *c);
void append_stats(const char *key, const uint16_t klen,
                  const char *val, const uint32_t vlen,
                  const void *cookie);
/** Return a datum for stats in binary protocol */
bool get_stats(const char *stat_type, int nkey, ADD_STAT add_stats, void *c);
void stats_reset(void);
void process_stat_settings(ADD_STAT add_stats, void *c);
void process_stats_conns(ADD_STAT add_stats, void *c);

#if HAVE_DROP_PRIVILEGES
extern void setup_privilege_violations_handler(void);
extern void drop_privileges(void);
#else
#define setup_privilege_violations_handler()
#define drop_privileges()
#endif

#if HAVE_DROP_WORKER_PRIVILEGES
extern void drop_worker_privileges(void);
#else
#define drop_worker_privileges()
#endif

/* If supported, give compiler hints for branch prediction. */
#if !defined(__GNUC__) || (__GNUC__ == 2 && __GNUC_MINOR__ < 96)
#define __builtin_expect(x, expected_value) (x)
#endif

#define likely(x)       __builtin_expect((x),1)
#define unlikely(x)     __builtin_expect((x),0)

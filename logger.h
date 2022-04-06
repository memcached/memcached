/* logging functions */
#ifndef LOGGER_H
#define LOGGER_H

#include "bipbuffer.h"

/* TODO: starttime tunable */
#define LOGGER_BUF_SIZE 1024 * 64
#define LOGGER_WATCHER_BUF_SIZE 1024 * 256
#define LOGGER_ENTRY_MAX_SIZE 2048
#define GET_LOGGER() ((logger *) pthread_getspecific(logger_key));

/* Inlined from memcached.h - should go into sub header */
typedef unsigned int rel_time_t;

enum log_entry_type {
    LOGGER_ASCII_CMD = 0,
    LOGGER_EVICTION,
    LOGGER_ITEM_GET,
    LOGGER_ITEM_STORE,
    LOGGER_CRAWLER_STATUS,
    LOGGER_SLAB_MOVE,
    LOGGER_CONNECTION_NEW,
    LOGGER_CONNECTION_CLOSE,
#ifdef EXTSTORE
    LOGGER_EXTSTORE_WRITE,
    LOGGER_COMPACT_START,
    LOGGER_COMPACT_ABORT,
    LOGGER_COMPACT_READ_START,
    LOGGER_COMPACT_READ_END,
    LOGGER_COMPACT_END,
    LOGGER_COMPACT_FRAGINFO,
#endif
#ifdef PROXY
    LOGGER_PROXY_CONFIG,
    LOGGER_PROXY_RAW,
    LOGGER_PROXY_ERROR,
    LOGGER_PROXY_USER,
    LOGGER_PROXY_REQ,
    LOGGER_PROXY_BE_ERROR,
#endif
};

enum logger_ret_type {
    LOGGER_RET_OK = 0,
    LOGGER_RET_NOSPACE,
    LOGGER_RET_ERR
};

enum logger_parse_entry_ret {
    LOGGER_PARSE_ENTRY_OK = 0,
    LOGGER_PARSE_ENTRY_FULLBUF,
    LOGGER_PARSE_ENTRY_FAILED
};

typedef struct _logentry logentry;
typedef struct _entry_details entry_details;

typedef void (*entry_log_cb)(logentry *e, const entry_details *d, const void *entry, va_list ap);
typedef int (*entry_parse_cb)(logentry *e, char *scratch);

struct _entry_details {
    int reqlen;
    uint16_t eflags;
    entry_log_cb log_cb;
    entry_parse_cb parse_cb;
    char *format;
};

/* log entry intermediary structures */
struct logentry_eviction {
    long long int exptime;
    int nbytes;
    uint32_t latime;
    uint16_t it_flags;
    uint8_t nkey;
    uint8_t clsid;
    char key[];
};
#ifdef EXTSTORE
struct logentry_ext_write {
    long long int exptime;
    uint32_t latime;
    uint16_t it_flags;
    uint8_t nkey;
    uint8_t clsid;
    uint8_t bucket;
    char key[];
};
#endif
struct logentry_item_get {
    uint8_t was_found;
    uint8_t nkey;
    uint8_t clsid;
    int nbytes;
    int sfd;
    char key[];
};

struct logentry_item_store {
    int status;
    int cmd;
    rel_time_t ttl;
    uint8_t nkey;
    uint8_t clsid;
    int nbytes;
    int sfd;
    char key[];
};

struct logentry_conn_event {
    int transport;
    int reason;
    int sfd;
    struct sockaddr_in6 addr;
};
#ifdef PROXY
struct logentry_proxy_req {
    unsigned short type;
    unsigned short code;
    int status;
    uint32_t reqlen;
    size_t dlen;
    size_t be_namelen;
    size_t be_portlen;
    long elapsed;
    char data[];
};
#endif
/* end intermediary structures */

/* WARNING: cuddled items aren't compatible with warm restart. more code
 * necessary to ensure log streams are all flushed/processed before stopping
 */
struct _logentry {
    enum log_entry_type event;
    uint8_t pad;
    uint16_t eflags;
    uint64_t gid;
    struct timeval tv; /* not monotonic! */
    int size;
    union {
        char end;
    } data[];
};

#define LOG_SYSEVENTS  (1<<1) /* threads start/stop/working */
#define LOG_FETCHERS   (1<<2) /* get/gets/etc */
#define LOG_MUTATIONS  (1<<3) /* set/append/incr/etc */
#define LOG_SYSERRORS  (1<<4) /* malloc/etc errors */
#define LOG_CONNEVENTS (1<<5) /* new client, closed, etc */
#define LOG_EVICTIONS  (1<<6) /* details of evicted items */
#define LOG_STRICT     (1<<7) /* block worker instead of drop */
#define LOG_RAWCMDS    (1<<9) /* raw ascii commands */
#define LOG_PROXYREQS  (1<<10) /* command logs from proxy */
#define LOG_PROXYEVENTS (1<<11) /* error log stream from proxy */
#define LOG_PROXYUSER (1<<12) /* user generated logs from proxy */

typedef struct _logger {
    struct _logger *prev;
    struct _logger *next;
    pthread_mutex_t mutex; /* guard for this + *buf */
    uint64_t written; /* entries written to the buffer */
    uint64_t dropped; /* entries dropped */
    uint64_t blocked; /* times blocked instead of dropped */
    uint16_t fetcher_ratio; /* log one out of every N fetches */
    uint16_t mutation_ratio; /* log one out of every N mutations */
    uint16_t eflags; /* flags this logger should log */
    bipbuf_t *buf;
    const entry_details *entry_map;
} logger;

enum logger_watcher_type {
    LOGGER_WATCHER_STDERR = 0,
    LOGGER_WATCHER_CLIENT = 1
};

typedef struct  {
    void *c; /* original connection structure. still with source thread attached */
    int sfd; /* client fd */
    int id; /* id number for watcher list */
    uint64_t skipped; /* lines skipped since last successful print */
    uint64_t min_gid; /* don't show log entries older than this GID */
    bool failed_flush; /* recently failed to write out (EAGAIN), wait before retry */
    enum logger_watcher_type t; /* stderr, client, syslog, etc */
    uint16_t eflags; /* flags we are interested in */
    bipbuf_t *buf; /* per-watcher output buffer */
} logger_watcher;


struct logger_stats {
    uint64_t worker_dropped;
    uint64_t worker_written;
    uint64_t watcher_skipped;
    uint64_t watcher_sent;
    uint64_t watcher_count;
};

extern pthread_key_t logger_key;

/* public functions */

void logger_init(void);
void logger_stop(void);
logger *logger_create(void);

#define LOGGER_LOG(l, flag, type, ...) \
    do { \
        logger *myl = l; \
        if (l == NULL) \
            myl = GET_LOGGER(); \
        if (myl->eflags & flag) \
            logger_log(myl, type, __VA_ARGS__); \
    } while (0)

enum logger_ret_type logger_log(logger *l, const enum log_entry_type event, const void *entry, ...);

enum logger_add_watcher_ret {
    LOGGER_ADD_WATCHER_TOO_MANY = 0,
    LOGGER_ADD_WATCHER_OK,
    LOGGER_ADD_WATCHER_FAILED
};

enum logger_add_watcher_ret logger_add_watcher(void *c, const int sfd, uint16_t f);

/* functions used by restart system */
uint64_t logger_get_gid(void);
void logger_set_gid(uint64_t gid);

#endif

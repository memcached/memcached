/* logging functions */
#ifndef LOGGER_H
#define LOGGER_H

#include "bipbuffer.h"

/* TODO: starttime tunable */
#define LOGGER_BUF_SIZE 1024 * 64
#define LOGGER_THREAD_BUF_SIZE 1024 * 256
#define LOGGER_ENTRY_MAX_SIZE 2048
#define GET_LOGGER() ((logger *) pthread_getspecific(logger_key));

enum log_entry_type {
    LOGGER_ASCII_CMD = 0,
    LOGGER_EVICTION
};

enum log_entry_subtype {
    LOGGER_TEXT_ENTRY = 0,
    LOGGER_EVICTION_ENTRY
};

enum logger_ret_type {
    LOGGER_RET_OK = 0,
    LOGGER_RET_NOSPACE,
    LOGGER_RET_ERR
};

enum logger_parse_entry_ret {
    LOGGER_PARSE_ENTRY_OK = 0,
    LOGGER_PARSE_ENTRY_FULLBUF
};

typedef const struct {
    enum log_entry_subtype subtype;
    int reqlen;
    char *format;
} entry_details;

typedef struct _logentry {
    enum log_entry_subtype event;
    uint64_t gid;
    struct timeval tv; /* not monotonic! */
    int size;
    union {
        void *entry; /* probably an item */
        char end;
    } data[];
} logentry;

struct logger_eflags {
    unsigned int log_sysevents :1; /* threads start/stop/working */
    unsigned int log_fetchers :1; /* get/gets/etc */
    unsigned int log_mutations :1; /* set/append/incr/etc */
    unsigned int log_syserrors :1; /* malloc/etc errors */
    unsigned int log_connevents :1; /* new client, closed, etc */
    unsigned int log_vconnevents :1; /* client state changes */
    unsigned int log_evictions :1; /* log details of evicted items */
    unsigned int log_strict :1; /* block instead of drop */
    unsigned int log_time :1; /* log the time the entry is created */
};

typedef struct _logger {
    struct _logger *prev;
    struct _logger *next;
    pthread_mutex_t mutex; /* guard for this + *buf */
    uint64_t logged; /* entries written to the buffer */
    uint64_t dropped; /* entries dropped */
    uint64_t blocked; /* times blocked instead of dropped */
    uint16_t fetcher_ratio; /* log one out of every N fetches */
    uint16_t mutation_ratio; /* log one out of every N mutations */
    struct logger_eflags f; /* flags this logger should log */
    bipbuf_t *buf;
    const entry_details *entry_map;
} logger;

typedef struct _logger_chunk {
    struct _logger_chunk *next;
    int size; /* max potential size */
    int written; /* amount written into the buffer (actual size) */
    int refcount; /* number of attached watchers */
    unsigned int filled :1; /* reached storage max */
    char data[];
} logger_chunk;

enum logger_watcher_type {
    LOGGER_WATCHER_STDERR = 0,
    LOGGER_WATCHER_CLIENT = 1
};

typedef struct  {
    void *c; /* original connection structure. still with source thread attached */
    logger_chunk *lc;
    int chunks; /* count of chunks stored up */
    int sfd; /* client fd */
    int flushed; /* backlog data flushed so far from active chunk */
    int id; /* id number for watcher list */
    enum logger_watcher_type t; /* stderr, client, syslog, etc */
    struct logger_eflags f; /* flags we are interested in */
} logger_watcher;

extern pthread_key_t logger_key;

/* public functions */

void logger_init(void);
logger *logger_create(void);

enum logger_ret_type logger_log(logger *l, const enum log_entry_type event, const void *entry, ...);

enum logger_add_watcher_ret {
    LOGGER_ADD_WATCHER_TOO_MANY = 0,
    LOGGER_ADD_WATCHER_OK,
    LOGGER_ADD_WATCHER_FAILED
};

enum logger_add_watcher_ret logger_add_watcher(void *c, const int sfd, const struct logger_eflags);

#endif

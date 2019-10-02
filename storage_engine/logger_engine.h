/* logging functions */
#ifndef LOGGER_H
#define LOGGER_H

/* Inlined from memcached.h - should go into sub header */
typedef unsigned int rel_time_t;

enum log_entry_type {
    LOGGER_ASCII_CMD = 0,
    LOGGER_EVICTION,
    LOGGER_ITEM_GET,
    LOGGER_ITEM_STORE,
    LOGGER_CRAWLER_STATUS,
    LOGGER_SLAB_MOVE,
    LOGGER_STORAGE_WRITE,
};

enum log_entry_subtype {
    LOGGER_TEXT_ENTRY = 0,
    LOGGER_EVICTION_ENTRY,
    LOGGER_ITEM_GET_ENTRY,
    LOGGER_ITEM_STORE_ENTRY,
    LOGGER_EXT_WRITE_ENTRY,
};

enum logger_ret_type {
    LOGGER_RET_OK = 0,
    LOGGER_RET_NOSPACE,
    LOGGER_RET_ERR
};

typedef const struct {
    enum log_entry_subtype subtype;
    int reqlen;
    uint16_t eflags;
    char *format;
} entry_details;

#define LOG_SYSEVENTS  (1<<1) /* threads start/stop/working */
#define LOG_FETCHERS   (1<<2) /* get/gets/etc */
#define LOG_MUTATIONS  (1<<3) /* set/append/incr/etc */
#define LOG_SYSERRORS  (1<<4) /* malloc/etc errors */
#define LOG_CONNEVENTS (1<<5) /* new client, closed, etc */
#define LOG_EVICTIONS  (1<<6) /* details of evicted items */
#define LOG_STRICT     (1<<7) /* block worker instead of drop */
#define LOG_RAWCMDS    (1<<9) /* raw ascii commands */

#endif

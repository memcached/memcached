#ifndef STORAGE_ENGINE_H
#define STORAGE_ENGINE_H

#ifndef MEMCACHED_H
#include "memcached_engine.h"
#endif

typedef struct {
    /* Item */
    void (*item_lock)(uint32_t hv);
    void (*item_unlock)(uint32_t hv);
    item *(*assoc_find)(const char *key, const size_t nkey, const uint32_t hv);
    int (*item_is_flushed)(item *it);
    void (*do_item_remove)(item *it);
    bool (*item_is_cold)(item *it);  /* plugins may decide to evict items based on this */

    /* Statistics */
    void (*append_stat)(const char *name, ADD_STAT add_stats, conn *c, const char *fmt, ...);
    void (*add_stats)(const char *key, const uint16_t klen,
                      const char *val, const uint32_t vlen,
                      const void *cookie);

    /* Logging */
    /* Rely on storing logger key in thread attributes */
    int num_log_entry_types;  /* number of log entry types in core, so engine doesn't overlap with them */
    int (*logger_create)(void);
    enum logger_ret_type (*logger_log)(int flag, int type, const void *entry, ...);

    /* Storage reads */
    void (*queue_storage_read)(storage_read *rd);
    void (*respond_storage_read)(storage_read *rd);
    void (*complete_storage_read)(storage_read *rd, bool redispatch);

    rel_time_t (*get_current_time)(void);
} core_handle;

/*
 * Thread-safety
 * Functions to read/write items, read statistics, and update settings at runtime can be called by multiple threads.
 * Access to the engine's underlying storage and to any other state that is global to the engine, must be thread-safe.
 */
typedef struct {
    const char *name;
    const char *version;
    const char *memcached_version;

    /* Initialization */
    int (*init)(core_handle *core_h);

    /* Threads */
    void (*start_threads)(void);
    void (*pause_threads)(void);
    void (*resume_threads)(void);

    /* Storage */
    int locator_size;                             /* Size in bytes of an item locator. Needed to preallocate space for hdr item */
    int (*read_item)(storage_read *rd, storage_read *rdq, char *locator);
    int (*write_item)(item *it, uint32_t hv, char *locator);
    int (*delete_item)(item *it, char *locator);
    int (*check_item)(item *it, char *locator);   /* Verify that the item is still present in storage */
    int (*submit)(storage_read *rdq);             /* Wakes up read thread (if engine uses one) */

    /* Configuration */
    void (*apply_defaults)(struct settings *global_settings);  /* Apply engine defaults, which may depend on global settings */
    int (*read_config)(char **option);                         /* Read engine-specific settings */
    int (*check_config)(struct settings *global_settings);     /* Verify configuration after it is all loaded */
    char** (*usage)(unsigned int *size);                                         /* Provide usage info for the engine */
    bool (*process_storage_command)(char *setting, char *value1, char *value2);  /* Apply engine settings at runtime through "storage" command */

    void (*set_recache_rate)(unsigned int);  /* Used in decision to recache item */
    unsigned int (*get_recache_rate)(void);
    void (*set_item_age)(unsigned int);      /* Used in decision to move item to storage engine */
    unsigned int (*get_item_age)(void);

    /* Statistics */
    void (*get_storage_stats)(void *c);      /* Stats shown as part of server stats */
    void (*get_command_stats)(void *c);      /* Stats shown in response to specific "stats storage" command */
    void (*get_settings_stats)(void *c);     /* Shows settings */

    /* Logging */
    entry_details *log_entry_types;          /* Engine-specific log entry types. They will be combined with the core types */
    int num_log_entry_types;
} storage_engine;



#define STORAGE_LOGGER_LOG(core, flag, type, index, entry, ...) \
    do { \
       core->logger_log(flag, type+index, entry, __VA_ARGS__); \
    } while (0)


/** Append a simple stat with a stat name, value format and value */
#define STORAGE_APPEND_STAT(core, name, fmt, val) \
    core->append_stat(name, core->add_stats, c, fmt, val);

/** Append an indexed stat with a stat name (with format), value format
    and value */
#define STORAGE_APPEND_NUM_FMT_STAT(core, name_fmt, num, name, fmt, val)  \
    klen = snprintf(key_str, STAT_KEY_LEN, name_fmt, num, name);    \
    vlen = snprintf(val_str, STAT_VAL_LEN, fmt, val);               \
    core->add_stats(key_str, klen, val_str, vlen, c);

/** Common APPEND_NUM_FMT_STAT format. */
#define STORAGE_APPEND_NUM_STAT(core, num, name, fmt, val) \
    STORAGE_APPEND_NUM_FMT_STAT(core, "%d:%s", num, name, fmt, val)


#endif

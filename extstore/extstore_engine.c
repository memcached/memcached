#include "extstore_engine.h"
#include "extstore.h"
#include "crc32c.h"
#include "../util.h"
#include <stdlib.h>
#include <limits.h>
#include <sysexits.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>
#include <assert.h>

#define ENGINE_VERSION "1.0"
#define ENGINE_NAME "extstore"
#define ENGINE_MEMCACHED_VERSION "1.5.19"

static pthread_mutex_t stats_lock = PTHREAD_MUTEX_INITIALIZER;
#define STAT_L pthread_mutex_lock(&stats_lock);
#define STAT_UL pthread_mutex_unlock(&stats_lock);


int engine_init(core_handle *core_h);

void start_threads(void);
void storage_compact_pause(void);
void storage_compact_resume(void);

int read_item(storage_read *rd, storage_read *rdq, char *locator);
void read_item_cb(void *e, obj_io *io, int ret);
int write_item(item *it, uint32_t hv, char *locator);
int delete_item(item *it, char *locator);
int check_item(item *it, char *locator);

int submit(storage_read *rdq);

void apply_defaults(struct settings *global_settings);
int read_config(char **option);
int check_config(struct settings *global_settings);
char** usage(unsigned int *size);

void get_storage_stats(void *c);
void process_extstore_stats(void *c);
void get_settings_stats(void *c);

bool process_extstore_command(char *setting, char *value1, char *value2);

void set_recache_rate(unsigned int recache_rate);
unsigned int get_recache_rate(void);
void set_item_age(unsigned int item_age);
unsigned int get_item_age(void);


struct extstore_conf_file *storage_conf_parse(char *arg, unsigned int page_size);
int storage_write(item *it, uint32_t hv, char *locator, void *storage);
int start_storage_compact_thread(void *arg);


// Ignore pointers and header bits from the CRC
#define STORE_OFFSET offsetof(item, nbytes)

#define PAGE_BUCKET_DEFAULT 0
#define PAGE_BUCKET_COMPACT 1
#define PAGE_BUCKET_CHUNKED 2
#define PAGE_BUCKET_LOWTTL  3

core_handle *core;
void *storage;  // exstore-specific store_engine

// Configuration
struct extstore_conf_file *storage_file = NULL;
struct extstore_conf ext_cf;

struct extstore_settings {
    unsigned int ext_item_age; /* max age of tail item before storing ext. */
    unsigned int ext_low_ttl; /* remaining TTL below this uses own pages */
    unsigned int ext_recache_rate; /* counter++ % recache_rate == 0 > recache */
    unsigned int ext_wbuf_size; /* read only note for the engine */
    unsigned int ext_compact_under; /* when fewer than this many pages, compact */
    unsigned int ext_drop_under; /* when fewer than this many pages, drop COLD items */
    double ext_max_frag; /* ideal maximum page fragmentation */
    bool ext_drop_unread; /* skip unread items during compaction */
} ext_settings;


enum {
    EXT_PAGE_SIZE,
    EXT_WBUF_SIZE,
    EXT_THREADS,
    EXT_IO_DEPTH,
    EXT_PATH,
    EXT_LOW_TTL,
    EXT_COMPACT_UNDER,
    EXT_DROP_UNDER,
    EXT_MAX_FRAG,
    EXT_DROP_UNREAD,
};


char *const subopts_tokens[] = {
    [EXT_PAGE_SIZE] = "ext_page_size",
    [EXT_WBUF_SIZE] = "ext_wbuf_size",
    [EXT_THREADS] = "ext_threads",
    [EXT_IO_DEPTH] = "ext_io_depth",
    [EXT_PATH] = "ext_path",
    [EXT_LOW_TTL] = "ext_low_ttl",
    [EXT_COMPACT_UNDER] = "ext_compact_under",
    [EXT_DROP_UNDER] = "ext_drop_under",
    [EXT_MAX_FRAG] = "ext_max_frag",
    [EXT_DROP_UNREAD] = "ext_drop_unread",
    NULL
};

unsigned int usage_info_size = 24;
char *usage_info[255] = {
    "ext_path",           "file to write to for external storage.",
    ""        ,           "ie: ext_path=/mnt/d1/extstore:1G",
    "ext_page_size",      "size in megabytes of storage pages.",
    "ext_wbuf_size",      "size in megabytes of page write buffers.",
    "ext_threads",        "number of IO threads to run.",
    "ext_low_ttl",        "consider TTLs lower than this specially",
    "ext_drop_unread",    "don't re-write unread values during compaction",
    "ext_compact_under",  "compact when fewer than this many free pages",
    "ext_drop_under",     "drop COLD items when fewer than this many free pages",
    "ext_max_frag",       "max page fragmentation to tolerage",
    "slab_automove_freeratio", "ratio of memory to hold free as buffer.",
    "",                   "(see doc/storage.txt for more info)"
};


// Statistics
struct extstore_global_stats {
    uint64_t      extstore_compact_lost; /* items lost because they were locked */
    uint64_t      extstore_compact_rescues; /* items re-written during compaction */
    uint64_t      extstore_compact_skipped; /* unhit items skipped during compaction */
} ext_global_stats;


// Logging
enum extstore_log_entry_type {
    LOGGER_COMPACT_START,
    LOGGER_COMPACT_ABORT,
    LOGGER_COMPACT_READ_START,
    LOGGER_COMPACT_READ_END,
    LOGGER_COMPACT_END,
    LOGGER_COMPACT_FRAGINFO,
};

/* Should this go somewhere else? */
static const entry_details default_entries[] = {
    [LOGGER_COMPACT_START] = {LOGGER_TEXT_ENTRY, 512, LOG_SYSEVENTS,
        "type=compact_start id=%lu version=%llu"
    },
    [LOGGER_COMPACT_ABORT] = {LOGGER_TEXT_ENTRY, 512, LOG_SYSEVENTS,
        "type=compact_abort id=%lu"
    },
    [LOGGER_COMPACT_READ_START] = {LOGGER_TEXT_ENTRY, 512, LOG_SYSEVENTS,
        "type=compact_read_start id=%lu offset=%llu"
    },
    [LOGGER_COMPACT_READ_END] = {LOGGER_TEXT_ENTRY, 512, LOG_SYSEVENTS,
        "type=compact_read_end id=%lu offset=%llu rescues=%lu lost=%lu skipped=%lu"
    },
    [LOGGER_COMPACT_END] = {LOGGER_TEXT_ENTRY, 512, LOG_SYSEVENTS,
        "type=compact_end id=%lu"
    },
    [LOGGER_COMPACT_FRAGINFO] = {LOGGER_TEXT_ENTRY, 512, LOG_SYSEVENTS,
        "type=compact_fraginfo ratio=%.2f bytes=%lu"
    },
};

int log_entry_type_index = 0; /* index of log entry types for this plugin within global entry types */


storage_engine *create_engine() {
    storage_engine *engine = calloc(1, sizeof(storage_engine));
    if (engine == NULL) {
        return NULL;
    }

    engine->name = ENGINE_NAME;
    engine->version = ENGINE_VERSION;
    engine->memcached_version = ENGINE_MEMCACHED_VERSION;

    engine->init = engine_init;

    engine->start_threads = start_threads;
    engine->pause_threads = storage_compact_pause;
    engine->resume_threads = storage_compact_resume;

    engine->locator_size = sizeof(item_hdr);
    engine->read_item = read_item;
    engine->write_item = write_item;
    engine->delete_item = delete_item;
    engine->check_item = check_item;

    engine->submit = submit;

    engine->apply_defaults = apply_defaults;
    engine->read_config = read_config;
    engine->check_config = check_config;
    engine->usage = usage;
    engine->process_storage_command=process_extstore_command;

    engine->set_recache_rate = set_recache_rate;
    engine->get_recache_rate = get_recache_rate;
    engine->set_item_age = set_item_age;
    engine->get_item_age = get_item_age;

    engine->get_storage_stats = get_storage_stats;
    engine->get_command_stats = process_extstore_stats;
    engine->get_settings_stats = get_settings_stats;

    engine->log_entry_types = default_entries;
    engine->num_log_entry_types = 6;

    return engine;
}


int engine_init(core_handle *core_h) {
    core = core_h;

    log_entry_type_index = core->num_log_entry_types+1;

    if (storage_file) {
        enum extstore_res eres;
        if (ext_settings.ext_compact_under == 0) {
            ext_settings.ext_compact_under = storage_file->page_count / 4;
            /* Only rescues non-COLD items if below this threshold */
            ext_settings.ext_drop_under = storage_file->page_count / 4;
        }
        crc32c_init();
        storage = extstore_init(storage_file, &ext_cf, &eres);
        if (storage == NULL) {
            fprintf(stderr, "Failed to initialize external storage: %s\n",
                    extstore_err(eres));
            if (eres == EXTSTORE_INIT_OPEN_FAIL) {
                perror("extstore open");
            }
            exit(EXIT_FAILURE);
        }
    }

    if(storage) {
        return 0;
    }
    else
        return 1;
}



// FIXME: This completely breaks UDP support.
inline int read_item(storage_read *rd, storage_read *rdq, char *locator) {
#ifdef NEED_ALIGN
    item_hdr hdr;
    memcpy(&hdr, locator, sizeof(hdr));
#else
    item_hdr *hdr = (item_hdr *)locator;
#endif
    obj_io *io = malloc(sizeof(obj_io));
    if(io == NULL) {
        return 1;
    }
    rd->engine_data = io;

    // FIXME: error handling.
    // This is probably super dangerous. keep it at 0 and fill into wrap
    // object?
    if (rd->nchunks > 1) {  // chunked
        io->iov = &rd->iov[rd->iovused];
        io->iovcnt = rd->nchunks;
    } else {
        io->iov = NULL;
    }
    io->buf = (void *)rd->read_it;
    // The offset we'll fill in on a hit.

    // We need to stack the sub-struct IO's together as well.
    if (rdq) {
        io->next = rdq->engine_data;
    } else {
        io->next = NULL;
    }
    // IO queue for this connection.
    core->queue_storage_read(rd);
    // reference ourselves for the callback.
    io->data = (void *)rd;

    // Now, fill in io->io based on what was in our header.
#ifdef NEED_ALIGN
    io->page_version = hdr->page_version;
    io->page_id = hdr->page_id;
    io->offset = hdr->offset;
#else
    io->page_version = hdr->page_version;
    io->page_id = hdr->page_id;
    io->offset = hdr->offset;
#endif
    io->len = rd->ntotal;
    io->mode = OBJ_IO_READ;
    io->cb = read_item_cb;

    //fprintf(stderr, "EXTSTORE: IO stacked %u\n", io->iovec_data);

    return 0;
}

// FIXME: This runs in the IO thread. to get better IO performance this should
// simply mark the io wrapper with the return value and decrement wrapleft, if
// zero redispatching. Still a bit of work being done in the side thread but
// minimized at least.
void read_item_cb(void *e, obj_io *io, int ret) {
    // FIXME: assumes success
    storage_read *rd = (storage_read *)io->data;
    assert(rd->active == true);
    item *read_it = (item *)io->buf;
    bool miss = false;

    // TODO: How to do counters for hit/misses?
    if (ret < 1) {
        miss = true;
    } else {
        uint32_t crc2;
        uint32_t crc = (uint32_t) read_it->exptime;
        int x;
        // item is chunked, crc the iov's
        if (io->iov != NULL) {
            // first iov is the header, which we don't use beyond crc
            crc2 = crc32c(0, (char *)io->iov[0].iov_base+STORE_OFFSET, io->iov[0].iov_len-STORE_OFFSET);
            // make sure it's not sent. hack :(
            io->iov[0].iov_len = 0;
            for (x = 1; x < io->iovcnt; x++) {
                crc2 = crc32c(crc2, (char *)io->iov[x].iov_base, io->iov[x].iov_len);
            }
        } else {
            crc2 = crc32c(0, (char *)read_it+STORE_OFFSET, io->len-STORE_OFFSET);
        }

        if (crc != crc2) {
            miss = true;
            rd->badcrc = true;
        }
    }

    rd->miss = miss;
    core->respond_storage_read(rd);

    free(io);
    rd->engine_data = NULL;

    core->complete_storage_read(rd, true);
}


int write_item(item *it, uint32_t hv, char *locator) {
    return storage_write(it, hv, locator, storage);
}


int storage_write(item *it, uint32_t hv, char *locator, void *storage) {

    item_hdr *hdr;
    obj_io io;
    size_t orig_ntotal = ITEM_ntotal(it);

    int bucket = (it->it_flags & ITEM_CHUNKED) ?
            PAGE_BUCKET_CHUNKED : PAGE_BUCKET_DEFAULT;
    // Compress soon to expire items into similar pages.
    if (it->exptime - core->get_current_time() < ext_settings.ext_low_ttl) {
        bucket = PAGE_BUCKET_LOWTTL;
    }

    hdr = NULL;
    io.len = orig_ntotal;
    io.mode = OBJ_IO_WRITE;
    // NOTE: when the item is read back in, the slab mover
    // may see it. Important to have refcount>=2 or ~ITEM_LINKED
    assert(it->refcount >= 2);
    // NOTE: write bucket vs free page bucket will disambiguate once
    // lowttl feature is better understood.
    if (extstore_write_request(storage, bucket, bucket, &io) == 0) {
        // cuddle the hash value into the time field so we don't have
        // to recalculate it.
        item *buf_it = (item *) io.buf;
        buf_it->time = hv;
        // copy from past the headers + time headers.
        // TODO: should be in items.c
        if (it->it_flags & ITEM_CHUNKED) {
            // Need to loop through the item and copy
            item_chunk *sch = (item_chunk *) ITEM_schunk(it);
            int remain = orig_ntotal;
            int copied = 0;
            // copy original header
            int hdrtotal = ITEM_ntotal(it) - it->nbytes;
            memcpy((char *)io.buf+STORE_OFFSET, (char *)it+STORE_OFFSET, hdrtotal - STORE_OFFSET);
            copied = hdrtotal;
            // copy data in like it were one large object.
            while (sch && remain) {
                assert(remain >= sch->used);
                memcpy((char *)io.buf+copied, sch->data, sch->used);
                // FIXME: use one variable?
                        remain -= sch->used;
                        copied += sch->used;
                        sch = sch->next;
            }
        } else {
            memcpy((char *)io.buf+STORE_OFFSET, (char *)it+STORE_OFFSET, io.len-STORE_OFFSET);
        }
        // crc what we copied so we can do it sequentially.
        buf_it->it_flags &= ~ITEM_LINKED;
        buf_it->exptime = crc32c(0, (char*)io.buf+STORE_OFFSET, orig_ntotal-STORE_OFFSET);
        extstore_write(storage, &io);

        hdr = (item_hdr *)locator;
        hdr->page_version = io.page_version;
        hdr->page_id = io.page_id;
        hdr->offset  = io.offset;

        STORAGE_LOGGER_LOG(core, LOG_EVICTIONS, LOGGER_STORAGE_WRITE, 0, it, bucket);  // index is 0 because LOGGER_STORAGE_WRITE is a global entry type.
    }

    if(hdr)
        return 0;
    else
        return 1;
}


int delete_item(item *it, char *locator) {
    item_hdr *hdr = (item_hdr *)locator;
    return extstore_delete(storage, hdr->page_id, hdr->page_version, 1, ITEM_ntotal(it));
}


int check_item(item *it, char *locator) {
    item_hdr *hdr = (item_hdr *)locator;
    return extstore_check(storage, hdr->page_id, hdr->page_version);
}


int submit(storage_read *rdq) {
    return extstore_submit(storage, rdq->engine_data);
}


void apply_defaults(struct settings *global_settings) {
    ext_settings.ext_low_ttl = 0;
    ext_settings.ext_max_frag = 0.8;
    ext_settings.ext_drop_unread = false;
    ext_settings.ext_wbuf_size = 1024 * 1024 * 4;
    ext_settings.ext_compact_under = 0;
    ext_settings.ext_drop_under = 0;
    ext_cf.page_size = 1024 * 1024 * 64;
    ext_cf.wbuf_size = ext_settings.ext_wbuf_size;
    ext_cf.io_threadcount = 1;
    ext_cf.io_depth = 1;
    ext_cf.page_buckets = 4;
    ext_cf.wbuf_count = ext_cf.page_buckets;
}


/* Option should be in name=value form (from command line)
 * Returns 1 if the option is not valid.
 * Returns 0 if option is valid.
 */
int read_config(char **option) {
    char *subopts_value;

    switch (getsubopt(option, subopts_tokens, &subopts_value)) {
    case EXT_PAGE_SIZE:
        if (storage_file) {
            fprintf(stderr, "Must specify ext_page_size before any ext_path arguments\n");
            return 1;
        }
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_page_size argument\n");
            return 1;
        }
        if (!safe_strtoul(subopts_value, &ext_cf.page_size)) {
            fprintf(stderr, "could not parse argument to ext_page_size\n");
            return 1;
        }
        ext_cf.page_size *= 1024 * 1024; /* megabytes */
        break;
    case EXT_WBUF_SIZE:
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_wbuf_size argument\n");
            return 1;
        }
        if (!safe_strtoul(subopts_value, &ext_cf.wbuf_size)) {
            fprintf(stderr, "could not parse argument to ext_wbuf_size\n");
            return 1;
        }
        ext_cf.wbuf_size *= 1024 * 1024; /* megabytes */
        ext_settings.ext_wbuf_size = ext_cf.wbuf_size;
        break;
    case EXT_THREADS:
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_threads argument\n");
            return 1;
        }
        if (!safe_strtoul(subopts_value, &ext_cf.io_threadcount)) {
            fprintf(stderr, "could not parse argument to ext_threads\n");
            return 1;
        }
        break;
    case EXT_IO_DEPTH:
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_io_depth argument\n");
            return 1;
        }
        if (!safe_strtoul(subopts_value, &ext_cf.io_depth)) {
            fprintf(stderr, "could not parse argument to ext_io_depth\n");
            return 1;
        }
        break;
    case EXT_LOW_TTL:
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_low_ttl argument\n");
            return 1;
        }
        if (!safe_strtoul(subopts_value, &ext_settings.ext_low_ttl)) {
            fprintf(stderr, "could not parse argument to ext_low_ttl\n");
            return 1;
        }
        break;
    case EXT_COMPACT_UNDER:
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_compact_under argument\n");
            return 1;
        }
        if (!safe_strtoul(subopts_value, &ext_settings.ext_compact_under)) {
            fprintf(stderr, "could not parse argument to ext_compact_under\n");
            return 1;
        }
        break;
    case EXT_DROP_UNDER:
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_drop_under argument\n");
            return 1;
        }
        if (!safe_strtoul(subopts_value, &ext_settings.ext_drop_under)) {
            fprintf(stderr, "could not parse argument to ext_drop_under\n");
            return 1;
        }
        break;
    case EXT_MAX_FRAG:
        if (subopts_value == NULL) {
            fprintf(stderr, "Missing ext_max_frag argument\n");
            return 1;
        }
        if (!safe_strtod(subopts_value, &ext_settings.ext_max_frag)) {
            fprintf(stderr, "could not parse argument to ext_max_frag\n");
            return 1;
        }
        break;
    case EXT_DROP_UNREAD:
        ext_settings.ext_drop_unread = true;
        break;
    case EXT_PATH:
        if (subopts_value) {
            struct extstore_conf_file *tmp = storage_conf_parse(subopts_value, ext_cf.page_size);
            if (tmp == NULL) {
                fprintf(stderr, "failed to parse ext_path argument\n");
                return 1;
            }
            if (storage_file != NULL) {
                tmp->next = storage_file;
            }
            storage_file = tmp;
        } else {
            fprintf(stderr, "missing argument to ext_path, ie: ext_path=/d/file:5G\n");
            return 1;
        }
        break;
    default:
        return 1;
    }

    return 0;
}


/* Run after all configuration has been read */
int check_config(struct settings *settings) {
    if (storage_file) {
        if (settings->item_size_max > ext_cf.wbuf_size) {
            fprintf(stderr, "-I (item_size_max: %d) cannot be larger than ext_wbuf_size: %d\n",
                settings->item_size_max, ext_cf.wbuf_size);
            exit(EX_USAGE);
        }

        if (settings->udpport) {
            fprintf(stderr, "Cannot use UDP with extstore enabled (-U 0 to disable)\n");
            exit(EX_USAGE);
        }

        return 0;
    }
    else {
        return 1;
    }
}


char** usage(unsigned int *size) {
    *size = usage_info_size;
    return usage_info;
}


void get_storage_stats(void *c) {
    struct extstore_stats st;

    STAT_L;
    STORAGE_APPEND_STAT(core, "extstore_compact_lost", "%llu", (unsigned long long)ext_global_stats.extstore_compact_lost);
    STORAGE_APPEND_STAT(core, "extstore_compact_rescues", "%llu", (unsigned long long)ext_global_stats.extstore_compact_rescues);
    STORAGE_APPEND_STAT(core, "extstore_compact_skipped", "%llu", (unsigned long long)ext_global_stats.extstore_compact_skipped);
    STAT_UL;
    extstore_get_stats(storage, &st);
    STORAGE_APPEND_STAT(core, "extstore_page_allocs", "%llu", (unsigned long long)st.page_allocs);
    STORAGE_APPEND_STAT(core, "extstore_page_evictions", "%llu", (unsigned long long)st.page_evictions);
    STORAGE_APPEND_STAT(core, "extstore_page_reclaims", "%llu", (unsigned long long)st.page_reclaims);
    STORAGE_APPEND_STAT(core, "extstore_pages_free", "%llu", (unsigned long long)st.pages_free);
    STORAGE_APPEND_STAT(core, "extstore_pages_used", "%llu", (unsigned long long)st.pages_used);
    STORAGE_APPEND_STAT(core, "extstore_objects_evicted", "%llu", (unsigned long long)st.objects_evicted);
    STORAGE_APPEND_STAT(core, "extstore_objects_read", "%llu", (unsigned long long)st.objects_read);
    STORAGE_APPEND_STAT(core, "extstore_objects_written", "%llu", (unsigned long long)st.objects_written);
    STORAGE_APPEND_STAT(core, "extstore_objects_used", "%llu", (unsigned long long)st.objects_used);
    STORAGE_APPEND_STAT(core, "extstore_bytes_evicted", "%llu", (unsigned long long)st.bytes_evicted);
    STORAGE_APPEND_STAT(core, "extstore_bytes_written", "%llu", (unsigned long long)st.bytes_written);
    STORAGE_APPEND_STAT(core, "extstore_bytes_read", "%llu", (unsigned long long)st.bytes_read);
    STORAGE_APPEND_STAT(core, "extstore_bytes_used", "%llu", (unsigned long long)st.bytes_used);
    STORAGE_APPEND_STAT(core, "extstore_bytes_fragmented", "%llu", (unsigned long long)st.bytes_fragmented);
    STORAGE_APPEND_STAT(core, "extstore_limit_maxbytes", "%llu", (unsigned long long)(st.page_count * st.page_size));
    STORAGE_APPEND_STAT(core, "extstore_io_queue", "%llu", (unsigned long long)(st.io_queue));
}


void process_extstore_stats(void *c) {
    int i;
    char key_str[STAT_KEY_LEN];
    char val_str[STAT_VAL_LEN];
    int klen = 0, vlen = 0;
    struct extstore_stats st;

    extstore_get_stats(storage, &st);
    st.page_data = calloc(st.page_count, sizeof(struct extstore_page_data));
    if(st.page_data == NULL) {
        return;
    }
    extstore_get_page_data(storage, &st);

    for (i = 0; i < st.page_count; i++) {
        STORAGE_APPEND_NUM_STAT(core, i, "version", "%llu",
                (unsigned long long) st.page_data[i].version);
        STORAGE_APPEND_NUM_STAT(core, i, "bytes", "%llu",
                (unsigned long long) st.page_data[i].bytes_used);
        STORAGE_APPEND_NUM_STAT(core, i, "bucket", "%u",
                st.page_data[i].bucket);
        STORAGE_APPEND_NUM_STAT(core, i, "free_bucket", "%u",
                st.page_data[i].free_bucket);
    }

    free(st.page_data);
}


void get_settings_stats(void *c) {
    STORAGE_APPEND_STAT(core, "ext_low_ttl", "%u", ext_settings.ext_low_ttl);
    STORAGE_APPEND_STAT(core, "ext_wbuf_size", "%u", ext_settings.ext_wbuf_size);
    STORAGE_APPEND_STAT(core, "ext_compact_under", "%u", ext_settings.ext_compact_under);
    STORAGE_APPEND_STAT(core, "ext_drop_under", "%u", ext_settings.ext_drop_under);
    STORAGE_APPEND_STAT(core, "ext_max_frag", "%.2f", ext_settings.ext_max_frag);
    STORAGE_APPEND_STAT(core, "ext_drop_unread", "%s", ext_settings.ext_drop_unread ? "yes" : "no");
}



bool process_extstore_command(char *setting, char *value1, char *value2) {
    bool ok = true;
    if (strcmp(setting, "low_ttl") == 0) {
        if (!safe_strtoul(value1, &ext_settings.ext_low_ttl))
            ok = false;
    } else if (strcmp(setting, "compact_under") == 0) {
        if (!safe_strtoul(value1, &ext_settings.ext_compact_under))
            ok = false;
    } else if (strcmp(setting, "drop_under") == 0) {
        if (!safe_strtoul(value1, &ext_settings.ext_drop_under))
            ok = false;
    } else if (strcmp(setting, "max_frag") == 0) {
        if (!safe_strtod(value1, &ext_settings.ext_max_frag))
            ok = false;
    } else if (strcmp(setting, "drop_unread") == 0) {
        unsigned int v;
        if (!safe_strtoul(value1, &v)) {
            ok = false;
        } else {
            ext_settings.ext_drop_unread = v == 0 ? false : true;
        }
    } else {
        ok = false;
    }

    return ok;
}



void set_recache_rate(unsigned int recache_rate) {
    ext_settings.ext_recache_rate = recache_rate;
}

unsigned int get_recache_rate() {
    return ext_settings.ext_recache_rate;
}

void set_item_age(unsigned int item_age) {
    ext_settings.ext_item_age = item_age;
}

unsigned int get_item_age() {
    return ext_settings.ext_item_age;
}



/*** COMPACTOR ***/

/* Fetch stats from the external storage system and decide to compact.
 * If we're more than half full, start skewing how aggressively to run
 * compaction, up to a desired target when all pages are full.
 */
static int storage_compact_check(void *storage,
        uint32_t *page_id, uint64_t *page_version,
        uint64_t *page_size, bool *drop_unread) {
    struct extstore_stats st;
    int x;
    double rate;
    uint64_t frag_limit;
    uint64_t low_version = ULLONG_MAX;
    uint64_t lowest_version = ULLONG_MAX;
    unsigned int low_page = 0;
    unsigned int lowest_page = 0;
    extstore_get_stats(storage, &st);
    if (st.pages_used == 0)
        return 0;

    // lets pick a target "wasted" value and slew.
    if (st.pages_free > ext_settings.ext_compact_under)
        return 0;
    *drop_unread = false;

    // the number of free pages reduces the configured frag limit
    // this allows us to defrag early if pages are very empty.
    rate = 1.0 - ((double)st.pages_free / st.page_count);
    rate *= ext_settings.ext_max_frag;
    frag_limit = st.page_size * rate;
    STORAGE_LOGGER_LOG(core, LOG_SYSEVENTS, LOGGER_COMPACT_FRAGINFO, log_entry_type_index,
            NULL, rate, frag_limit);
    st.page_data = calloc(st.page_count, sizeof(struct extstore_page_data));
    if (st.page_data == NULL) {
        return 0; // If memory couldn't be allocated, don't start compaction.
    }
    extstore_get_page_data(storage, &st);

    // find oldest page by version that violates the constraint
    for (x = 0; x < st.page_count; x++) {
        if (st.page_data[x].version == 0 ||
            st.page_data[x].bucket == PAGE_BUCKET_LOWTTL)
            continue;
        if (st.page_data[x].version < lowest_version) {
            lowest_page = x;
            lowest_version = st.page_data[x].version;
        }
        if (st.page_data[x].bytes_used < frag_limit) {
            if (st.page_data[x].version < low_version) {
                low_page = x;
                low_version = st.page_data[x].version;
            }
        }
    }
    *page_size = st.page_size;
    free(st.page_data);

    // we have a page + version to attempt to reclaim.
    if (low_version != ULLONG_MAX) {
        *page_id = low_page;
        *page_version = low_version;
        return 1;
    } else if (lowest_version != ULLONG_MAX && ext_settings.ext_drop_unread
            && st.pages_free <= ext_settings.ext_drop_under) {
        // nothing matched the frag rate barrier, so pick the absolute oldest
        // version if we're configured to drop items.
        *page_id = lowest_page;
        *page_version = lowest_version;
        *drop_unread = true;
        return 1;
    }

    return 0;
}

static pthread_t storage_compact_tid;
static pthread_mutex_t storage_compact_plock;
#define MIN_STORAGE_COMPACT_SLEEP 10000
#define MAX_STORAGE_COMPACT_SLEEP 2000000

struct storage_compact_wrap {
    obj_io io;
    pthread_mutex_t lock; // gates the bools.
    bool done;
    bool submitted;
    bool miss; // version flipped out from under us
};

static void storage_compact_readback(void *storage,
        bool drop_unread, char *readback_buf,
        uint32_t page_id, uint64_t page_version, uint64_t read_size) {
    uint64_t offset = 0;
    unsigned int rescues = 0;
    unsigned int lost = 0;
    unsigned int skipped = 0;

    while (offset < read_size) {
        item *hdr_it = NULL;
        item_hdr *hdr = NULL;
        item *it = (item *)(readback_buf+offset);
        unsigned int ntotal;
        // probably zeroed out junk at the end of the wbuf
        if (it->nkey == 0) {
            break;
        }

        ntotal = ITEM_ntotal(it);
        uint32_t hv = (uint32_t)it->time;
        core->item_lock(hv);
        // We don't have a conn and don't need to do most of do_item_get
        hdr_it = core->assoc_find(ITEM_key(it), it->nkey, hv);
        if (hdr_it != NULL) {
            bool do_write = false;
            refcount_incr(hdr_it);

            // Check validity but don't bother removing it.
            if ((hdr_it->it_flags & ITEM_HDR) && !core->item_is_flushed(hdr_it) &&
                   (hdr_it->exptime == 0 || hdr_it->exptime > core->get_current_time())) {
                hdr = (item_hdr *)ITEM_data(hdr_it);
                if (hdr->page_id == page_id && hdr->page_version == page_version) {
                    // Item header is still completely valid.
                    extstore_delete(storage, page_id, page_version, 1, ntotal);
                    // drop inactive items.
                    if (drop_unread && core->item_is_cold(it)) {
                        do_write = false;
                        skipped++;
                    } else {
                        do_write = true;
                    }
                }
            }

            if (do_write) {
                bool do_update = false;
                int tries;
                obj_io io;
                io.len = ntotal;
                io.mode = OBJ_IO_WRITE;
                for (tries = 10; tries > 0; tries--) {
                    if (extstore_write_request(storage, PAGE_BUCKET_COMPACT, PAGE_BUCKET_COMPACT, &io) == 0) {
                        memcpy(io.buf, it, io.len);
                        extstore_write(storage, &io);
                        do_update = true;
                        break;
                    } else {
                        usleep(1000);
                    }
                }

                if (do_update) {
                    if (it->refcount == 2) {
                        hdr->page_version = io.page_version;
                        hdr->page_id = io.page_id;
                        hdr->offset = io.offset;
                        rescues++;
                    } else {
                        lost++;
                        // TODO: re-alloc and replace header.
                    }
                } else {
                    lost++;
                }
            }

            core->do_item_remove(hdr_it);
        }

        core->item_unlock(hv);
        offset += ntotal;
        if (read_size - offset < sizeof(struct _stritem))
            break;
    }

    STAT_L;
    ext_global_stats.extstore_compact_lost += lost;
    ext_global_stats.extstore_compact_rescues += rescues;
    ext_global_stats.extstore_compact_skipped += skipped;
    STAT_UL;
    STORAGE_LOGGER_LOG(core, LOG_SYSEVENTS, LOGGER_COMPACT_READ_END, log_entry_type_index,
            NULL, page_id, offset, rescues, lost, skipped);
}

static void _storage_compact_cb(void *e, obj_io *io, int ret) {
    struct storage_compact_wrap *wrap = (struct storage_compact_wrap *)io->data;
    assert(wrap->submitted == true);

    pthread_mutex_lock(&wrap->lock);

    if (ret < 1) {
        wrap->miss = true;
    }
    wrap->done = true;

    pthread_mutex_unlock(&wrap->lock);
}

// TODO: hoist the storage bits from lru_maintainer_thread in here.
// would be nice if they could avoid hammering the same locks though?
// I guess it's only COLD. that's probably fine.
static void *storage_compact_thread(void *arg) {
    void *storage = arg;
    useconds_t to_sleep = MAX_STORAGE_COMPACT_SLEEP;
    bool compacting = false;
    uint64_t page_version = 0;
    uint64_t page_size = 0;
    uint64_t page_offset = 0;
    uint32_t page_id = 0;
    bool drop_unread = false;
    char *readback_buf = NULL;
    struct storage_compact_wrap wrap;

    int ret = core->logger_create();
    if (ret == -1) {
        fprintf(stderr, "Failed to allocate logger for storage compaction thread\n");
        abort();
    }

    readback_buf = malloc(ext_settings.ext_wbuf_size);
    if (readback_buf == NULL) {
        fprintf(stderr, "Failed to allocate readback buffer for storage compaction thread\n");
        abort();
    }

    pthread_mutex_init(&wrap.lock, NULL);
    wrap.done = false;
    wrap.submitted = false;
    wrap.io.data = &wrap;
    wrap.io.buf = (void *)readback_buf;

    wrap.io.len = ext_settings.ext_wbuf_size;
    wrap.io.mode = OBJ_IO_READ;
    wrap.io.cb = _storage_compact_cb;
    pthread_mutex_lock(&storage_compact_plock);

    while (1) {
        pthread_mutex_unlock(&storage_compact_plock);
        if (to_sleep) {
            extstore_run_maint(storage);
            usleep(to_sleep);
        }
        pthread_mutex_lock(&storage_compact_plock);

        if (!compacting && storage_compact_check(storage,
                    &page_id, &page_version, &page_size, &drop_unread)) {
            page_offset = 0;
            compacting = true;
            STORAGE_LOGGER_LOG(core, LOG_SYSEVENTS, LOGGER_COMPACT_START, log_entry_type_index,
                    NULL, page_id, page_version);
        }

        if (compacting) {
            pthread_mutex_lock(&wrap.lock);
            if (page_offset < page_size && !wrap.done && !wrap.submitted) {
                wrap.io.page_version = page_version;
                wrap.io.page_id = page_id;
                wrap.io.offset = page_offset;
                // FIXME: should be smarter about io->next (unlink at use?)
                wrap.io.next = NULL;
                wrap.submitted = true;
                wrap.miss = false;

                extstore_submit(storage, &wrap.io);
            } else if (wrap.miss) {
                STORAGE_LOGGER_LOG(core, LOG_SYSEVENTS, LOGGER_COMPACT_ABORT, log_entry_type_index,
                        NULL, page_id);
                wrap.done = false;
                wrap.submitted = false;
                compacting = false;
            } else if (wrap.submitted && wrap.done) {
                STORAGE_LOGGER_LOG(core, LOG_SYSEVENTS, LOGGER_COMPACT_READ_START, log_entry_type_index,
                        NULL, page_id, page_offset);
                storage_compact_readback(storage, drop_unread,
                        readback_buf, page_id, page_version, ext_settings.ext_wbuf_size);
                page_offset += ext_settings.ext_wbuf_size;
                wrap.done = false;
                wrap.submitted = false;
            } else if (page_offset >= page_size) {
                compacting = false;
                wrap.done = false;
                wrap.submitted = false;
                extstore_close_page(storage, page_id, page_version);
                STORAGE_LOGGER_LOG(core, LOG_SYSEVENTS, LOGGER_COMPACT_END, log_entry_type_index, NULL, page_id);
            }
            pthread_mutex_unlock(&wrap.lock);

            if (to_sleep > MIN_STORAGE_COMPACT_SLEEP)
                to_sleep /= 2;
        } else {
            if (to_sleep < MAX_STORAGE_COMPACT_SLEEP)
                to_sleep += MIN_STORAGE_COMPACT_SLEEP;
        }
    }
    free(readback_buf);

    return NULL;
}

// TODO
// logger needs logger_destroy() to exist/work before this is safe.
/*int stop_storage_compact_thread(void) {
    int ret;
    pthread_mutex_lock(&lru_maintainer_lock);
    do_run_lru_maintainer_thread = 0;
    pthread_mutex_unlock(&lru_maintainer_lock);
    if ((ret = pthread_join(lru_maintainer_tid, NULL)) != 0) {
        fprintf(stderr, "Failed to stop LRU maintainer thread: %s\n", strerror(ret));
        return -1;
    }
    settings.lru_maintainer_thread = false;
    return 0;
}*/

void start_threads() {
    if (storage && start_storage_compact_thread(storage) != 0) {
        fprintf(stderr, "Failed to start storage compaction thread\n");
        exit(EXIT_FAILURE);
    }
}

void storage_compact_pause(void) {
    pthread_mutex_lock(&storage_compact_plock);
}

void storage_compact_resume(void) {
    pthread_mutex_unlock(&storage_compact_plock);
}

int start_storage_compact_thread(void *arg) {
    int ret;

    pthread_mutex_init(&storage_compact_plock, NULL);
    if ((ret = pthread_create(&storage_compact_tid, NULL,
        storage_compact_thread, arg)) != 0) {
        fprintf(stderr, "Can't create storage_compact thread: %s\n",
            strerror(ret));
        return -1;
    }

    return 0;
}

/*** UTILITY ***/
// /path/to/file:100G:bucket1
// FIXME: Modifies argument. copy instead?
struct extstore_conf_file *storage_conf_parse(char *arg, unsigned int page_size) {
    struct extstore_conf_file *cf = NULL;
    char *b = NULL;
    char *p = strtok_r(arg, ":", &b);
    char unit = 0;
    uint64_t multiplier = 0;
    int base_size = 0;
    if (p == NULL)
        goto error;
    // First arg is the filepath.
    cf = calloc(1, sizeof(struct extstore_conf_file));
    if(cf == NULL) {
        fprintf(stderr, "failed to allocate memory\n");
        goto error;
    }
    cf->file = strdup(p);

    p = strtok_r(NULL, ":", &b);
    if (p == NULL) {
        fprintf(stderr, "must supply size to ext_path, ie: ext_path=/f/e:64m (M|G|T|P supported)\n");
        goto error;
    }
    unit = tolower(p[strlen(p)-1]);
    p[strlen(p)-1] = '\0';
    // sigh.
    switch (unit) {
        case 'm':
            multiplier = 1024 * 1024;
            break;
        case 'g':
            multiplier = 1024 * 1024 * 1024;
            break;
        case 't':
            multiplier = 1024 * 1024;
            multiplier *= 1024 * 1024;
            break;
        case 'p':
            multiplier = 1024 * 1024;
            multiplier *= 1024 * 1024 * 1024;
            break;
    }
    base_size = atoi(p);
    multiplier *= base_size;
    // page_count is nearest-but-not-larger-than pages * psize
    cf->page_count = multiplier / page_size;
    assert(page_size * cf->page_count <= multiplier);

    // final token would be a default free bucket
    p = strtok_r(NULL, ",", &b);
    // TODO: We reuse the original DEFINES for now,
    // but if lowttl gets split up this needs to be its own set.
    if (p != NULL) {
        if (strcmp(p, "compact") == 0) {
            cf->free_bucket = PAGE_BUCKET_COMPACT;
        } else if (strcmp(p, "lowttl") == 0) {
            cf->free_bucket = PAGE_BUCKET_LOWTTL;
        } else if (strcmp(p, "chunked") == 0) {
            cf->free_bucket = PAGE_BUCKET_CHUNKED;
        } else if (strcmp(p, "default") == 0) {
            cf->free_bucket = PAGE_BUCKET_DEFAULT;
        } else {
            fprintf(stderr, "Unknown extstore bucket: %s\n", p);
            goto error;
        }
    } else {
        // TODO: is this necessary?
        cf->free_bucket = PAGE_BUCKET_DEFAULT;
    }

    // TODO: disabling until compact algorithm is improved.
    if (cf->free_bucket != PAGE_BUCKET_DEFAULT) {
        fprintf(stderr, "ext_path only presently supports the default bucket\n");
        goto error;
    }

    return cf;
error:
    if (cf) {
        if (cf->file)
            free(cf->file);
        free(cf);
    }
    return NULL;
}

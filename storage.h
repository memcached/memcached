#ifndef STORAGE_H
#define STORAGE_H

void storage_delete(void *e, item *it);
#ifdef EXTSTORE
#define STORAGE_delete(e, it) \
    do { \
        storage_delete(e, it); \
    } while (0)
#else
#define STORAGE_delete(...)
#endif

// API.
void storage_stats(ADD_STAT add_stats, conn *c);
void process_extstore_stats(ADD_STAT add_stats, conn *c);
bool storage_validate_item(void *e, item *it);
int storage_get_item(conn *c, item *it, mc_resp *resp);

// callbacks for the IO queue subsystem.
void storage_submit_cb(io_queue_t *q);
void storage_complete_cb(io_queue_t *q);
void storage_finalize_cb(io_pending_t *pending);

// Thread functions.
int start_storage_write_thread(void *arg);
void storage_write_pause(void);
void storage_write_resume(void);
int start_storage_compact_thread(void *arg);
void storage_compact_pause(void);
void storage_compact_resume(void);

// Init functions.
struct extstore_conf_file *storage_conf_parse(char *arg, unsigned int page_size);
void *storage_init_config(struct settings *s);
int storage_read_config(void *conf, char **subopt);
int storage_check_config(void *conf);
void *storage_init(void *conf);

// Ignore pointers and header bits from the CRC
#define STORE_OFFSET offsetof(item, nbytes)

#endif

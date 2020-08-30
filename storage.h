#ifndef STORAGE_H
#define STORAGE_H

void storage_submit_cb(void *ctx, io_pending_t *pending);
void storage_free_cb(void *ctx, io_pending_t *pending);
int start_storage_write_thread(void *arg);
void storage_write_pause(void);
void storage_write_resume(void);
int start_storage_compact_thread(void *arg);
void storage_compact_pause(void);
void storage_compact_resume(void);
struct extstore_conf_file *storage_conf_parse(char *arg, unsigned int page_size);

// Ignore pointers and header bits from the CRC
#define STORE_OFFSET offsetof(item, nbytes)

#endif

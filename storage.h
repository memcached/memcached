#ifndef STORAGE_H
#define STORAGE_H

int start_storage_write_thread(void *arg);
void storage_write_pause(void);
void storage_write_resume(void);
int start_storage_compact_thread(void *arg);
void storage_compact_pause(void);
void storage_compact_resume(void);

// Ignore pointers and header bits from the CRC
#define STORE_OFFSET offsetof(item, nbytes)

#endif

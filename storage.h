#ifndef STORAGE_H
#define STORAGE_H

int lru_maintainer_store(void *storage, const int clsid);
int start_storage_compact_thread(void *arg);
void storage_compact_pause(void);
void storage_compact_resume(void);

// Ignore pointers and header bits from the CRC
#define STORE_OFFSET offsetof(item, nbytes)

#endif

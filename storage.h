#ifndef STORAGE_H
#define STORAGE_H

#include "storage_engine/storage_engine.h"

storage_engine *load_engine(char *path);
void unload_engine(void);

int start_storage_write_thread(void *arg);
void storage_write_pause(void);
void storage_write_resume(void);

int storage_logger_create(void);
enum logger_ret_type storage_logger_log(int flag, int type, const void *entry, ...);

bool item_is_cold(item *it);

void queue_storage_read(storage_read *rd);
void respond_storage_read(storage_read *rd);
void complete_storage_read(storage_read *rd, bool redispatch);

rel_time_t get_current_time(void);

#endif

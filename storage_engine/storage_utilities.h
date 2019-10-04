#ifndef STORAGE_UTILITIES_H
#define STORAGE_UTILITIES_H

#include "memcached_engine.h"

int item_consolidate_chunks(item *cons_it, item *it);
int data_consolidate_chunks(char *cons_data, item *it);
void item_populate_chunks(storage_read *rd, void *it);
void data_populate_chunks(storage_read *rd, void *it);

#endif

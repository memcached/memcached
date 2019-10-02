#ifndef ITEM_ACCESS_TESTS_H
#define ITEM_ACCESS_TESTS_H

#include "test_helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *test_write(storage_engine *engine, char *key, char *value);
char *test_chunked_write(storage_engine *engine, char *key, char *value, unsigned int nperchunk);
void test_read(storage_engine *engine, char *locator, char *key, char *expvalue);
void test_delete(storage_engine *engine, char *locator, char *key, unsigned int nvalue);

#endif

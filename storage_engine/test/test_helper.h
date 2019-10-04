#ifndef TEST_HELPER_H
#define TEST_HELPER_H

#include "../storage_engine.h"

item *allocate_item(unsigned int nkey, unsigned int nvalue);
item *allocate_chunked_item(unsigned int nkey, unsigned int nchunks, unsigned int nperchunk);

item *generate_item(char* key, unsigned int nkey, char *value, unsigned int nvalue);
item *generate_hdr_item(char* key, unsigned int nkey, char *locator, unsigned int locator_size, unsigned int nvalue);
item *generate_chunked_item(char *key, unsigned int nkey, char *value, unsigned int nvalue, unsigned int nperchunk);

storage_read prepare_read(item *hdr_it);

core_handle create_core_mock(void);

#endif

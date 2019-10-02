#ifndef EXTSTORE_ENGINE_H
#define EXTSTORE_ENGINE_H

#include "../storage_engine/storage_engine.h"

typedef struct {
    unsigned int page_version; /* from IO header */
    unsigned int offset; /* from IO header */
    unsigned short page_id; /* from IO header */
} item_hdr;

__attribute__ ((visibility ("default"))) storage_engine *create_engine(void);

#endif

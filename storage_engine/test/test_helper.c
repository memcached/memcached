#include "test_helper.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

void queue_storage_read(storage_read *rd);
void respond_storage_read(storage_read *rd);
void complete_storage_read(storage_read *rd, bool redispatch);


item *allocate_item(unsigned int nkey, unsigned int nvalue) {
    item *it = calloc(1, sizeof(item) + nkey + 1 + nvalue);
    it->nkey = nkey;
    it->nbytes = nvalue;
    return it;
}

item *allocate_chunked_item(unsigned int nkey, unsigned int nchunks, unsigned int nperchunk) {
    unsigned int nvalue = nchunks*nperchunk;
    item *it = calloc(1, sizeof(item) + nkey + 1 + sizeof(item_chunk));
    it->nkey = nkey;
    it->nbytes = nvalue;
    it->it_flags |= ITEM_CHUNKED;

    item_chunk *ch = (item_chunk *) ITEM_schunk(it);
    ch->head = it;
    ch->prev = ch;
    ch->next = 0;
    ch->used = 0;
    ch->size = 0;

    // Allocate chunks
    for (int i = 0; i < nchunks; i++) {
        item_chunk *nch = calloc(1, sizeof(item_chunk) + nperchunk);
        nch->head = ch->head;
        ch->next = nch;
        nch->prev = ch;
        nch->next = 0;
        nch->used = 0;
        nch->size = nperchunk;
        nch->it_flags |= ITEM_CHUNK;
        ch = nch;
    }

    return it;
}

item *generate_item(char *key, unsigned int nkey, char *value, unsigned int nvalue) {
    item *it = allocate_item(nkey, nvalue);
    memcpy(ITEM_key(it), key, nkey);
    *(ITEM_key(it)+nkey) = '\0';  // null-terminate key
    memcpy(ITEM_data(it), value, nvalue);
    return it;
}

item *generate_hdr_item(char *key, unsigned int nkey, char *locator, unsigned int locator_size, unsigned int nvalue) {
    item *it = generate_item(key, nkey, locator, locator_size);
    it->nbytes = nvalue;
    it->it_flags |= ITEM_HDR;
    return it;
}

item *generate_chunked_item(char *key, unsigned int nkey, char *value, unsigned int nvalue, unsigned int nperchunk) {
    unsigned int nchunks = nvalue/nperchunk;
    if (nvalue%nperchunk != 0) {
        nchunks++;
    }

    item *it = allocate_chunked_item(nkey, nchunks, nperchunk);
    memcpy(ITEM_key(it), key, nkey);
    *(ITEM_key(it)+nkey) = '\0';  // null-terminate key

    item_chunk *ch = (item_chunk *) ITEM_schunk(it);
    ch = ch->next;
    unsigned int offset = 0;
    for (int i = 0; i < nchunks; i++) {
        unsigned int ncopy = nperchunk;
        if ((offset+nperchunk) >= nvalue) {
            ncopy = nvalue-offset;
        }
        memcpy(ch->data, value+offset, ncopy);
        offset += ncopy;
        ch->used = ncopy;
        ch = ch->next;
    }

    return it;
}


storage_read prepare_read(item *hdr_it) {
    item *read_it = allocate_item(hdr_it->nkey, hdr_it->nbytes);
    memcpy(ITEM_key(read_it), ITEM_key(hdr_it), hdr_it->nkey);

    storage_read rd;
    rd.hdr_it = hdr_it;
    rd.read_it = read_it;
    rd.nchunks = 1;
    rd.ntotal = ITEM_ntotal(hdr_it);
    rd.active = true;
    rd.next = NULL;

    return rd;
}




void queue_storage_read(storage_read *rd) {}

void respond_storage_read(storage_read *rd) {}

void complete_storage_read(storage_read *rd, bool redispatch) {
    rd->active = false;
}


core_handle create_core_mock() {
    core_handle core;

    core.queue_storage_read = queue_storage_read;
    core.respond_storage_read = respond_storage_read;
    core.complete_storage_read = complete_storage_read;

    return core;
}

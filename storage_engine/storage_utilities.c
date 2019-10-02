/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "storage_utilities.h"
#include <string.h>
#include <assert.h>

/* Consolidate chunked items (it places all chunks sequentially).
 * if copy_header == true, cons will contain header (metadata+key) + consolidated data from all chunks
 * if copy_header == false, cons will contain consolidated data from all chunks (no header)
 */
int consolidate_chunks(char *cons, item *it, bool copy_header) {
    int orig_ntotal = ITEM_ntotal(it);
    int nchunks = 0;  // count includes header */

    if (it->it_flags & ITEM_CHUNKED) {
        // Need to loop through the item and copy
        item_chunk *sch = (item_chunk *) ITEM_schunk(it);
        int remain = orig_ntotal;
        int copied = 0;
        // copy original header
        if (copy_header) {
            int hdrtotal = ITEM_ntotal(it) - it->nbytes;
            memcpy(cons, (char *)it, hdrtotal);
            copied = hdrtotal;
        }
        // copy data in like it were one large object.
        while (sch && remain) {
            assert(remain >= sch->used);
            memcpy(cons+copied, sch->data, sch->used);
            // FIXME: use one variable?
            remain -= sch->used;
            copied += sch->used;
            sch = sch->next;
            nchunks++;
        }
    } else {
        nchunks = 1;
        if(copy_header) {
            memcpy(cons, (char *)it, orig_ntotal);
        } else {
            memcpy(cons, ITEM_data(it), it->nbytes);
        }
    }

    return nchunks;
}

int item_consolidate_chunks(item *cons_it, item *it) {
    return consolidate_chunks((char *)cons_it, it, true);
}

int data_consolidate_chunks(char *cons_data, item *it) {
    return consolidate_chunks(cons_data, it, false);
}


/* Given an item with all chunks sequentially, read into iovs for chunked item */
void item_populate_chunks(storage_read *rd, void *it) {
    if (rd->nchunks > 1) {
        struct iovec *iov;

        int offset = 0;
        for(int i = 0; i < rd->nchunks; i++) {
            iov = &rd->iov[rd->iovused+i];
            memcpy(iov->iov_base, (char *)it+offset, iov->iov_len);
            offset += iov->iov_len;

            // first iov is the header, which we don't use beyond crc
            // make sure it's not sent. hack :(
            if(i == 0)
                iov->iov_len = 0;
        }
    } else {
        memcpy(rd->read_it, it, rd->ntotal);
    }
}

/* Similar to item_populate_chunks, but metadata+key are preserved from rd->read_it and only data is populated */
void data_populate_chunks(storage_read *rd, void *data) {
    int hdrkey_size = rd->ntotal-rd->hdr_it->nbytes;

    if (rd->nchunks > 1) {
        struct iovec *iov;

        // First iov is the header
        // Don't worry about populating it as it will not be sent back anyway. hack :(
        iov = &rd->iov[rd->iovused];
        iov->iov_len = 0;

        int offset = 0;
        for(int i = 1; i < rd->nchunks; i++) {
            iov = &rd->iov[rd->iovused+i];
            memcpy(iov->iov_base, (char *)data+offset, iov->iov_len);
            offset += iov->iov_len;
        }
        // Data does not contain \r\n
        ((char *)iov->iov_base)[iov->iov_len-2] = '\r';
        ((char *)iov->iov_base)[iov->iov_len-1] = '\n';
    } else {
        rd->read_it->it_flags = rd->hdr_it->it_flags & ~ITEM_HDR;  // remove the hdr flag, as this is a full item
        rd->read_it->time = 0;  // hash value was not cuddled in time field. This will force recalculating.

        memcpy(((char *)(rd->read_it))+hdrkey_size, data, rd->read_it->nbytes);
        ((char *)rd->read_it)[rd->ntotal] = '\r';
        ((char *)rd->read_it)[rd->ntotal+1] = '\n';
    }
}

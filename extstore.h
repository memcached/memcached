#ifndef EXTSTORE_H
#define EXTSTORE_H

// TODO: Temporary configuration structure. A "real" library should have an
// extstore_set(enum, void *ptr) which hides the implementation.
// this is plenty for quick development.
struct extstore_conf {
    unsigned int page_size; // ideally 64-256M in size
    unsigned int page_count;
    unsigned int page_buckets; // number of different writeable pages
    unsigned int wbuf_size; // must divide cleanly into page_size
    unsigned int wbuf_count; // this might get locked to "2 per active page"
    unsigned int io_threadcount;
    unsigned int io_depth; // with normal I/O, hits locks less. req'd for AIO
};

enum obj_io_mode {
    OBJ_IO_READ = 0,
    OBJ_IO_WRITE,
};

typedef struct _obj_io obj_io;
typedef void (*obj_io_cb)(void *e, obj_io *io, int ret);

/* An object for both reads and writes to the storage engine.
 * Once an IO is submitted, ->next may be changed by the IO thread. It is not
 * safe to further modify the IO stack until the entire request is completed.
 */
struct _obj_io {
    void *data; /* user supplied data pointer */
    struct _obj_io *next;
    char *buf;  /* buffer of data to read or write to */
    uint64_t page_version;     /* page version for read mode */
    unsigned int len;     /* for both modes */
    unsigned int page_id; /* for read mode */
    unsigned int offset;  /* for read mode */
    enum obj_io_mode mode;
    /* callback pointers? */
    obj_io_cb cb;
};

void *extstore_init(char *fn, struct extstore_conf *cf);
int extstore_write(void *ptr, unsigned int bucket, obj_io *io);
int extstore_submit(void *ptr, obj_io *io);
int extstore_delete(void *ptr, unsigned int page_id, uint64_t page_version, unsigned int count);

#endif

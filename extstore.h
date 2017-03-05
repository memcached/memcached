#ifndef EXTSTORE_H
#define EXTSTORE_H

enum obj_io_mode {
    OBJ_IO_READ = 0,
    OBJ_IO_WRITE,
};

typedef struct _obj_io obj_io;
typedef void (*obj_io_cb)(void *e, obj_io *io, int ret);

/* An object for both reads and writes to the storage engine.
 */
typedef struct _obj_io {
    void *data; /* user supplied data pointer */
    struct _obj_io *next;
    char *buf;  /* buffer of data to read or write to */
    unsigned int len;
    unsigned int ttl;     /* for write mode */
    unsigned int page_id; /* for read mode */
    unsigned int offset;  /* for read mode */
    enum obj_io_mode mode;
    /* callback pointers? */
    obj_io_cb cb;
} obj_io;

void *extstore_init(char *fn, size_t pgsize, size_t pgcount, size_t wbufsize);
int extstore_write(void *ptr, obj_io *io);
int extstore_read(void *ptr, obj_io *io);

#endif

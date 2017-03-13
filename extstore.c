/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

// FIXME: config.h?
#include <stdint.h>
#include <stdbool.h>
// end FIXME
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h> // FIXME: only when DEBUG compiled?
#include <string.h>
#include <assert.h>
#include "extstore.h"

/* TODO: manage the page refcount */

/* TODO: Embed obj_io for internal wbuf's. change extstore_read to
 * extstore_submit.
 */
typedef struct __store_wbuf {
    struct __store_wbuf *next;
    struct __store_wbuf *page_next; /* second linked list for page usage */
    char *buf;
    char *buf_pos;
    unsigned int free;
    unsigned int size;
    unsigned int page_id; /* page owner of this write buffer */
    unsigned int offset; /* offset into page this write starts at */
    bool full; /* done writing to this page */
    bool flushed; /* whether wbuf has been flushed to disk */
} _store_wbuf;

typedef struct _store_page {
    pthread_mutex_t mutex; /* Need to be held for most operations */
    uint64_t version;
    uint64_t obj_count;
    uint64_t offset; /* starting address of page within fd */
    unsigned int refcount;
    unsigned int id;
    unsigned int allocated;
    unsigned int written; /* item offsets can be past written if wbuf not flushed */
    int fd;
    bool active;
    _store_wbuf *wbuf; /* currently active wbuf from the stack */
    _store_wbuf *wbuf_stack; /* ordered stack of wbuf's being flushed to disk */
    struct _store_page *next;
    uint64_t histo[61];
} store_page;

typedef struct store_engine store_engine;
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    obj_io *queue;
    _store_wbuf *wbuf_queue;
    store_engine *e;
} store_io_thread;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    store_engine *e;
} store_maint_thread;

/* TODO: Array of FDs for JBOD support */
struct store_engine {
    pthread_mutex_t mutex; /* Need to hold to find active write page */
    pthread_mutex_t io_mutex; /* separate mutex for IO submissions */
    store_page *pages;
    _store_wbuf *wbuf_stack;
    store_io_thread *io_threads;
    store_maint_thread *maint_thread;
    store_page *page_stack;
    size_t page_size;
    uint64_t version; /* global version counter */
    unsigned int last_io_thread; /* round robin the IO threads */
    unsigned int io_threadcount; /* count of IO threads */
    unsigned int page_count;
    unsigned int page_free; /* unallocated pages */
    unsigned int low_ttl_page;
    unsigned int high_ttl_page;
    unsigned int io_depth; /* FIXME: Might cache into thr struct */
};

static _store_wbuf *wbuf_new(size_t size) {
    _store_wbuf *b = calloc(1, sizeof(_store_wbuf));
    if (b == NULL)
        return NULL;
    b->buf = malloc(size);
    if (b->buf == NULL) {
        free(b);
        return NULL;
    }
    b->buf_pos = b->buf;
    b->free = size;
    b->size = size;
    return b;
}

static store_io_thread *_get_io_thread(store_engine *e) {
    int tid;
    pthread_mutex_lock(&e->mutex);
    tid = (e->last_io_thread + 1) % e->io_threadcount;
    e->last_io_thread = tid;
    pthread_mutex_unlock(&e->mutex);

    return &e->io_threads[tid];
}

static uint64_t _next_version(store_engine *e) {
    return e->version++;
}

static void *extstore_io_thread(void *arg);
static void *extstore_maint_thread(void *arg);

/* TODO: engine init function; takes file, page size, total size arguments */
/* also directio/aio optional? thread pool size? options struct? ttl
 * threshold? */

/* Open file.
 * fill **pages
 * error if page size > 4g
 * (fallocate?)
 * allocate write buffers
 * set initial low/high pages
 * spawn threads
 * return void pointer to engine context.
 */

/* TODO: debug mode with prints? error code? */
// TODO: Somehow pass real error codes from config failures
void *extstore_init(char *fn, struct extstore_conf *cf) {
    int i;
    int fd;
    uint64_t offset = 0;
    pthread_t thread;

    if (cf->page_size % cf->wbuf_size != 0) {
        return NULL;
    }

    // TODO: More intelligence around alignment of flash erasure block sizes
    if (cf->page_size % (1024 * 1024 * 2) != 0 ||
        cf->wbuf_size % (1024 * 1024 * 2) != 0) {
        return NULL;
    }

    store_engine *e = calloc(1, sizeof(store_engine));
    if (e == NULL) {
        return NULL;
    }

    e->page_size = cf->page_size;
    fd = open(fn, O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(e);
        return NULL;
    }

    e->pages = calloc(cf->page_count, sizeof(store_page));
    if (e->pages == NULL) {
        close(fd);
        free(e);
        return NULL;
    }

    for (i = 0; i < cf->page_count; i++) {
        e->pages[i].id = i;
        e->pages[i].fd = fd;
        e->pages[i].offset = offset;
        offset += e->page_size;
    }

    for (i = cf->page_count; i > 1; i--) {
        e->pages[i].next = e->page_stack;
        e->page_stack = &e->pages[i];
        e->page_free++;
    }

    e->page_count = cf->page_count;
    /* TODO: Lazy allocate page categories */
    e->low_ttl_page = 0;
    e->pages[0].active = true;
    e->high_ttl_page = 1;
    e->pages[1].active = true;

    /* allocate write buffers */
    for (i = 0; i < cf->wbuf_count; i++) {
        _store_wbuf *w = wbuf_new(cf->wbuf_size);
        /* TODO: on error, loop again and free stack. */
        w->next = e->wbuf_stack;
        e->wbuf_stack = w;
    }

    pthread_mutex_init(&e->mutex, NULL);
    pthread_mutex_init(&e->io_mutex, NULL);

    e->io_depth = cf->io_depth;

    /* spawn threads */
    e->io_threads = calloc(cf->io_threadcount, sizeof(store_io_thread));
    for (i = 0; i < cf->io_threadcount; i++) {
        pthread_mutex_init(&e->io_threads[i].mutex, NULL);
        pthread_cond_init(&e->io_threads[i].cond, NULL);
        e->io_threads[i].e = e;
        // FIXME: error handling
        pthread_create(&thread, NULL, extstore_io_thread, &e->io_threads[i]);
    }
    e->io_threadcount = cf->io_threadcount;

    e->maint_thread = calloc(1, sizeof(store_maint_thread));
    e->maint_thread->e = e;
    // FIXME: error handling
    pthread_create(&thread, NULL, extstore_maint_thread, &e->maint_thread);

    return (void *)e;
}

/* engine write function; takes engine, item_io.
 * fast fail if no available write buffer (flushing)
 * lock engine context, find active page, unlock
 * rotate buffers? active/passive
 * if full and rotated, submit page/buffer to io thread.
 * return status code
 */

int extstore_write(void *ptr, obj_io *io) {
    store_engine *e = (store_engine *)ptr;
    store_page *p;
    int ret = -1;

    /* This is probably a loop; we continue if the output page had to be
     * replaced
     */
    pthread_mutex_lock(&e->mutex);
    p = &e->pages[e->low_ttl_page];
    pthread_mutex_unlock(&e->mutex);
    /* FIXME: Is it safe to lock here? Need to double check the flag and loop
     * or lock from within e->mutex
     */

    pthread_mutex_lock(&p->mutex);
    if (!p->active) {
        pthread_mutex_unlock(&p->mutex);
        fprintf(stderr, "EXTSTORE: WRITE PAGE INACTIVE!\n");
        return -1;
    }

    /* memcpy into wbuf */
    if (p->wbuf && (p->wbuf->free < io->len || p->wbuf->full)) {
        /* Submit to IO thread */
        /* FIXME: enqueue_io command, use an obj_io? */
        if (!p->wbuf->full) {
            store_io_thread *t = _get_io_thread(e);
            pthread_mutex_lock(&t->mutex);
            /* FIXME: Track tail and do FIFO instead of LIFO */
            p->wbuf->next = t->wbuf_queue;
            t->wbuf_queue = p->wbuf;
            pthread_mutex_unlock(&t->mutex);
            pthread_cond_signal(&t->cond);
            p->wbuf->full = true;
        }

        // Flushed buffer to now-full page, assign a new one.
        if (p->allocated >= e->page_size) {
            fprintf(stderr, "EXTSTORE: allocating new page\n");
            // TODO: Pages assigned inline or from bg thread?
            pthread_mutex_lock(&e->mutex);
            if (e->page_free > 0) {
                assert(e->page_stack != NULL);
                e->low_ttl_page = e->page_stack->id;
                e->page_stack->active = true;
                e->page_stack->version = _next_version(e);
                e->page_stack = e->page_stack->next;
                e->page_free--;
            }
            pthread_mutex_unlock(&e->mutex);
            // FIXME: This falls through and fails.
        }
    }

    // TODO: e->page_size safe for dirty reads? "cache" into page object?
    if (!p->wbuf || p->wbuf->full) {
        if (p->allocated < e->page_size) {
            _store_wbuf *wbuf = NULL;
            /* TODO: give the engine specific mutexes around things?
             * would have to ensure struct is padded to avoid false-sharing
             */
            pthread_mutex_lock(&e->mutex);
            if (e->wbuf_stack) {
                wbuf = e->wbuf_stack;
                e->wbuf_stack = wbuf->next;
                wbuf->next = 0;
            }
            pthread_mutex_unlock(&e->mutex);
            if (wbuf) {
                wbuf->page_id = p->id;

                wbuf->offset = p->allocated;
                p->allocated += wbuf->size;
                wbuf->free = wbuf->size;
                wbuf->buf_pos = wbuf->buf;
                wbuf->page_next = NULL;
                wbuf->full = false;
                wbuf->flushed = false;

                // maintain the tail.
                if (p->wbuf) {
                    p->wbuf->page_next = wbuf;
                }
                p->wbuf = wbuf;
                if (!p->wbuf_stack) {
                    p->wbuf_stack = wbuf;
                }
            }
        }
    }

    if (p->wbuf && !p->wbuf->full && p->wbuf->free >= io->len) {
        memcpy(p->wbuf->buf_pos, io->buf, io->len);
        io->page_id = p->id;
        io->offset = p->wbuf->offset + (p->wbuf->size - p->wbuf->free);
        io->page_version = p->version;
        p->wbuf->buf_pos += io->len;
        p->wbuf->free -= io->len;
        p->obj_count++;
        ret = 0;
    }

    pthread_mutex_unlock(&p->mutex);
    /* p->written is incremented post-wbuf flush */
    return ret;
}

/* allocate new pages in here or another buffer? */

/* engine read function; takes engine, item_io stack.
 * lock io_thread context and add stack?
 * signal io thread to wake.
 * return sucess.
 */
int extstore_read(void *ptr, obj_io *io) {
    store_engine *e = (store_engine *)ptr;
    store_io_thread *t = _get_io_thread(e);

    pthread_mutex_lock(&t->mutex);
    if (t->queue == NULL) {
        t->queue = io;
    } else {
        /* Have to put the *io stack at the end of current queue.
         * Optimize by tracking tail.
         */
        obj_io *tmp = t->queue;
        while (tmp->next != NULL) {
            tmp = tmp->next;
            assert(tmp != t->queue); // FIXME: Temporary loop detection
        }
        tmp->next = io;
    }
    pthread_mutex_unlock(&t->mutex);

    //pthread_mutex_lock(&t->mutex);
    pthread_cond_signal(&t->cond);
    //pthread_mutex_unlock(&t->mutex);
    return 0;
}

/* engine note delete function: takes engine, page id, size?
 * note that an item in this page is no longer valid
 */

// call with page locked
// FIXME: protect from reading past wbuf
static inline int _read_from_wbuf(store_page *p, obj_io *io) {
    unsigned int offset = io->offset;
    unsigned int bytes = p->written;
    // start at head of wbuf stack, then subtract-and-conquer
    _store_wbuf *wbuf = p->wbuf_stack;
    while (wbuf) {
        if (bytes + wbuf->size < offset) {
            bytes += wbuf->size;
            wbuf = wbuf->page_next;
        } else {
            break;
        }
    }
    assert(wbuf != NULL); // shouldn't have invalid offsets
    memcpy(io->buf, p->wbuf->buf + (io->offset - p->wbuf->offset), io->len);
    return io->len;
}

/* engine IO thread; takes engine context
 * manage writes/reads :P
 * run callback any necessary callback commands?
 */
// FIXME: protect from reading past page
static void *extstore_io_thread(void *arg) {
    store_io_thread *me = (store_io_thread *)arg;
    store_engine *e = me->e;
    while (1) {
        obj_io *io_stack = NULL;
        _store_wbuf *wbuf_stack = NULL;
        // TODO: lock/check queue before going into wait
        pthread_mutex_lock(&me->mutex);
        if (me->queue == NULL && me->wbuf_queue == NULL) {
            pthread_cond_wait(&me->cond, &me->mutex);
        }

        if (me->wbuf_queue != NULL) {
            int i;
            _store_wbuf *end = NULL;
            wbuf_stack = me->wbuf_queue;
            end = wbuf_stack;
            /* Pull and disconnect a batch from the queue */
            for (i = 1; i < e->io_depth; i++) {
                if (end->next) {
                    end = end->next;
                } else {
                    break;
                }
            }
            me->wbuf_queue = end->next;
            end->next = NULL;
        }

        if (me->queue != NULL) {
            int i;
            obj_io *end = NULL;
            io_stack = me->queue;
            end = io_stack;
            // Pull and disconnect a batch from the queue
            for (i = 1; i < e->io_depth; i++) {
                if (end->next) {
                    end = end->next;
                } else {
                    break;
                }
            }
            me->queue = end->next;
            end->next = NULL;
        }
        pthread_mutex_unlock(&me->mutex);

        /* TODO: Direct IO + libaio mode */
        _store_wbuf *cur_wbuf = wbuf_stack;
        while (cur_wbuf) {
            _store_wbuf *next = cur_wbuf->next;
            int ret;
            store_page *p = &e->pages[cur_wbuf->page_id];
            ret = pwrite(p->fd, cur_wbuf->buf, cur_wbuf->size - cur_wbuf->free,
                    p->offset + cur_wbuf->offset);
            // FIXME: Remove.
            if (ret == 0) {
                fprintf(stderr, "Write returned 0 bytes for some reason\n");
            }
            if (ret < 0) {
                perror("wbuf write failed");
            }
            cur_wbuf->flushed = true;
            pthread_mutex_lock(&p->mutex);
            //p->written += cur_wbuf->size;
            assert(p->wbuf_stack != NULL);
            // If this buffer is the head of the page stack, remove and
            // collapse. Also advance written pointer.
            if (p->wbuf_stack == cur_wbuf) {
                _store_wbuf *tmp = p->wbuf_stack;
                while (tmp) {
                    if (tmp->flushed) {
                        p->written += tmp->size;
                        p->wbuf_stack = tmp->page_next;
                        // return wbuf to engine stack.
                        pthread_mutex_lock(&e->mutex);
                        tmp->page_next = NULL;
                        tmp->next = e->wbuf_stack;
                        e->wbuf_stack = tmp;
                        pthread_mutex_unlock(&e->mutex);
                    } else {
                        break;
                    }
                    tmp = tmp->page_next;
                }
                if (!p->wbuf_stack) {
                    p->wbuf = NULL;
                }
            }
            pthread_mutex_unlock(&p->mutex);
            cur_wbuf = next;
        }

        obj_io *cur_io = io_stack;
        while (cur_io) {
            // We need to hold the next before the callback in case the stack
            // gets reused.
            obj_io *next = cur_io->next;
            int ret = 0;
            int do_op = 1;
            store_page *p = &e->pages[cur_io->page_id];
            // TODO: loop if not enough bytes were read/written.
            switch (cur_io->mode) {
                case OBJ_IO_READ:
                    // Page is currently open. deal if read is past the end.
                    pthread_mutex_lock(&p->mutex);
                    if (p->version == cur_io->page_version) {
                        if (p->active && cur_io->offset >= p->written) {
                            ret = _read_from_wbuf(p, cur_io);
                            do_op = 0;
                        } else {
                            p->refcount++;
                        }
                    } else {
                        do_op = 0;
                        ret = -2; // TODO: enum in IO for status?
                    }
                    pthread_mutex_unlock(&p->mutex);
                    if (do_op)
                        ret = pread(p->fd, cur_io->buf, cur_io->len, p->offset + cur_io->offset);
                    break;
                case OBJ_IO_WRITE:
                    ret = pwrite(p->fd, cur_io->buf, cur_io->len, p->offset + cur_io->offset);
                    break;
            }
            // FIXME: Remove.
            if (ret == 0) {
                fprintf(stderr, "read returned nothingt\n");
            }

            // FIXME: Remove.
            if (ret < 0) {
                perror("read/write op failed");
            }
            cur_io->cb(e, cur_io, ret);
            pthread_mutex_lock(&p->mutex);
            p->refcount--;
            pthread_mutex_unlock(&p->mutex);
            cur_io = next;
        }
    }

    return NULL;
}

/* engine maint thread; takes engine context
 * if write flips buffer, or if a new page is allocated for use, signal engine
 * maint thread.
 * maint thread sorts pages by estimated freeness, marks inactive best
 * candidate and waits for refcount to hit 0.
 * adds any freed page areas to free pool.
 * stats?
 */

static void *extstore_maint_thread(void *arg) {
    store_maint_thread *me = (store_maint_thread *)arg;
    store_engine *e = me->e;
    pthread_mutex_lock(&me->mutex);
    while (1) {
        pthread_cond_wait(&me->cond, &me->mutex);
        pthread_mutex_lock(&e->mutex);
        pthread_mutex_unlock(&e->mutex);
    }

    return NULL;
}

/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */

#include "config.h"
// FIXME: config.h?
#include <stdint.h>
#include <stdbool.h>
// end FIXME
#include <stdlib.h>
#include <limits.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "extstore.h"

// TODO: better if an init option turns this on/off.
#ifdef EXTSTORE_DEBUG
#define E_DEBUG(...) \
    do { \
        fprintf(stderr, __VA_ARGS__); \
    } while (0)
#else
#define E_DEBUG(...)
#endif

#define STAT_L(e) pthread_mutex_lock(&e->stats_mutex);
#define STAT_UL(e) pthread_mutex_unlock(&e->stats_mutex);
#define STAT_INCR(e, stat, amount) { \
    pthread_mutex_lock(&e->stats_mutex); \
    e->stats.stat += amount; \
    pthread_mutex_unlock(&e->stats_mutex); \
}

#define STAT_DECR(e, stat, amount) { \
    pthread_mutex_lock(&e->stats_mutex); \
    e->stats.stat -= amount; \
    pthread_mutex_unlock(&e->stats_mutex); \
}

typedef struct __store_wbuf {
    struct __store_wbuf *next;
    char *buf;
    char *buf_pos;
    unsigned int free;
    unsigned int size;
    unsigned int offset; /* offset into page this write starts at */
    bool full; /* done writing to this page */
    bool flushed; /* whether wbuf has been flushed to disk */
} _store_wbuf;

typedef struct _store_page {
    pthread_mutex_t mutex; /* Need to be held for most operations */
    uint64_t obj_count; /* _delete can decrease post-closing */
    uint64_t bytes_used; /* _delete can decrease post-closing */
    uint64_t offset; /* starting address of page within fd */
    unsigned int version;
    unsigned int refcount;
    unsigned int allocated;
    unsigned int written; /* item offsets can be past written if wbuf not flushed */
    unsigned int bucket; /* which bucket the page is linked into */
    unsigned int free_bucket; /* which bucket this page returns to when freed */
    int fd;
    unsigned short id;
    bool active; /* actively being written to */
    bool closed; /* closed and draining before free */
    bool free; /* on freelist */
    _store_wbuf *wbuf; /* currently active wbuf from the stack */
    struct _store_page *next;
} store_page;

typedef struct store_engine store_engine;
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    obj_io *queue;
    obj_io *queue_tail;
    store_engine *e;
    unsigned int depth; // queue depth
} store_io_thread;

// sub-struct for maintenance related tasks.
struct store_maint {
    pthread_mutex_t mutex;
};

struct store_engine {
    pthread_mutex_t mutex; /* covers internal stacks and variables */
    store_page *pages; /* directly addressable page list */
    _store_wbuf *wbuf_stack; /* wbuf freelist */
    obj_io *io_stack; /* IO's to use with submitting wbuf's */
    store_io_thread *io_threads;
    store_io_thread *bg_thread; /* dedicated thread for write submit / compact ops */
    store_page **page_buckets; /* stack of pages currently allocated to each bucket */
    store_page **free_page_buckets; /* stack of use-case isolated free pages */
    size_t page_size;
    unsigned int version; /* global version counter */
    unsigned int last_io_thread; /* round robin the IO threads */
    unsigned int io_threadcount; /* count of IO threads */
    unsigned int page_count;
    unsigned int page_free; /* unallocated pages */
    unsigned int page_bucketcount; /* count of potential page buckets */
    unsigned int free_page_bucketcount; /* count of free page buckets */
    unsigned int io_depth; /* FIXME: Might cache into thr struct */
    pthread_mutex_t stats_mutex;
    struct extstore_stats stats;
    struct store_maint maint;
};

// FIXME: code is duplicated from thread.c since extstore.c doesn't pull in
// the memcached ecosystem. worth starting a cross-utility header with static
// definitions/macros?
// keeping a minimal func here for now.
#define THR_NAME_MAXLEN 16
static void thread_setname(pthread_t thread, const char *name) {
assert(strlen(name) < THR_NAME_MAXLEN);
#if defined(__linux__) && defined(HAVE_PTHREAD_SETNAME_NP)
pthread_setname_np(thread, name);
#endif
}
#undef THR_NAME_MAXLEN

static _store_wbuf *wbuf_new(size_t size) {
    _store_wbuf *b = calloc(1, sizeof(_store_wbuf));
    if (b == NULL)
        return NULL;
    b->buf = calloc(size, sizeof(char));
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
    int tid = -1;
    long long int low = LLONG_MAX;
    pthread_mutex_lock(&e->mutex);
    // find smallest queue. ignoring lock since being wrong isn't fatal.
    // TODO: if average queue depth can be quickly tracked, can break as soon
    // as we see a thread that's less than average, and start from last_io_thread
    for (int x = 0; x < e->io_threadcount; x++) {
        if (e->io_threads[x].depth == 0) {
            tid = x;
            break;
        } else if (e->io_threads[x].depth < low) {
                tid = x;
            low = e->io_threads[x].depth;
        }
    }
    pthread_mutex_unlock(&e->mutex);

    return &e->io_threads[tid];
}

static uint64_t _next_version(store_engine *e) {
    return e->version++;
}
// internal only method for freeing a page up
static void _free_page(store_engine *e, store_page *p);

static void *extstore_io_thread(void *arg);

/* Copies stats internal to engine and computes any derived values */
void extstore_get_stats(void *ptr, struct extstore_stats *st) {
    store_engine *e = (store_engine *)ptr;
    STAT_L(e);
    memcpy(st, &e->stats, sizeof(struct extstore_stats));
    STAT_UL(e);

    // grab pages_free/pages_used
    pthread_mutex_lock(&e->mutex);
    st->pages_free = e->page_free;
    st->pages_used = e->page_count - e->page_free;
    pthread_mutex_unlock(&e->mutex);
    st->io_queue = 0;
    for (int x = 0; x < e->io_threadcount; x++) {
        pthread_mutex_lock(&e->io_threads[x].mutex);
        st->io_queue += e->io_threads[x].depth;
        pthread_mutex_unlock(&e->io_threads[x].mutex);
    }
    // calculate bytes_fragmented.
    // note that open and yet-filled pages count against fragmentation.
    st->bytes_fragmented = st->pages_used * e->page_size -
        st->bytes_used;
}

void extstore_get_page_data(void *ptr, struct extstore_stats *st) {
    store_engine *e = (store_engine *)ptr;
    pthread_mutex_lock(&e->maint.mutex);
    struct extstore_page_data *pd = st->page_data;

    for (int i = 0; i < e->page_count; i++) {
        store_page *p = &e->pages[i];
        pthread_mutex_lock(&p->mutex);

        pd[p->id].free_bucket = p->free_bucket;
        pd[p->id].version = p->version;
        pd[p->id].bytes_used = p->bytes_used;
        if (p->active) {
            pd[p->id].active = true;
        }
        if (p->active || p->free) {
            pthread_mutex_unlock(&p->mutex);
            continue;
        }
        if (p->obj_count > 0 && !p->closed) {
            pd[p->id].bucket = p->bucket;
        }
        if ((p->obj_count == 0 || p->closed) && p->refcount == 0) {
            _free_page(e, p);
        }
        pthread_mutex_unlock(&p->mutex);
    }

    pthread_mutex_unlock(&e->maint.mutex);
}

const char *extstore_err(enum extstore_res res) {
    const char *rv = "unknown error";
    switch (res) {
        case EXTSTORE_INIT_BAD_WBUF_SIZE:
            rv = "page_size must be divisible by wbuf_size";
            break;
        case EXTSTORE_INIT_NEED_MORE_WBUF:
            rv = "wbuf_count must be >= page_buckets";
            break;
        case EXTSTORE_INIT_NEED_MORE_BUCKETS:
            rv = "page_buckets must be > 0";
            break;
        case EXTSTORE_INIT_PAGE_WBUF_ALIGNMENT:
            rv = "page_size and wbuf_size must be divisible by 1024*1024*2";
            break;
        case EXTSTORE_INIT_TOO_MANY_PAGES:
            rv = "page_count must total to < 65536. Increase page_size or lower path sizes";
            break;
        case EXTSTORE_INIT_OOM:
            rv = "failed calloc for engine";
            break;
        case EXTSTORE_INIT_OPEN_FAIL:
            rv = "failed to open file";
            break;
        case EXTSTORE_INIT_THREAD_FAIL:
            break;
    }
    return rv;
}

// TODO: #define's for DEFAULT_BUCKET, FREE_VERSION, etc
void *extstore_init(struct extstore_conf_file *fh, struct extstore_conf *cf,
        enum extstore_res *res) {
    int i;
    struct extstore_conf_file *f = NULL;
    pthread_t thread;

    if (cf->page_size % cf->wbuf_size != 0) {
        *res = EXTSTORE_INIT_BAD_WBUF_SIZE;
        return NULL;
    }
    // Should ensure at least one write buffer per potential page
    if (cf->page_buckets > cf->wbuf_count) {
        *res = EXTSTORE_INIT_NEED_MORE_WBUF;
        return NULL;
    }
    if (cf->page_buckets < 1) {
        *res = EXTSTORE_INIT_NEED_MORE_BUCKETS;
        return NULL;
    }

    // TODO: More intelligence around alignment of flash erasure block sizes
    if (cf->page_size % (1024 * 1024 * 2) != 0 ||
        cf->wbuf_size % (1024 * 1024 * 2) != 0) {
        *res = EXTSTORE_INIT_PAGE_WBUF_ALIGNMENT;
        return NULL;
    }

    store_engine *e = calloc(1, sizeof(store_engine));
    if (e == NULL) {
        *res = EXTSTORE_INIT_OOM;
        return NULL;
    }

    e->page_size = cf->page_size;
    uint64_t temp_page_count = 0;
    for (f = fh; f != NULL; f = f->next) {
        f->fd = open(f->file, O_RDWR | O_CREAT, 0644);
        if (f->fd < 0) {
            *res = EXTSTORE_INIT_OPEN_FAIL;
#ifdef EXTSTORE_DEBUG
            perror("extstore open");
#endif
            free(e);
            return NULL;
        }
        // use an fcntl lock to help avoid double starting.
        struct flock lock;
        lock.l_type = F_WRLCK;
        lock.l_start = 0;
        lock.l_whence = SEEK_SET;
        lock.l_len = 0;
        if (fcntl(f->fd, F_SETLK, &lock) < 0) {
            *res = EXTSTORE_INIT_OPEN_FAIL;
            free(e);
            return NULL;
        }
        if (ftruncate(f->fd, 0) < 0) {
            *res = EXTSTORE_INIT_OPEN_FAIL;
            free(e);
            return NULL;
        }

        temp_page_count += f->page_count;
        f->offset = 0;
    }

    if (temp_page_count >= UINT16_MAX) {
        *res = EXTSTORE_INIT_TOO_MANY_PAGES;
        free(e);
        return NULL;
    }
    e->page_count = temp_page_count;

    e->pages = calloc(e->page_count, sizeof(store_page));
    if (e->pages == NULL) {
        *res = EXTSTORE_INIT_OOM;
        // FIXME: loop-close. make error label
        free(e);
        return NULL;
    }

    // interleave the pages between devices
    f = NULL; // start at the first device.
    for (i = 0; i < e->page_count; i++) {
        // find next device with available pages
        while (1) {
            // restart the loop
            if (f == NULL || f->next == NULL) {
                f = fh;
            } else {
                f = f->next;
            }
            if (f->page_count) {
                f->page_count--;
                break;
            }
        }
        pthread_mutex_init(&e->pages[i].mutex, NULL);
        e->pages[i].id = i;
        e->pages[i].fd = f->fd;
        e->pages[i].free_bucket = f->free_bucket;
        e->pages[i].offset = f->offset;
        e->pages[i].free = true;
        f->offset += e->page_size;
    }

    // free page buckets allows the app to organize devices by use case
    e->free_page_buckets = calloc(cf->page_buckets, sizeof(store_page *));
    e->free_page_bucketcount = cf->page_buckets;

    e->page_free = e->page_count;
    for (i = e->page_count-1; i >= 0; i--) {
        int fb = e->pages[i].free_bucket;
        e->pages[i].next = e->free_page_buckets[fb];
        e->free_page_buckets[fb] = &e->pages[i];
    }

    // 0 is magic "page is freed" version
    e->version = 1;

    // scratch data for stats. TODO: malloc failure handle
    e->stats.page_data =
        calloc(e->page_count, sizeof(struct extstore_page_data));
    e->stats.page_count = e->page_count;
    e->stats.page_size = e->page_size;

    // page buckets lazily have pages assigned into them
    e->page_buckets = calloc(cf->page_buckets, sizeof(store_page *));
    e->page_bucketcount = cf->page_buckets;

    // allocate write buffers
    // also IO's to use for shipping to IO thread
    for (i = 0; i < cf->wbuf_count; i++) {
        _store_wbuf *w = wbuf_new(cf->wbuf_size);
        obj_io *io = calloc(1, sizeof(obj_io));
        /* TODO: on error, loop again and free stack. */
        w->next = e->wbuf_stack;
        e->wbuf_stack = w;
        io->next = e->io_stack;
        e->io_stack = io;
    }

    pthread_mutex_init(&e->mutex, NULL);
    pthread_mutex_init(&e->stats_mutex, NULL);
    pthread_mutex_init(&e->maint.mutex, NULL);

    e->io_depth = cf->io_depth;

    // spawn threads
    e->io_threads = calloc(cf->io_threadcount, sizeof(store_io_thread));
    for (i = 0; i < cf->io_threadcount; i++) {
        pthread_mutex_init(&e->io_threads[i].mutex, NULL);
        pthread_cond_init(&e->io_threads[i].cond, NULL);
        e->io_threads[i].e = e;
        // FIXME: error handling
        pthread_create(&thread, NULL, extstore_io_thread, &e->io_threads[i]);
        thread_setname(thread, "mc-ext-io");
    }
    e->io_threadcount = cf->io_threadcount;

    // dedicated IO thread for certain non-hotpath functions.
    e->bg_thread = calloc(1, sizeof(store_io_thread));
    e->bg_thread->e = e;
    pthread_mutex_init(&e->bg_thread->mutex, NULL);
    pthread_cond_init(&e->bg_thread->cond, NULL);
    pthread_create(&thread, NULL, extstore_io_thread, e->bg_thread);
    thread_setname(thread, "mc-ext-bgio");

    return (void *)e;
}

// Call without *e locked, not a fast function.
static void _evict_page(store_engine *e, unsigned int bucket,
        unsigned int free_bucket) {
    struct extstore_stats st;
    st.page_data = calloc(e->page_count, sizeof(struct extstore_page_data));
    extstore_get_page_data(e, &st);
    uint64_t low_version = ULLONG_MAX;
    unsigned int low_page = 0;

    // find lowest version of anything in free_bucket OR 0
    // unless free_bucket is 0
    for (int i = 0; i < e->page_count; i++) {
        // must belong to 0 or the requested free_bucket
        if (st.page_data[i].free_bucket &&
            st.page_data[i].free_bucket != free_bucket) {
            continue;
        }

        // found a free page, don't evict.
        if (st.page_data[i].version == 0) {
            low_version = ULLONG_MAX;
            break;
        }

        // find the lowest version.
        if (!st.page_data[i].active &&
                st.page_data[i].version < low_version) {
            low_page = i;
            low_version = st.page_data[i].version;
        }
    }

    if (low_version != ULLONG_MAX) {
        extstore_evict_page(e, low_page, low_version);
    }
    free(st.page_data);
}

// call with *e locked
static store_page *_allocate_page(store_engine *e, unsigned int bucket,
        unsigned int free_bucket) {
    E_DEBUG("EXTSTORE: allocating new page [bucket:%u]\n", bucket);
    assert(!e->page_buckets[bucket] || e->page_buckets[bucket]->allocated == e->page_size);
    store_page *tmp = NULL;
    if (e->free_page_buckets[free_bucket] != NULL) {
        assert(e->page_free > 0);
        tmp = e->free_page_buckets[free_bucket];
        e->free_page_buckets[free_bucket] = tmp->next;
    } else if (e->free_page_buckets[0] != NULL) {
        // fall back to default bucket.
        assert(e->page_free > 0);
        tmp = e->free_page_buckets[0];
        e->free_page_buckets[0] = tmp->next;
    }
    if (tmp != NULL) {
        tmp->next = e->page_buckets[bucket];
        e->page_buckets[bucket] = tmp;
        tmp->active = true;
        tmp->free = false;
        tmp->closed = false;
        tmp->version = _next_version(e);
        tmp->bucket = bucket;
        e->page_free--;
        STAT_INCR(e, page_allocs, 1);
    }

    if (tmp)
        E_DEBUG("EXTSTORE: got page %u [free:%u]\n", tmp->id, e->page_free);
    return tmp;
}

// call with *p locked. locks *e
static void _allocate_wbuf(store_engine *e, store_page *p) {
    _store_wbuf *wbuf = NULL;
    assert(!p->wbuf);
    pthread_mutex_lock(&e->mutex);
    if (e->wbuf_stack) {
        wbuf = e->wbuf_stack;
        e->wbuf_stack = wbuf->next;
        wbuf->next = 0;
    }
    pthread_mutex_unlock(&e->mutex);
    if (wbuf) {
        wbuf->offset = p->allocated;
        p->allocated += wbuf->size;
        wbuf->free = wbuf->size;
        wbuf->buf_pos = wbuf->buf;
        wbuf->full = false;
        wbuf->flushed = false;

        p->wbuf = wbuf;
    }
}

/* callback after wbuf is flushed. can only remove wbuf's from the head onward
 * if successfully flushed, which complicates this routine. each callback
 * attempts to free the wbuf stack, which is finally done when the head wbuf's
 * callback happens.
 * It's rare flushes would happen out of order.
 */
static void _wbuf_cb(void *ep, obj_io *io, int ret) {
    store_engine *e = (store_engine *)ep;
    store_page *p = &e->pages[io->page_id];
    _store_wbuf *w = (_store_wbuf *) io->data;

    // TODO: Examine return code. Not entirely sure how to handle errors.
    // Naive first-pass should probably cause the page to close/free.
    w->flushed = true;
    pthread_mutex_lock(&p->mutex);
    assert(p->wbuf != NULL && p->wbuf == w);
    assert(p->written == w->offset);
    p->written += w->size;
    p->wbuf = NULL;

    if (p->written == e->page_size)
        p->active = false;

    // return the wbuf
    pthread_mutex_lock(&e->mutex);
    w->next = e->wbuf_stack;
    e->wbuf_stack = w;
    // also return the IO we just used.
    io->next = e->io_stack;
    e->io_stack = io;
    pthread_mutex_unlock(&e->mutex);
    pthread_mutex_unlock(&p->mutex);
}

/* Wraps pages current wbuf in an io and submits to IO thread.
 * Called with p locked, locks e.
 */
static void _submit_wbuf(store_engine *e, store_page *p) {
    _store_wbuf *w;
    pthread_mutex_lock(&e->mutex);
    obj_io *io = e->io_stack;
    e->io_stack = io->next;
    pthread_mutex_unlock(&e->mutex);
    w = p->wbuf;

    // zero out the end of the wbuf to allow blind readback of data.
    memset(w->buf + (w->size - w->free), 0, w->free);

    io->next = NULL;
    io->mode = OBJ_IO_WRITE;
    io->page_id = p->id;
    io->data = w;
    io->offset = w->offset;
    io->len = w->size;
    io->buf = w->buf;
    io->cb = _wbuf_cb;

    extstore_submit_bg(e, io);
}

/* engine write function; takes engine, item_io.
 * fast fail if no available write buffer (flushing)
 * lock engine context, find active page, unlock
 * if page full, submit page/buffer to io thread.
 *
 * write is designed to be flaky; if page full, caller must try again to get
 * new page. best if used from a background thread that can harmlessly retry.
 */

int extstore_write_request(void *ptr, unsigned int bucket,
        unsigned int free_bucket, obj_io *io) {
    store_engine *e = (store_engine *)ptr;
    store_page *p;
    int ret = -1;
    if (bucket >= e->page_bucketcount)
        return ret;

    pthread_mutex_lock(&e->mutex);
    p = e->page_buckets[bucket];
    if (!p) {
        p = _allocate_page(e, bucket, free_bucket);
    }
    pthread_mutex_unlock(&e->mutex);
    if (!p) {
        _evict_page(e, bucket, free_bucket);
        return ret;
    }

    pthread_mutex_lock(&p->mutex);

    // FIXME: can't null out page_buckets!!!
    // page is full, clear bucket and retry later.
    if (!p->active ||
            ((!p->wbuf || p->wbuf->full) && p->allocated >= e->page_size)) {
        pthread_mutex_unlock(&p->mutex);
        pthread_mutex_lock(&e->mutex);
        store_page *temp_p = _allocate_page(e, bucket, free_bucket);
        pthread_mutex_unlock(&e->mutex);
        if (!temp_p) {
            _evict_page(e, bucket, free_bucket);
        }
        return ret;
    }

    // if io won't fit, submit IO for wbuf and find new one.
    if (p->wbuf && p->wbuf->free < io->len && !p->wbuf->full) {
        _submit_wbuf(e, p);
        p->wbuf->full = true;
    }

    if (!p->wbuf && p->allocated < e->page_size) {
        _allocate_wbuf(e, p);
    }

    // hand over buffer for caller to copy into
    // leaves p locked.
    if (p->wbuf && !p->wbuf->full && p->wbuf->free >= io->len) {
        io->buf = p->wbuf->buf_pos;
        io->page_id = p->id;
        return 0;
    }

    pthread_mutex_unlock(&p->mutex);
    // p->written is incremented post-wbuf flush
    return ret;
}

/* _must_ be called after a successful write_request.
 * fills the rest of io structure.
 */
void extstore_write(void *ptr, obj_io *io) {
    store_engine *e = (store_engine *)ptr;
    store_page *p = &e->pages[io->page_id];

    io->offset = p->wbuf->offset + (p->wbuf->size - p->wbuf->free);
    io->page_version = p->version;
    p->wbuf->buf_pos += io->len;
    p->wbuf->free -= io->len;
    p->bytes_used += io->len;
    p->obj_count++;
    STAT_L(e);
    e->stats.bytes_written += io->len;
    e->stats.bytes_used += io->len;
    e->stats.objects_written++;
    e->stats.objects_used++;
    STAT_UL(e);

    pthread_mutex_unlock(&p->mutex);
}

/* engine submit function; takes engine, item_io stack.
 * lock io_thread context and add stack
 * signal io thread to wake.
 * return success.
 */
static int _extstore_submit(void *ptr, obj_io *io, store_io_thread *t) {
    unsigned int depth = 0;
    obj_io *tio = io;
    obj_io *tail = NULL;
    while (tio != NULL) {
        tail = tio; // keep updating potential tail.
        depth++;
        tio = tio->next;
    }

    pthread_mutex_lock(&t->mutex);

    t->depth += depth;
    if (t->queue == NULL) {
        t->queue = io;
        t->queue_tail = tail;
    } else {
        // Have to put the *io stack at the end of current queue.
        assert(tail->next == NULL);
        assert(t->queue_tail->next == NULL);
        t->queue_tail->next = io;
        t->queue_tail = tail;
    }

    pthread_mutex_unlock(&t->mutex);

    //pthread_mutex_lock(&t->mutex);
    pthread_cond_signal(&t->cond);
    //pthread_mutex_unlock(&t->mutex);
    return 0;
}

int extstore_submit(void *ptr, obj_io *io) {
    store_engine *e = (store_engine *)ptr;
    store_io_thread *t = _get_io_thread(e);
    return _extstore_submit(ptr, io, t);
}

int extstore_submit_bg(void *ptr, obj_io *io) {
    store_engine *e = (store_engine *)ptr;
    store_io_thread *t = e->bg_thread;
    return _extstore_submit(ptr, io, t);
}

/* engine note delete function: takes engine, page id, size?
 * note that an item in this page is no longer valid
 */
int extstore_delete(void *ptr, unsigned int page_id, uint64_t page_version,
        unsigned int count, unsigned int bytes) {
    store_engine *e = (store_engine *)ptr;
    // FIXME: validate page_id in bounds
    store_page *p = &e->pages[page_id];
    int ret = 0;

    pthread_mutex_lock(&p->mutex);
    if (!p->closed && p->version == page_version) {
        if (p->bytes_used >= bytes) {
            p->bytes_used -= bytes;
        } else {
            p->bytes_used = 0;
        }

        if (p->obj_count >= count) {
            p->obj_count -= count;
        } else {
            p->obj_count = 0; // caller has bad accounting?
        }
        STAT_L(e);
        e->stats.bytes_used -= bytes;
        e->stats.objects_used -= count;
        STAT_UL(e);

        if (p->obj_count == 0 && p->refcount == 0 && !p->active) {
            _free_page(e, p);
        }
    } else {
        ret = -1;
    }
    pthread_mutex_unlock(&p->mutex);
    return ret;
}

int extstore_check(void *ptr, unsigned int page_id, uint64_t page_version) {
    store_engine *e = (store_engine *)ptr;
    store_page *p = &e->pages[page_id];
    int ret = 0;

    pthread_mutex_lock(&p->mutex);
    if (p->version != page_version)
        ret = -1;
    pthread_mutex_unlock(&p->mutex);
    return ret;
}

/* allows a compactor to say "we're done with this page, kill it." */
void extstore_close_page(void *ptr, unsigned int page_id, uint64_t page_version) {
    store_engine *e = (store_engine *)ptr;
    store_page *p = &e->pages[page_id];

    pthread_mutex_lock(&p->mutex);
    if (!p->closed && !p->active && p->version == page_version) {
        p->closed = true;
        if (p->refcount == 0) {
            _free_page(e, p);
        }
    }
    pthread_mutex_unlock(&p->mutex);
}

/* signal that we've forcefully ejected rather than gracefully closed */
void extstore_evict_page(void *ptr, unsigned int page_id, uint64_t page_version) {
    store_engine *e = (store_engine *)ptr;
    store_page *p = &e->pages[page_id];

    pthread_mutex_lock(&p->mutex);
    if (!p->closed && !p->active && p->version == page_version) {
        E_DEBUG("EXTSTORE: evicting page [%d] [v: %llu]\n",
                p->id, (unsigned long long) p->version);

        p->closed = true;
        STAT_L(e);
        e->stats.page_evictions++;
        e->stats.objects_evicted += p->obj_count;
        e->stats.bytes_evicted += p->bytes_used;
        STAT_UL(e);
        if (p->refcount == 0) {
            _free_page(e, p);
        }
    }
    pthread_mutex_unlock(&p->mutex);
}

/* Finds an attached wbuf that can satisfy the read.
 * Since wbufs can potentially be flushed to disk out of order, they are only
 * removed as the head of the list successfully flushes to disk.
 */
// call with *p locked
// FIXME: protect from reading past wbuf
static inline int _read_from_wbuf(store_page *p, obj_io *io) {
    _store_wbuf *wbuf = p->wbuf;
    assert(wbuf != NULL);
    assert(io->offset < p->written + wbuf->size);
    if (io->iov == NULL) {
        memcpy(io->buf, wbuf->buf + (io->offset - wbuf->offset), io->len);
    } else {
        int x;
        unsigned int off = io->offset - wbuf->offset;
        // need to loop fill iovecs
        for (x = 0; x < io->iovcnt; x++) {
            struct iovec *iov = &io->iov[x];
            memcpy(iov->iov_base, wbuf->buf + off, iov->iov_len);
            off += iov->iov_len;
        }
    }
    return io->len;
}

/* engine IO thread; takes engine context
 * manage writes/reads
 * runs IO callbacks inline after each IO
 */
// FIXME: protect from reading past page
static void *extstore_io_thread(void *arg) {
    store_io_thread *me = (store_io_thread *)arg;
    store_engine *e = me->e;
    while (1) {
        obj_io *io_stack = NULL;
        pthread_mutex_lock(&me->mutex);
        if (me->queue == NULL) {
            pthread_cond_wait(&me->cond, &me->mutex);
        }

        // Pull and disconnect a batch from the queue
        // Chew small batches from the queue so the IO thread picker can keep
        // the IO queue depth even, instead of piling on threads one at a time
        // as they gobble a queue.
        if (me->queue != NULL) {
            int i;
            obj_io *end = NULL;
            io_stack = me->queue;
            end = io_stack;
            for (i = 1; i < e->io_depth; i++) {
                if (end->next) {
                    end = end->next;
                } else {
                    me->queue_tail = end->next;
                    break;
                }
            }
            me->depth -= i;
            me->queue = end->next;
            end->next = NULL;
        }
        pthread_mutex_unlock(&me->mutex);

        obj_io *cur_io = io_stack;
        while (cur_io) {
            // We need to note next before the callback in case the obj_io
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
                    if (!p->free && !p->closed && p->version == cur_io->page_version) {
                        if (p->active && cur_io->offset >= p->written) {
                            ret = _read_from_wbuf(p, cur_io);
                            do_op = 0;
                        } else {
                            p->refcount++;
                        }
                        STAT_L(e);
                        e->stats.bytes_read += cur_io->len;
                        e->stats.objects_read++;
                        STAT_UL(e);
                    } else {
                        do_op = 0;
                        ret = -2; // TODO: enum in IO for status?
                    }
                    pthread_mutex_unlock(&p->mutex);
                    if (do_op) {
#if !defined(HAVE_PREAD) || !defined(HAVE_PREADV)
                        // TODO: lseek offset is natively 64-bit on OS X, but
                        // perhaps not on all platforms? Else use lseek64()
                        ret = lseek(p->fd, p->offset + cur_io->offset, SEEK_SET);
                        if (ret >= 0) {
                            if (cur_io->iov == NULL) {
                                ret = read(p->fd, cur_io->buf, cur_io->len);
                            } else {
                                ret = readv(p->fd, cur_io->iov, cur_io->iovcnt);
                            }
                        }
#else
                        if (cur_io->iov == NULL) {
                            ret = pread(p->fd, cur_io->buf, cur_io->len, p->offset + cur_io->offset);
                        } else {
                            ret = preadv(p->fd, cur_io->iov, cur_io->iovcnt, p->offset + cur_io->offset);
                        }
#endif
                    }
                    break;
                case OBJ_IO_WRITE:
                    do_op = 0;
                    // FIXME: Should hold refcount during write. doesn't
                    // currently matter since page can't free while active.
                    ret = pwrite(p->fd, cur_io->buf, cur_io->len, p->offset + cur_io->offset);
                    break;
            }
            if (ret == 0) {
                E_DEBUG("read returned nothing\n");
            }

#ifdef EXTSTORE_DEBUG
            if (ret == -1) {
                perror("read/write op failed");
            }
#endif
            cur_io->cb(e, cur_io, ret);
            if (do_op) {
                pthread_mutex_lock(&p->mutex);
                p->refcount--;
                pthread_mutex_unlock(&p->mutex);
            }
            cur_io = next;
        }
    }

    return NULL;
}

// call with *p locked.
static void _free_page(store_engine *e, store_page *p) {
    store_page *tmp = NULL;
    store_page *prev = NULL;
    E_DEBUG("EXTSTORE: freeing page %u\n", p->id);
    STAT_L(e);
    e->stats.objects_used -= p->obj_count;
    e->stats.bytes_used -= p->bytes_used;
    e->stats.page_reclaims++;
    STAT_UL(e);
    pthread_mutex_lock(&e->mutex);
    // unlink page from bucket list
    tmp = e->page_buckets[p->bucket];
    while (tmp) {
        if (tmp == p) {
            if (prev) {
                prev->next = tmp->next;
            } else {
                e->page_buckets[p->bucket] = tmp->next;
            }
            tmp->next = NULL;
            break;
        }
        prev = tmp;
        tmp = tmp->next;
    }
    // reset most values
    p->version = 0;
    p->obj_count = 0;
    p->bytes_used = 0;
    p->allocated = 0;
    p->written = 0;
    p->bucket = 0;
    p->active = false;
    p->closed = false;
    p->free = true;
    // add to page stack
    p->next = e->free_page_buckets[p->free_bucket];
    e->free_page_buckets[p->free_bucket] = p;
    e->page_free++;
    E_DEBUG("EXTSTORE: pages free %u\n", e->page_free);
    pthread_mutex_unlock(&e->mutex);
}

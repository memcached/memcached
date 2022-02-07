#include "memcached.h"

#include "restart.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

typedef struct _restart_data_cb restart_data_cb;

struct _restart_data_cb {
    void *data; // user supplied opaque data.
    struct _restart_data_cb *next; // callbacks are ordered stack
    restart_check_cb ccb;
    restart_save_cb scb;
    char tag[RESTART_TAG_MAXLEN];
};

// TODO: struct to hand back to caller.
static int mmap_fd = 0;
static void *mmap_base = NULL;
static size_t slabmem_limit = 0;
char *memory_file = NULL;

static restart_data_cb *cb_stack = NULL;

// Allows submodules and engines to have independent check and save metadata
// routines for the restart code.
void restart_register(const char *tag, restart_check_cb ccb, restart_save_cb scb, void *data) {
    restart_data_cb *cb = calloc(1, sizeof(restart_data_cb));
    if (cb == NULL) {
        fprintf(stderr, "[restart] failed to allocate callback register\n");
        abort();
    }

    // Handle first time call initialization inline so we don't need separate
    // API call.
    if (cb_stack == NULL) {
        cb_stack = cb;
    } else {
        // Ensure we fire the callbacks in registration order.
        // Someday I'll get a queue.h overhaul.
        restart_data_cb *finder = cb_stack;
        while (finder->next != NULL) {
            finder = finder->next;
        }
        finder->next = cb;
    }

    safe_strcpy(cb->tag, tag, RESTART_TAG_MAXLEN);
    cb->data = data;
    cb->ccb = *ccb;
    cb->scb = *scb;
}

typedef struct {
    FILE *f;
    restart_data_cb *cb;
    char *line;
    bool done;
} restart_cb_ctx;

// TODO: error string from cb?
// - look for final line with checksum
// - checksum entire file (up until final line)
// - seek to start

static int restart_check(const char *file) {
    // metadata is kept in a separate file.
    size_t flen = strlen(file);
    const char *ext = ".meta";
    char *metafile = calloc(1, flen + strlen(ext) + 1);
    if (metafile == NULL) {
        // probably in a really bad position if we hit here, so don't start.
        fprintf(stderr, "[restart] failed to allocate memory for restart check\n");
        abort();
    }
    memcpy(metafile, file, flen);
    memcpy(metafile+flen, ext, strlen(ext));

    FILE *f = fopen(metafile, "r");
    if (f == NULL) {
        fprintf(stderr, "[restart] no metadata save file, starting with a clean cache\n");
        free(metafile);
        return -1;
    }

    restart_cb_ctx ctx;

    ctx.f = f;
    ctx.cb = NULL;
    ctx.line = NULL;
    ctx.done = false;
    if (restart_get_kv(&ctx, NULL, NULL) != RESTART_DONE) {
        // First line must be a tag, so read it in and set up the proper
        // callback here.
        fprintf(stderr, "[restart] corrupt metadata file\n");
        // TODO: this should probably just return -1 and skip the reuse.
        abort();
    }
    if (ctx.cb == NULL) {
        fprintf(stderr, "[restart] Failed to read a tag from metadata file\n");
        abort();
    }

    // loop call the callback, check result code.
    bool failed = false;
    while (!ctx.done) {
        restart_data_cb *cb = ctx.cb;
        if (cb->ccb(cb->tag, &ctx, cb->data) != 0) {
            failed = true;
            break;
        }
    }

    if (ctx.line)
        free(ctx.line);

    fclose(f);

    unlink(metafile);
    free(metafile);

    if (failed) {
        fprintf(stderr, "[restart] failed to validate metadata, starting with a clean cache\n");
        return -1;
    } else {
        return 0;
    }
}

// This function advances the file read while being called directly from the
// callback.
// The control inversion here (callback calling in which might change the next
// callback) allows the callbacks to set up proper loops or sequences for
// reading data back, avoiding an event model.
enum restart_get_kv_ret restart_get_kv(void *ctx, char **key, char **val) {
    char *line = NULL;
    size_t len = 0;
    restart_data_cb *cb = NULL;
    restart_cb_ctx *c = (restart_cb_ctx *) ctx;
    // free previous line.
    // we could just pass it into getline, but it can randomly realloc so we'd
    // have to re-assign it into the structure anyway.
    if (c->line != NULL) {
        free(c->line);
        c->line = NULL;
    }

    if (getline(&line, &len, c->f) != -1) {
        // First char is an indicator:
        // T for TAG, changing the callback we use.
        // K for key/value, to ship to the active callback.
        char *p = line;
        while (*p != '\n') {
            p++;
        }
        *p = '\0';

        if (line[0] == 'T') {
            cb = cb_stack;
            while (cb != NULL) {
                // NOTE: len is allocated size, not line len. need to chomp \n
                if (strcmp(cb->tag, line+1) == 0) {
                    break;
                }
                cb = cb->next;
            }
            if (cb == NULL) {
                fprintf(stderr, "[restart] internal handler for metadata tag not found: %s:\n", line+1);
                return RESTART_NOTAG;
            }
            c->cb = cb;
        } else if (line[0] == 'K') {
            char *p = line+1; // start just ahead of the token.
            // tokenize the string and return the pointers?
            if (key != NULL) {
                *key = p;
            }

            // turn key into a normal NULL terminated string.
            while (*p != ' ' && (p - line < len)) {
                p++;
            }
            *p = '\0';
            p++;

            // value _should_ run until where the newline was, which is \0 now
            if (val != NULL) {
                *val = p;
            }
            c->line = line;

            return RESTART_OK;
        } else {
            // FIXME: proper error chain.
            fprintf(stderr, "[restart] invalid metadata line:\n\n%s\n", line);
            free(line);
            return RESTART_BADLINE;
        }
    } else {
        // EOF or error in read.
        c->done = true;
    }

    return RESTART_DONE;
}

// TODO:
// - rolling checksum along with the writes.
// - write final line + checksum + byte count or w/e.

static int restart_save(const char *file) {
    // metadata is kept in a separate file.
    // FIXME: function.
    size_t flen = strlen(file);
    const char *ext = ".meta";
    size_t extlen = strlen(ext);
    char *metafile = calloc(1, flen + extlen + 1);
    if (metafile == NULL) {
        fprintf(stderr, "[restart] failed to allocate memory during metadata save\n");
        return -1;
    }
    memcpy(metafile, file, flen);
    memcpy(metafile+flen, ext, extlen);

    // restrictive permissions for the metadata file.
    // TODO: also for the mmap file eh? :P
    mode_t oldmask = umask(~(S_IRUSR | S_IWUSR));
    FILE *f = fopen(metafile, "w");
    umask(oldmask);
    if (f == NULL) {
        // FIXME: correct error handling.
        free(metafile);
        perror("failed to write metadata file");
        return -1;
    }

    restart_data_cb *cb = cb_stack;
    restart_cb_ctx ctx;
    ctx.f = f;
    while (cb != NULL) {
        // Plugins/engines in the metadata file are separated by tag lines.
        fprintf(f, "T%s\n", cb->tag);
        if (cb->scb(cb->tag, &ctx, cb->data) != 0) {
            fclose(f);
            free(metafile);
            return -1;
        }

        cb = cb->next;
    }

    fclose(f);
    free(metafile);

    return 0;
}

// Keys and values must not contain spaces or newlines.
// Could offer an interface that uriencodes values for the caller, however
// nothing currently would use it, so add when necessary.
#define SET_VAL_MAX 4096
void restart_set_kv(void *ctx, const char *key, const char *fmt, ...) {
    va_list ap;
    restart_cb_ctx *c = (restart_cb_ctx *) ctx;
    char valbuf[SET_VAL_MAX];

    va_start(ap, fmt);
    int vlen = vsnprintf(valbuf, SET_VAL_MAX-1, fmt, ap);
    va_end(ap);
    // This is heavy handed. We need to protect against corrupt data as much
    // as possible. The buffer is large and these values are currently small,
    // it will take a significant mistake to land here.
    if (vlen >= SET_VAL_MAX) {
        fprintf(stderr, "[restart] fatal error while saving metadata state, value too long for: %s %s",
                key, valbuf);
        abort();
    }

    fprintf(c->f, "K%s %s\n", key, valbuf);
    // TODO: update crc32c
}

static long _find_pagesize(void) {
#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
    return sysconf(_SC_PAGESIZE);
#else
    // A good guess.
    return 4096;
#endif
}

bool restart_mmap_open(const size_t limit, const char *file, void **mem_base) {
    bool reuse_mmap = true;

    long pagesize = _find_pagesize();
    memory_file = strdup(file);
    mmap_fd = open(file, O_RDWR|O_CREAT, S_IRWXU);
    if (mmap_fd == -1) {
        perror("failed to open file for mmap");
        abort();
    }
    if (ftruncate(mmap_fd, limit) != 0) {
        perror("ftruncate failed");
        abort();
    }
    /* Allocate everything in a big chunk with malloc */
    if (limit % pagesize) {
        // This is a sanity check; shouldn't ever be possible since we
        // increase memory by whole megabytes.
        fprintf(stderr, "[restart] memory limit not divisible evenly by pagesize (please report bug)\n");
        abort();
    }
    mmap_base = mmap(NULL, limit, PROT_READ|PROT_WRITE, MAP_SHARED, mmap_fd, 0);
    if (mmap_base == MAP_FAILED) {
        perror("failed to mmap, aborting");
        abort();
    }
    // Set the limit before calling check_mmap, so we can find the meta page..
    slabmem_limit = limit;
    if (restart_check(file) != 0) {
        reuse_mmap = false;
    }
    *mem_base = mmap_base;

    return reuse_mmap;
}

/* Gracefully stop/close the shared memory segment */
void restart_mmap_close(void) {
    msync(mmap_base, slabmem_limit, MS_SYNC);

    if (restart_save(memory_file) != 0) {
        fprintf(stderr, "[restart] failed to save metadata");
    }

    if (munmap(mmap_base, slabmem_limit) != 0) {
        perror("[restart] failed to munmap shared memory");
    } else if (close(mmap_fd) != 0) {
        perror("[restart] failed to close shared memory fd");
    }

    free(memory_file);
}

// given memory base, quickly walk memory and do pointer fixup.
// do this once on startup to avoid having to do pointer fixup on every
// reference from hash table or LRU.
unsigned int restart_fixup(void *orig_addr) {
    struct timeval tv;
    uint64_t checked = 0;
    const unsigned int page_size = settings.slab_page_size;
    unsigned int page_remain = page_size;

    gettimeofday(&tv, NULL);
    if (settings.verbose > 0) {
        fprintf(stderr, "[restart] original memory base: [%p] new base: [%p]\n", orig_addr, mmap_base);
        fprintf(stderr, "[restart] recovery start [%d.%d]\n", (int)tv.tv_sec, (int)tv.tv_usec);
    }

    // since chunks don't align with pages, we have to also track page size.
    while (checked < slabmem_limit) {
        //fprintf(stderr, "checked: %lu\n", checked);
        item *it = (item *)((char *)mmap_base + checked);

        int size = slabs_fixup((char *)mmap_base + checked,
                checked % settings.slab_page_size);
        //fprintf(stderr, "id: %d, size: %d remain: %u\n", it->slabs_clsid, size, page_remain);
        // slabber gobbled an entire page, skip and move on.
        if (size == -1) {
            assert(page_remain % page_size == 0);
            assert(page_remain == page_size);
            checked += page_remain;
            page_remain = page_size;
            continue;
        }

        if (it->it_flags & ITEM_LINKED) {
            // fixup next/prev links while on LRU.
            if (it->next) {
                it->next = (item *)((mc_ptr_t)it->next - (mc_ptr_t)orig_addr);
                it->next = (item *)((mc_ptr_t)it->next + (mc_ptr_t)mmap_base);
            }
            if (it->prev) {
                it->prev = (item *)((mc_ptr_t)it->prev - (mc_ptr_t)orig_addr);
                it->prev = (item *)((mc_ptr_t)it->prev + (mc_ptr_t)mmap_base);
            }

            //fprintf(stderr, "item was linked\n");
            do_item_link_fixup(it);
        }

        if (it->it_flags & (ITEM_CHUNKED|ITEM_CHUNK)) {
            item_chunk *ch;
            if (it->it_flags & ITEM_CHUNKED) {
                ch = (item_chunk *) ITEM_schunk(it);
                // Sigh. Chunked items are a hack; the clsid is the clsid of
                // the full object (always the largest slab class) rather than
                // the actual chunk.
                // I bet this is fixable :(
                size = slabs_size(ch->orig_clsid);
                //fprintf(stderr, "fixing chunked item header [%d]\n", size);
            } else {
                //fprintf(stderr, "fixing item chunk [%d]\n", size);
                ch = (item_chunk *) it;
            }
            if (ch->next) {
                ch->next = (item_chunk *)((mc_ptr_t)ch->next - (mc_ptr_t)orig_addr);
                ch->next = (item_chunk *)((mc_ptr_t)ch->next + (mc_ptr_t)mmap_base);
            }
            if (ch->prev) {
                ch->prev = (item_chunk *)((mc_ptr_t)ch->prev - (mc_ptr_t)orig_addr);
                ch->prev = (item_chunk *)((mc_ptr_t)ch->prev + (mc_ptr_t)mmap_base);
            }
            if (ch->head) {
                ch->head = (item *)((mc_ptr_t)ch->head - (mc_ptr_t)orig_addr);
                ch->head = (item *)((mc_ptr_t)ch->head + (mc_ptr_t)mmap_base);
            }
        }

        // next chunk
        checked += size;
        page_remain -= size;
        if (size > page_remain) {
            //fprintf(stderr, "doot %d\n", page_remain);
            checked += page_remain;
            page_remain = settings.slab_page_size;
        }
        //assert(checked != 3145728);
    }

    if (settings.verbose > 0) {
        gettimeofday(&tv, NULL);
        fprintf(stderr, "[restart] recovery end [%d.%d]\n", (int)tv.tv_sec, (int)tv.tv_usec);
    }

    return 0;
}

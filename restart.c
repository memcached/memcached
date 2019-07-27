#include "memcached.h"

#include "restart.h"

#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

// TODO: allocating from the _front_ (or using a different file?)
// makes it easier to do dynamic memory limits again.
// downside is having to track potential hugepage alignment for the slab
// memory.
// tracking data at the end of the memory base makes this easier.

// TODO: also start/min size
typedef struct {
    void *base_addr;
    double factor; /* factor from last slab init */
    char version[255];
    bool clean; /* set to true during a clean shutdown */
} slab_mmap_meta;

// TODO: struct to hand back to caller.
static int mmap_fd = 0;
static int pagesize = 0;
static void *mmap_base = NULL;
static size_t slabmem_limit = 0;

// TODO: This should be a function external to the slabber.
static unsigned int check_mmap(void *mem_base) {
    slab_mmap_meta *m = (slab_mmap_meta *)((char *)mem_base + slabmem_limit);
    if (!m->clean) {
        fprintf(stderr, "mmap not clean\n");
        return -1;
    }
    if (m->base_addr == 0) {
        fprintf(stderr, "base address 0\n");
        return -2;
    }
    if (memcmp(VERSION, m->version, strlen(VERSION)) != 0) {
        fprintf(stderr, "version doesn't match\n");
        return -3;
    }
    // TODO: check factor/etc important arguments
    return 0;
}

// NOTE: must be called _after_ main code fixup?
// else: m->base_addr is only set during close.
// else: set m->clean = false here but set rest on close...
void restart_mmap_set(void) {
    slab_mmap_meta *m = (slab_mmap_meta *)((char *)mmap_base + slabmem_limit);
    m->base_addr = mmap_base;
    m->clean = false;
    memcpy(m->version, VERSION, strlen(VERSION));
}

bool restart_mmap_open(const size_t limit, const char *file, void **mem_base) {
    bool reuse_mmap = true;

    pagesize = getpagesize();
    mmap_fd = open(file, O_RDWR|O_CREAT, S_IRWXU);
    fprintf(stderr, "mmap_fd: %d\n", mmap_fd);
    if (ftruncate(mmap_fd, limit + pagesize) != 0) {
        perror("ftruncate failed");
        abort();
    }
    /* Allocate everything in a big chunk with malloc */
    if (limit % pagesize) {
        // FIXME: what was I smoking? is this an error?
        fprintf(stderr, "WARNING: mem_limit not divible evenly by pagesize\n");
    }
    mmap_base = mmap(NULL, limit + pagesize, PROT_READ|PROT_WRITE, MAP_SHARED, mmap_fd, 0);
    if (mmap_base == MAP_FAILED) {
        perror("failed to mmap, aborting");
        abort();
    }
    // Set the limit before calling check_mmap, so we can find the meta page..
    slabmem_limit = limit;
    if (check_mmap(mmap_base) != 0) {
        fprintf(stderr, "failed to validate mmap, not reusing\n");
        reuse_mmap = false;
    }
    *mem_base = mmap_base;

    // save metadata snapshot.
    // TODO: just have to mark it as not clean here.
    //restart_set_mmap();
    return reuse_mmap;
}

// TODO: meta at start vs end of memory.
/* Gracefully stop/close the shared memory segment */
void restart_mmap_close(void) {
    slab_mmap_meta *m = (slab_mmap_meta *)((char *)mmap_base + slabmem_limit);
    m->clean = true;
    m->base_addr = mmap_base;
    if (munmap(mmap_base, slabmem_limit + pagesize) != 0) {
        perror("failed to munmap shared memory");
    } else if (close(mmap_fd) != 0) {
        perror("failed to close shared memory fd");
    }
}

// given memory base, quickly walk memory and do pointer fixup.
// do this once on startup to avoid having to do pointer fixup on every
// reference from hash table or LRU.
unsigned int restart_fixup(void) {
    struct timeval tv;
    uint64_t checked = 0;
    slab_mmap_meta *m = (slab_mmap_meta *)((char *)mmap_base + slabmem_limit);
    void *orig_addr = m->base_addr;
    const unsigned int page_size = settings.slab_page_size;
    unsigned int page_remain = page_size;

    gettimeofday(&tv, NULL);
    fprintf(stderr, "orig base: [%p] new base: [%p]\n", orig_addr, mmap_base);
    fprintf(stderr, "recovery start [%d.%d]\n", (int)tv.tv_sec, (int)tv.tv_usec);

    // since chunks don't align with pages, we have to also track page size.
    while (checked < slabmem_limit) {
        //fprintf(stderr, "checked: %lu\n", checked);
        item *it = (item *)((char *)mmap_base + checked);

        int size = slabs_fixup((char *)mmap_base + checked,
                checked % settings.slab_page_size);
        // slabber gobbled an entire page, skip and move on.
        if (size == -1) {
            assert(page_remain % page_size == 0);
            assert(page_remain == page_size);
            checked += page_remain;
            page_remain = page_size;
            continue;
        }

        // FIXME: only do this if linked.
        // fixup next/prev links. same for freelist or LRU
        if (it->next) {
            it->next = (item *)((uint64_t)it->next - (uint64_t)orig_addr);
            it->next = (item *)((uint64_t)it->next + (uint64_t)mmap_base);
        }
        if (it->prev) {
            it->prev = (item *)((uint64_t)it->prev - (uint64_t)orig_addr);
            it->prev = (item *)((uint64_t)it->prev + (uint64_t)mmap_base);
        }

        if (it->it_flags & ITEM_LINKED) {
            //fprintf(stderr, "item was linked\n");
            do_item_link_fixup(it);
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

    gettimeofday(&tv, NULL);
    fprintf(stderr, "recovery end [%d.%d]\n", (int)tv.tv_sec, (int)tv.tv_usec);

    return 0;
}

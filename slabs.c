/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 * Slabs memory allocation, based on powers-of-N. Slabs are up to 1MB in size
 * and are divided into chunks. The chunk sizes start off at the size of the
 * "item" structure plus space for a small key and value. They increase by
 * a multiplier factor from there, up to half the maximum slab size.
 */
#include "memcached.h"
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

//#define DEBUG_SLAB_MOVER
/* powers-of-N allocation structures */

typedef struct {
    uint32_t size;      /* sizes of items */
    uint32_t perslab;   /* how many items per slab */

    void *slots;           /* list of item ptrs */
    unsigned int sl_curr;   /* total free items in list */

    unsigned int slabs;     /* how many slabs were allocated for this class */

    void **slab_list;       /* array of slab pointers */
    unsigned int list_size; /* size of prev array */
} slabclass_t;

static slabclass_t slabclass[MAX_NUMBER_OF_SLAB_CLASSES];
static size_t mem_limit = 0;
static size_t mem_malloced = 0;
/* If the memory limit has been hit once. Used as a hint to decide when to
 * early-wake the LRU maintenance thread */
static bool mem_limit_reached = false;
static int power_largest;

static void *mem_base = NULL;
static void *mem_current = NULL;
static size_t mem_avail = 0;
/**
 * Access to the slab allocator is protected by this lock
 */
static pthread_mutex_t slabs_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * Forward Declarations
 */
static int do_grow_slab_list(const unsigned int id);
static int do_slabs_newslab(const unsigned int id);
static void *memory_allocate(size_t size);
static void do_slabs_free(void *ptr, unsigned int id);

/* Preallocate as many slab pages as possible (called from slabs_init)
   on start-up, so users don't get confused out-of-memory errors when
   they do have free (in-slab) space, but no space to make new slabs.
   if maxslabs is 18 (POWER_LARGEST - POWER_SMALLEST + 1), then all
   slab types can be made.  if max memory is less than 18 MB, only the
   smaller ones will be made.  */
static void slabs_preallocate (const unsigned int maxslabs);

/*
 * Figures out which slab class (chunk size) is required to store an item of
 * a given size.
 *
 * Given object size, return id to use when allocating/freeing memory for object
 * 0 means error: can't store such a large object
 */

unsigned int slabs_clsid(const size_t size) {
    int res = POWER_SMALLEST;

    if (size == 0 || size > settings.item_size_max)
        return 0;
    while (size > slabclass[res].size)
        if (res++ == power_largest)     /* won't fit in the biggest slab */
            return power_largest;
    return res;
}

unsigned int slabs_size(const int clsid) {
    return slabclass[clsid].size;
}

// TODO: could this work with the restartable memory?
// Docs say hugepages only work with private shm allocs.
/* Function split out for better error path handling */
static void * alloc_large_chunk(const size_t limit)
{
    void *ptr = NULL;
#if defined(__linux__) && defined(MADV_HUGEPAGE)
    size_t pagesize = 0;
    FILE *fp;
    int ret;

    /* Get the size of huge pages */
    fp = fopen("/proc/meminfo", "r");
    if (fp != NULL) {
        char buf[64];

        while ((fgets(buf, sizeof(buf), fp)))
            if (!strncmp(buf, "Hugepagesize:", 13)) {
                ret = sscanf(buf + 13, "%zu\n", &pagesize);

                /* meminfo huge page size is in KiBs */
                pagesize <<= 10;
            }
        fclose(fp);
    }

    if (!pagesize) {
        fprintf(stderr, "Failed to get supported huge page size\n");
        return NULL;
    }

    if (settings.verbose > 1)
        fprintf(stderr, "huge page size: %zu\n", pagesize);

    /* This works because glibc simply uses mmap when the alignment is
     * above a certain limit. */
    ret = posix_memalign(&ptr, pagesize, limit);
    if (ret != 0) {
        fprintf(stderr, "Failed to get aligned memory chunk: %d\n", ret);
        return NULL;
    }

    ret = madvise(ptr, limit, MADV_HUGEPAGE);
    if (ret < 0) {
        fprintf(stderr, "Failed to set transparent hugepage hint: %d\n", ret);
        free(ptr);
        ptr = NULL;
    }
#elif defined(__FreeBSD__)
    size_t align = (sizeof(size_t) * 8 - (__builtin_clzl(4095)));
    ptr = mmap(NULL, limit, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON | MAP_ALIGNED(align) | MAP_ALIGNED_SUPER, -1, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "Failed to set super pages\n");
        ptr = NULL;
    }
#else
    ptr = malloc(limit);
#endif
    return ptr;
}

unsigned int slabs_fixup(char *chunk, const int border) {
    slabclass_t *p;
    item *it = (item *)chunk;
    int id = ITEM_clsid(it);

    // memory isn't used yet. shunt to global pool.
    // (which must be 0)
    if (id == 0) {
        //assert(border == 0);
        p = &slabclass[0];
        do_grow_slab_list(0);
        p->slab_list[p->slabs++] = (char*)chunk;
        return -1;
    }
    p = &slabclass[id];

    // if we're on a page border, add the slab to slab class
    if (border == 0) {
        do_grow_slab_list(id);
        p->slab_list[p->slabs++] = chunk;
    }

    // increase free count if ITEM_SLABBED
    if (it->it_flags == ITEM_SLABBED) {
        // if ITEM_SLABBED re-stack on freelist.
        // don't have to run pointer fixups.
        it->prev = 0;
        it->next = p->slots;
        if (it->next) it->next->prev = it;
        p->slots = it;

        p->sl_curr++;
        //fprintf(stderr, "replacing into freelist\n");
    }

    return p->size;
}

/**
 * Determines the chunk sizes and initializes the slab class descriptors
 * accordingly.
 */
void slabs_init(const size_t limit, const double factor, const bool prealloc, const uint32_t *slab_sizes, void *mem_base_external, bool reuse_mem) {
    int i = POWER_SMALLEST - 1;
    unsigned int size = sizeof(item) + settings.chunk_size;

    /* Some platforms use runtime transparent hugepages. If for any reason
     * the initial allocation fails, the required settings do not persist
     * for remaining allocations. As such it makes little sense to do slab
     * preallocation. */
    bool __attribute__ ((unused)) do_slab_prealloc = false;

    mem_limit = limit;

    if (prealloc && mem_base_external == NULL) {
        mem_base = alloc_large_chunk(mem_limit);
        if (mem_base) {
            do_slab_prealloc = true;
            mem_current = mem_base;
            mem_avail = mem_limit;
        } else {
            fprintf(stderr, "Warning: Failed to allocate requested memory in"
                    " one large chunk.\nWill allocate in smaller chunks\n");
        }
    } else if (prealloc && mem_base_external != NULL) {
        // Can't (yet) mix hugepages with mmap allocations, so separate the
        // logic from above. Reusable memory also force-preallocates memory
        // pages into the global pool, which requires turning mem_* variables.
        do_slab_prealloc = true;
        mem_base = mem_base_external;
        // _current shouldn't be used in this case, but we set it to where it
        // should be anyway.
        if (reuse_mem) {
            mem_current = ((char*)mem_base) + mem_limit;
            mem_avail = 0;
        } else {
            mem_current = mem_base;
            mem_avail = mem_limit;
        }
    }

    memset(slabclass, 0, sizeof(slabclass));

    while (++i < MAX_NUMBER_OF_SLAB_CLASSES-1) {
        if (slab_sizes != NULL) {
            if (slab_sizes[i-1] == 0)
                break;
            size = slab_sizes[i-1];
        } else if (size >= settings.slab_chunk_size_max / factor) {
            break;
        }
        /* Make sure items are always n-byte aligned */
        if (size % CHUNK_ALIGN_BYTES)
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);

        slabclass[i].size = size;
        slabclass[i].perslab = settings.slab_page_size / slabclass[i].size;
        if (slab_sizes == NULL)
            size *= factor;
        if (settings.verbose > 1) {
            fprintf(stderr, "slab class %3d: chunk size %9u perslab %7u\n",
                    i, slabclass[i].size, slabclass[i].perslab);
        }
    }

    power_largest = i;
    slabclass[power_largest].size = settings.slab_chunk_size_max;
    slabclass[power_largest].perslab = settings.slab_page_size / settings.slab_chunk_size_max;
    if (settings.verbose > 1) {
        fprintf(stderr, "slab class %3d: chunk size %9u perslab %7u\n",
                i, slabclass[i].size, slabclass[i].perslab);
    }

    /* for the test suite:  faking of how much we've already malloc'd */
    {
        char *t_initial_malloc = getenv("T_MEMD_INITIAL_MALLOC");
        if (t_initial_malloc) {
            int64_t env_malloced;
            if (safe_strtoll((const char *)t_initial_malloc, &env_malloced)) {
                mem_malloced = (size_t)env_malloced;
            }
        }

    }

    if (do_slab_prealloc) {
        if (!reuse_mem) {
            slabs_preallocate(power_largest);
        }
    }
}

void slabs_prefill_global(void) {
    void *ptr;
    slabclass_t *p = &slabclass[0];
    int len = settings.slab_page_size;

    while (mem_malloced < mem_limit
            && (ptr = memory_allocate(len)) != NULL) {
        do_grow_slab_list(0);
        // Ensure the front header is zero'd to avoid confusing restart code.
        // It's probably good enough to cast it and just zero slabs_clsid, but
        // this is extra paranoid.
        memset(ptr, 0, sizeof(item));
        p->slab_list[p->slabs++] = ptr;
    }
    mem_limit_reached = true;
}

static void slabs_preallocate(const unsigned int maxslabs) {
    int i;
    unsigned int prealloc = 0;

    /* pre-allocate a 1MB slab in every size class so people don't get
       confused by non-intuitive "SERVER_ERROR out of memory"
       messages.  this is the most common question on the mailing
       list.  if you really don't want this, you can rebuild without
       these three lines.  */

    for (i = POWER_SMALLEST; i < MAX_NUMBER_OF_SLAB_CLASSES; i++) {
        if (++prealloc > maxslabs)
            break;
        if (do_slabs_newslab(i) == 0) {
            fprintf(stderr, "Error while preallocating slab memory!\n"
                "If using -L or other prealloc options, max memory must be "
                "at least %d megabytes.\n", power_largest);
            exit(1);
        }
    }
}

static int do_grow_slab_list(const unsigned int id) {
    if (id > power_largest)
        return 0;

    slabclass_t *p = &slabclass[id];
    if (p->slabs == p->list_size) {
        size_t new_size =  (p->list_size != 0) ? p->list_size * 2 : 16;
        void *new_list = realloc(p->slab_list, new_size * sizeof(void *));
        if (new_list == 0) return 0;
        p->list_size = new_size;
        p->slab_list = new_list;
    }
    return 1;
}

int slabs_grow_slab_list(const unsigned int id) {
    int ret = 0;
    pthread_mutex_lock(&slabs_lock);
    ret = do_grow_slab_list(id);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

static void split_slab_page_into_freelist(char *ptr, const unsigned int id) {
    slabclass_t *p = &slabclass[id];
    int x;
    for (x = 0; x < p->perslab; x++) {
        do_slabs_free(ptr, id);
        ptr += p->size;
    }
}

/* Fast FIFO queue */
static void *get_page_from_global_pool(void) {
    slabclass_t *p = &slabclass[SLAB_GLOBAL_PAGE_POOL];
    if (p->slabs < 1) {
        return NULL;
    }
    char *ret = p->slab_list[p->slabs - 1];
    p->slabs--;
    return ret;
}

static int do_slabs_newslab(const unsigned int id) {
    slabclass_t *p = &slabclass[id];
    slabclass_t *g = &slabclass[SLAB_GLOBAL_PAGE_POOL];
    int len = (settings.slab_reassign || settings.slab_chunk_size_max != settings.slab_page_size)
        ? settings.slab_page_size
        : p->size * p->perslab;
    char *ptr;

    if ((mem_limit && mem_malloced + len > mem_limit && p->slabs > 0
         && g->slabs == 0)) {
        mem_limit_reached = true;
        MEMCACHED_SLABS_SLABCLASS_ALLOCATE_FAILED(id);
        return 0;
    }

    if ((do_grow_slab_list(id) == 0) ||
        (((ptr = get_page_from_global_pool()) == NULL) &&
        ((ptr = memory_allocate((size_t)len)) == 0))) {

        MEMCACHED_SLABS_SLABCLASS_ALLOCATE_FAILED(id);
        return 0;
    }

    // Always wipe the memory at this stage: in restart mode the mmap memory
    // could be unused, yet still full of data. Better for usability if we're
    // wiping memory as it's being pulled out of the global pool instead of
    // blocking startup all at once.
    memset(ptr, 0, (size_t)len);
    split_slab_page_into_freelist(ptr, id);

    p->slab_list[p->slabs++] = ptr;
    MEMCACHED_SLABS_SLABCLASS_ALLOCATE(id);

    return 1;
}

/*@null@*/
static void *do_slabs_alloc(unsigned int id,
        unsigned int flags) {
    slabclass_t *p;
    void *ret = NULL;
    item *it = NULL;

    if (id < POWER_SMALLEST || id > power_largest) {
        MEMCACHED_SLABS_ALLOCATE_FAILED(id);
        return NULL;
    }
    p = &slabclass[id];
    assert(p->sl_curr == 0 || (((item *)p->slots)->it_flags & ITEM_SLABBED));

    /* fail unless we have space at the end of a recently allocated page,
       we have something on our freelist, or we could allocate a new page */
    if (p->sl_curr == 0 && flags != SLABS_ALLOC_NO_NEWPAGE) {
        do_slabs_newslab(id);
    }

    if (p->sl_curr != 0) {
        /* return off our freelist */
        it = (item *)p->slots;
        p->slots = it->next;
        if (it->next) it->next->prev = 0;
        /* Kill flag and initialize refcount here for lock safety in slab
         * mover's freeness detection. */
        it->it_flags &= ~ITEM_SLABBED;
        it->refcount = 1;
        p->sl_curr--;
        ret = (void *)it;
    } else {
        ret = NULL;
    }

    if (ret) {
        MEMCACHED_SLABS_ALLOCATE(id, p->size, ret);
    } else {
        MEMCACHED_SLABS_ALLOCATE_FAILED(id);
    }

    return ret;
}

static void do_slabs_free_chunked(item *it) {
    item_chunk *chunk = (item_chunk *) ITEM_schunk(it);
    slabclass_t *p;

    it->it_flags = ITEM_SLABBED;
    // FIXME: refresh on how this works?
    //it->slabs_clsid = 0;
    it->prev = 0;
    // header object's original classid is stored in chunk.
    p = &slabclass[chunk->orig_clsid];
    // original class id needs to be set on free memory.
    it->slabs_clsid = chunk->orig_clsid;
    if (chunk->next) {
        chunk = chunk->next;
        chunk->prev = 0;
    } else {
        // header with no attached chunk
        chunk = NULL;
    }

    // return the header object.
    // TODO: This is in three places, here and in do_slabs_free().
    it->prev = 0;
    it->next = p->slots;
    if (it->next) it->next->prev = it;
    p->slots = it;
    p->sl_curr++;

    item_chunk *next_chunk;
    while (chunk) {
        assert(chunk->it_flags == ITEM_CHUNK);
        chunk->it_flags = ITEM_SLABBED;
        p = &slabclass[chunk->slabs_clsid];
        next_chunk = chunk->next;

        chunk->prev = 0;
        chunk->next = p->slots;
        if (chunk->next) chunk->next->prev = chunk;
        p->slots = chunk;
        p->sl_curr++;

        chunk = next_chunk;
    }

    return;
}

static void do_slabs_free(void *ptr, unsigned int id) {
    slabclass_t *p;
    item *it;

    assert(id >= POWER_SMALLEST && id <= power_largest);
    if (id < POWER_SMALLEST || id > power_largest)
        return;

    MEMCACHED_SLABS_FREE(id, ptr);
    p = &slabclass[id];

    it = (item *)ptr;
    if ((it->it_flags & ITEM_CHUNKED) == 0) {
        it->it_flags = ITEM_SLABBED;
        it->slabs_clsid = id;
        it->prev = 0;
        it->next = p->slots;
        if (it->next) it->next->prev = it;
        p->slots = it;

        p->sl_curr++;
    } else {
        do_slabs_free_chunked(it);
    }
    return;
}

/* With refactoring of the various stats code the automover won't need a
 * custom function here.
 */
void fill_slab_stats_automove(slab_stats_automove *am) {
    int n;
    pthread_mutex_lock(&slabs_lock);
    for (n = 0; n < MAX_NUMBER_OF_SLAB_CLASSES; n++) {
        slabclass_t *p = &slabclass[n];
        slab_stats_automove *cur = &am[n];
        cur->chunks_per_page = p->perslab;
        cur->free_chunks = p->sl_curr;
        cur->total_pages = p->slabs;
        cur->chunk_size = p->size;
    }
    pthread_mutex_unlock(&slabs_lock);
}

/* TODO: slabs_available_chunks should grow up to encompass this.
 * mem_flag is redundant with the other function.
 */
unsigned int global_page_pool_size(bool *mem_flag) {
    unsigned int ret = 0;
    pthread_mutex_lock(&slabs_lock);
    if (mem_flag != NULL)
        *mem_flag = mem_malloced >= mem_limit ? true : false;
    ret = slabclass[SLAB_GLOBAL_PAGE_POOL].slabs;
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

/*@null@*/
static void do_slabs_stats(ADD_STAT add_stats, void *c) {
    int i, total;
    /* Get the per-thread stats which contain some interesting aggregates */
    struct thread_stats thread_stats;
    threadlocal_stats_aggregate(&thread_stats);

    total = 0;
    for(i = POWER_SMALLEST; i <= power_largest; i++) {
        slabclass_t *p = &slabclass[i];
        if (p->slabs != 0) {
            uint32_t perslab, slabs;
            slabs = p->slabs;
            perslab = p->perslab;

            char key_str[STAT_KEY_LEN];
            char val_str[STAT_VAL_LEN];
            int klen = 0, vlen = 0;

            APPEND_NUM_STAT(i, "chunk_size", "%u", p->size);
            APPEND_NUM_STAT(i, "chunks_per_page", "%u", perslab);
            APPEND_NUM_STAT(i, "total_pages", "%u", slabs);
            APPEND_NUM_STAT(i, "total_chunks", "%u", slabs * perslab);
            APPEND_NUM_STAT(i, "used_chunks", "%u",
                            slabs*perslab - p->sl_curr);
            APPEND_NUM_STAT(i, "free_chunks", "%u", p->sl_curr);
            /* Stat is dead, but displaying zero instead of removing it. */
            APPEND_NUM_STAT(i, "free_chunks_end", "%u", 0);
            APPEND_NUM_STAT(i, "get_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].get_hits);
            APPEND_NUM_STAT(i, "cmd_set", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].set_cmds);
            APPEND_NUM_STAT(i, "delete_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].delete_hits);
            APPEND_NUM_STAT(i, "incr_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].incr_hits);
            APPEND_NUM_STAT(i, "decr_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].decr_hits);
            APPEND_NUM_STAT(i, "cas_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].cas_hits);
            APPEND_NUM_STAT(i, "cas_badval", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].cas_badval);
            APPEND_NUM_STAT(i, "touch_hits", "%llu",
                    (unsigned long long)thread_stats.slab_stats[i].touch_hits);
            total++;
        }
    }

    /* add overall slab stats and append terminator */

    APPEND_STAT("active_slabs", "%d", total);
    APPEND_STAT("total_malloced", "%llu", (unsigned long long)mem_malloced);
    add_stats(NULL, 0, NULL, 0, c);
}

static void *memory_allocate(size_t size) {
    void *ret;

    if (mem_base == NULL) {
        /* We are not using a preallocated large memory chunk */
        ret = malloc(size);
    } else {
        ret = mem_current;

        if (size > mem_avail) {
            return NULL;
        }

        /* mem_current pointer _must_ be aligned!!! */
        if (size % CHUNK_ALIGN_BYTES) {
            size += CHUNK_ALIGN_BYTES - (size % CHUNK_ALIGN_BYTES);
        }

        mem_current = ((char*)mem_current) + size;
        if (size < mem_avail) {
            mem_avail -= size;
        } else {
            mem_avail = 0;
        }
    }
    mem_malloced += size;

    return ret;
}

/* Must only be used if all pages are item_size_max */
static void memory_release(void) {
    void *p = NULL;
    if (mem_base != NULL)
        return;

    if (!settings.slab_reassign)
        return;

    while (mem_malloced > mem_limit &&
            (p = get_page_from_global_pool()) != NULL) {
        free(p);
        mem_malloced -= settings.slab_page_size;
    }
}

void *slabs_alloc(unsigned int id, unsigned int flags) {
    void *ret;

    pthread_mutex_lock(&slabs_lock);
    ret = do_slabs_alloc(id, flags);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

void slabs_free(void *ptr, unsigned int id) {
    pthread_mutex_lock(&slabs_lock);
    do_slabs_free(ptr, id);
    pthread_mutex_unlock(&slabs_lock);
}

void slabs_stats(ADD_STAT add_stats, void *c) {
    pthread_mutex_lock(&slabs_lock);
    do_slabs_stats(add_stats, c);
    pthread_mutex_unlock(&slabs_lock);
}

static bool do_slabs_adjust_mem_limit(size_t new_mem_limit) {
    /* Cannot adjust memory limit at runtime if prealloc'ed */
    if (mem_base != NULL)
        return false;
    settings.maxbytes = new_mem_limit;
    mem_limit = new_mem_limit;
    mem_limit_reached = false; /* Will reset on next alloc */
    memory_release(); /* free what might already be in the global pool */
    return true;
}

bool slabs_adjust_mem_limit(size_t new_mem_limit) {
    bool ret;
    pthread_mutex_lock(&slabs_lock);
    ret = do_slabs_adjust_mem_limit(new_mem_limit);
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

unsigned int slabs_available_chunks(const unsigned int id, bool *mem_flag,
        unsigned int *chunks_perslab) {
    unsigned int ret;
    slabclass_t *p;

    pthread_mutex_lock(&slabs_lock);
    p = &slabclass[id];
    ret = p->sl_curr;
    if (mem_flag != NULL)
        *mem_flag = mem_malloced >= mem_limit ? true : false;
    if (chunks_perslab != NULL)
        *chunks_perslab = p->perslab;
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

void *slabs_peek_page(const unsigned int id, uint32_t *size, uint32_t *perslab) {
    slabclass_t *s_cls;
    void *page = NULL;
    if (id > power_largest) {
        return NULL;
    }
    pthread_mutex_lock(&slabs_lock);
    s_cls = &slabclass[id];
    if (s_cls->slabs < 2) {
        pthread_mutex_unlock(&slabs_lock);
        return NULL;
    }
    *size = s_cls->size;
    *perslab = s_cls->perslab;

    page = s_cls->slab_list[0];

    pthread_mutex_unlock(&slabs_lock);

    return page;
}

/* detaches item/chunk from freelist.
 * for use with page mover.
 * lock _must_ be held.
 */
void do_slabs_unlink_free_chunk(const unsigned int id, item *it) {
    slabclass_t *s_cls = &slabclass[id];
    /* Ensure this was on the freelist and nothing else. */
    assert(it->it_flags == ITEM_SLABBED);
    if (s_cls->slots == it) {
        s_cls->slots = it->next;
    }
    if (it->next) it->next->prev = it->prev;
    if (it->prev) it->prev->next = it->next;
    s_cls->sl_curr--;
}

void slabs_finalize_page_move(const unsigned int sid, const unsigned int did, void *page) {
    pthread_mutex_lock(&slabs_lock);
    slabclass_t *s_cls = &slabclass[sid];
    slabclass_t *d_cls = &slabclass[did];

    s_cls->slabs--;
    for (int x = 0; x < s_cls->slabs; x++) {
        s_cls->slab_list[x] = s_cls->slab_list[x+1];
    }

    // FIXME: it's nearly impossible for this to fail, and error handling here
    // is gnarly since we'll have to just put the page back where we got it
    // from.
    // For now we won't handle the error, and a subsequent commit should
    // remove the need to resize the slab list.
    do_grow_slab_list(did);
    d_cls->slab_list[d_cls->slabs++] = page;
    /* Don't need to split the page into chunks if we're just storing it */
    if (did > SLAB_GLOBAL_PAGE_POOL) {
        memset(page, 0, (size_t)settings.slab_page_size);
        split_slab_page_into_freelist(page, did);
    } else if (did == SLAB_GLOBAL_PAGE_POOL) {
        /* memset just enough to signal restart handler to skip */
        memset(page, 0, sizeof(item));
        /* mem_malloc'ed might be higher than mem_limit. */
        mem_limit_reached = false;
        memory_release();
    }

    pthread_mutex_unlock(&slabs_lock);
}
/* Iterate at most once through the slab classes and pick a "random" source.
 * I like this better than calling rand() since rand() is slow enough that we
 * can just check all of the classes once instead.
 */
int slabs_pick_any_for_reassign(const unsigned int did) {
    pthread_mutex_lock(&slabs_lock);
    static int cur = POWER_SMALLEST - 1;
    int tries = MAX_NUMBER_OF_SLAB_CLASSES - POWER_SMALLEST + 1;
    for (; tries > 0; tries--) {
        cur++;
        if (cur > MAX_NUMBER_OF_SLAB_CLASSES)
            cur = POWER_SMALLEST;
        if (cur == did)
            continue;
        if (slabclass[cur].slabs > 1) {
            pthread_mutex_unlock(&slabs_lock);
            return cur;
        }
    }
    pthread_mutex_unlock(&slabs_lock);
    return -1;
}

int slabs_page_count(const unsigned int id) {
    int ret;
    pthread_mutex_lock(&slabs_lock);
    ret = slabclass[id].slabs;
    pthread_mutex_unlock(&slabs_lock);
    return ret;
}

int slabs_locked_callback(slabs_cb cb, void *arg) {
    int ret = 0;
    pthread_mutex_lock(&slabs_lock);
    ret = cb(arg);
    pthread_mutex_unlock(&slabs_lock);

    return ret;
}

/* The slabber system could avoid needing to understand much, if anything,
 * about items if callbacks were strategically used. Due to how the slab mover
 * works, certain flag bits can only be adjusted while holding the slabs lock.
 * Using these functions, isolate sections of code needing this and turn them
 * into callbacks when an interface becomes more obvious.
 */
void slabs_mlock(void) {
    pthread_mutex_lock(&slabs_lock);
}

void slabs_munlock(void) {
    pthread_mutex_unlock(&slabs_lock);
}

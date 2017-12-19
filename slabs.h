/* slabs memory allocation */
#ifndef SLABS_H
#define SLABS_H

/** Init the subsystem. 1st argument is the limit on no. of bytes to allocate,
    0 if no limit. 2nd argument is the growth factor; each slab will use a chunk
    size equal to the previous slab's chunk size times this factor.
    3rd argument specifies if the slab allocator should allocate all memory
    up front (if true), or allocate memory in chunks as it is needed (if false)
*/
void slabs_init(const size_t limit, const double factor, const bool prealloc, const uint32_t *slab_sizes);

/** Call only during init. Pre-allocates all available memory */
void slabs_prefill_global(void);

/**
 * Given object size, return id to use when allocating/freeing memory for object
 * 0 means error: can't store such a large object
 */

unsigned int slabs_clsid(const size_t size);

/** Allocate object of given length. 0 on error */ /*@null@*/
#define SLABS_ALLOC_NO_NEWPAGE 1
void *slabs_alloc(const size_t size, unsigned int id, uint64_t *total_bytes, unsigned int flags);

/** Free previously allocated object */
void slabs_free(void *ptr, size_t size, unsigned int id);

/** Adjust the stats for memory requested */
void slabs_adjust_mem_requested(unsigned int id, size_t old, size_t ntotal);

/** Adjust global memory limit up or down */
bool slabs_adjust_mem_limit(size_t new_mem_limit);

/** Return a datum for stats in binary protocol */
bool get_stats(const char *stat_type, int nkey, ADD_STAT add_stats, void *c);

typedef struct {
    unsigned int chunks_per_page;
    unsigned int chunk_size;
    long int free_chunks;
    long int total_pages;
} slab_stats_automove;
void fill_slab_stats_automove(slab_stats_automove *am);
unsigned int global_page_pool_size(bool *mem_flag);

/** Fill buffer with stats */ /*@null@*/
void slabs_stats(ADD_STAT add_stats, void *c);

/* Hints as to freespace in slab class */
unsigned int slabs_available_chunks(unsigned int id, bool *mem_flag, uint64_t *total_bytes, unsigned int *chunks_perslab);

void slabs_mlock(void);
void slabs_munlock(void);

int start_slab_maintenance_thread(void);
void stop_slab_maintenance_thread(void);

enum reassign_result_type {
    REASSIGN_OK=0, REASSIGN_RUNNING, REASSIGN_BADCLASS, REASSIGN_NOSPARE,
    REASSIGN_SRC_DST_SAME
};

enum reassign_result_type slabs_reassign(int src, int dst);

void slabs_rebalancer_pause(void);
void slabs_rebalancer_resume(void);

#ifdef EXTSTORE
void slabs_set_storage(void *arg);
#endif

#endif

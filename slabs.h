/* slabs memory allocation */
#ifndef SLABS_H
#define SLABS_H

/** Init the subsystem. 1st argument is the limit on no. of bytes to allocate,
    0 if no limit. 2nd argument is the growth factor; each slab will use a chunk
    size equal to the previous slab's chunk size times this factor.
    3rd argument specifies if the slab allocator should allocate all memory
    up front (if true), or allocate memory in chunks as it is needed (if false)
*/
void slabs_init(const size_t limit, const double factor, const bool prealloc);


/**
 * Given object size, return id to use when allocating/freeing memory for object
 * 0 means error: can't store such a large object
 */

unsigned int slabs_clsid(const size_t size);

/** Allocate object of given length. 0 on error */ /*@null@*/
void *slabs_alloc(const size_t size, unsigned int id);

/** Free previously allocated object */
void slabs_free(void *ptr, size_t size, unsigned int id);

/** Return a datum for stats in binary protocol */
bool get_stats(const char *stat_type, int nkey, ADD_STAT add_stats, void *c);

/** Fill buffer with stats */ /*@null@*/
void slabs_stats(ADD_STAT add_stats, void *c);

#endif

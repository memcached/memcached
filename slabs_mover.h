#ifndef SLABS_MOVER_H
#define SLABS_MOVER_H

struct slab_rebal_thread;
struct slab_rebal_thread *start_slab_maintenance_thread(void *storage);
void stop_slab_maintenance_thread(struct slab_rebal_thread *t);

enum reassign_result_type {
    REASSIGN_OK=0, REASSIGN_RUNNING, REASSIGN_BADCLASS, REASSIGN_NOSPARE,
    REASSIGN_SRC_DST_SAME
};

#define SLABS_REASSIGN_ALLOW_EVICTIONS 1
enum reassign_result_type slabs_reassign(struct slab_rebal_thread *t, int src, int dst, int flags);

void slab_maintenance_pause(struct slab_rebal_thread *t);
void slab_maintenance_resume(struct slab_rebal_thread *t);

#endif // SLABS_MOVER_H

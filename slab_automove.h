#ifndef SLAB_AUTOMOVE_H
#define SLAB_AUTOMOVE_H

void *slab_automove_init(uint32_t window_size, double max_age_ratio);
void slab_automove_free(void *arg);
void slab_automove_run(void *arg, int *src, int *dst);

#endif

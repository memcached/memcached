#ifndef SLAB_AUTOMOVE_EXTSTORE_H
#define SLAB_AUTOMOVE_EXTSTORE_H

void *slab_automove_extstore_init(struct settings *settings);
void slab_automove_extstore_free(void *arg);
void slab_automove_extstore_run(void *arg, int *src, int *dst);

#endif

#ifndef RESTART_H
#define RESTART_H

bool restart_mmap_open(const size_t limit, const char *file, void **mem_base, void **old_base);
void restart_mmap_close(void);
void restart_mmap_set(void);
unsigned int restart_fixup(void *old_base);

#endif

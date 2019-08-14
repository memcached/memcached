#ifndef RESTART_H
#define RESTART_H

#define RESTART_TAG_MAXLEN 255

typedef int (*restart_check_cb)(const char *tag, void *ctx, void *data);
typedef int (*restart_save_cb)(const char *tag, void *ctx, void *data);
void restart_register(const char *tag, restart_check_cb ccb, restart_save_cb scb, void *data);

void restart_set_kv(void *ctx, const char *key, const char *fmt, ...);
int restart_get_kv(void *ctx, char **key, char **val);

bool restart_mmap_open(const size_t limit, const char *file, void **mem_base);
void restart_mmap_close(void);
void restart_mmap_set(void);
unsigned int restart_fixup(void *old_base);

#endif

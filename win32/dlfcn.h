#ifndef DLFCN_H
#define DLFCN_H
void* dlopen(const char* path, int mode);
void* dlsym(void* handle, const char* symbol);
int dlclose(void* handle);
const char *dlerror(void);

#define RTLD_LAZY 1
#define RTLD_LOCAL 2

#define RTLD_NOW 0x00002
#endif

#ifndef PORTABILITY_H
#define PORTABILITY_H
#include "config.h"
#include <assert.h>
#include <string.h>
#include <pthread.h>

#if defined(__FreeBSD__)
#include <pthread_np.h>
#endif

// Interface is slightly different on various platforms.
// On linux, at least, the len limit is 16 bytes.
// TODO We can fairly add in macOs but it sets only for the current thread
#define THR_NAME_MAXLEN 16

__attribute__((unused)) static void thread_setname(pthread_t thread, const char *name) {
assert(strlen(name) < THR_NAME_MAXLEN);
#if defined(__linux__)
    pthread_setname_np(thread, name);
#elif defined(__FreeBSD__)
    // TODO once 13.x release becomes the minimum
    // linux and freebsd can be merged in one.
    pthread_set_name_np(thread, name);
#endif
}
#undef THR_NAME_MAXLEN

#endif

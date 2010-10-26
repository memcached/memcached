/* dummy_defs.c
 *
 * Create blank UNIX function definitions to allow win32 builds. */

#include <config.h>

int lstat(const char *path, struct stat *tstat) {
    return -1;
}

int getrlimit(int __resource, struct rlimit *rlimits) {
    rlimits->rlim_cur = 1; // Hack: just enough to allow main() to move forward.
    rlimits->rlim_max = 1;
    return 0;
}

int setrlimit(int __resource, struct rlimit *__rlimits) {
    return 0;
}

_uid_t getuid(void) {
    return -1;
}
_uid_t geteuid(void) {
    return -1;
}

struct passwd *getpwnam(const char *name) {
    return 0;
}

int setuid(_uid_t uid) {
    return -1;
}

int setgid(_uid_t gid) {
    return -1;
}

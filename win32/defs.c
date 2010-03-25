/* dummy_defs.c
 *
 * Create blank UNIX function definitions to allow win32 builds. */

#include <config.h>

int lstat(const char *path, struct stat *tstat) {
    return -1;
}

int getrlimit(int __resource, struct rlimit *__rlimits) {
    /* HACK ALERT: This function MUST BE called from main() before any *
     * network operation for Windows networking to work. Since the     *
     * main() is calling getrlimit() that is NOT meaningful for        *
     * Windows, this function is being used to invoke WSAStartup()     *
     * below only once during the the first call to getrlimit()        *
     */
    static int onceonly = 0;
    WSADATA wsaData;
    if (!onceonly) {
        onceonly = 1;
        if (WSAStartup(MAKEWORD(2,0), &wsaData) != 0) {
            fprintf(stderr, "Socket Initialization Error. Program aborted\n");
            exit(EXIT_FAILURE);
        }
    }
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

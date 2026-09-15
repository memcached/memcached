/* win_compat.h - Windows / MSVC compatibility definitions for Memcached */
#ifndef WIN_COMPAT_H
#define WIN_COMPAT_H

#if defined(_WIN32) || defined(_MSC_VER)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

/* Standard C and Windows headers */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <event2/util.h>

/* Mode and type definitions */
#if !defined(_MODE_T_DEFINED) && !defined(_MODE_T_DEFINED_) && !defined(_MODE_T_)
#define _MODE_T_DEFINED
#define _MODE_T_DEFINED_
#define _MODE_T_
typedef unsigned short mode_t;
#endif

#if !defined(_SSIZE_T_DEFINED) && !defined(_SSIZE_T_) && !defined(SSIZE_T)
#define _SSIZE_T_DEFINED
#define _SSIZE_T_
#if defined(_WIN64)
typedef __int64 ssize_t;
#else
typedef int ssize_t;
#endif
#endif

#ifndef _GID_T_DEFINED
#define _GID_T_DEFINED
typedef int gid_t;
#endif

#ifndef _UID_T_DEFINED
#define _UID_T_DEFINED
typedef int uid_t;
#endif

#ifndef _IN_PORT_T_DEFINED
#define _IN_PORT_T_DEFINED
typedef uint16_t in_port_t;
#endif

#ifndef _PID_T_DEFINED
#define _PID_T_DEFINED
typedef int pid_t;
#endif

/* Polyfill GCC attributes for MSVC */
#ifndef __attribute__
#define __attribute__(x)
#endif

/* Polyfill POSIX file permission constants */
#ifndef S_IRUSR
#define S_IRUSR 0400
#endif
#ifndef S_IWUSR
#define S_IWUSR 0200
#endif
#ifndef S_IXUSR
#define S_IXUSR 0100
#endif
#ifndef S_IRWXU
#define S_IRWXU 0700
#endif

/* Polyfill POSIX string functions */
#ifndef strtok_r
#define strtok_r strtok_s
#endif

/* Avoid conflict with MSVC CRT itoa(int, char*, int) */
#ifdef itoa
#undef itoa
#endif
#define itoa itoa_ljust_internal

/* Include POSIX signal, pthread, and sys/uio compatibility */
#include <posix-signal.h>
#include <posix-pthread.h>
#include <posix-sys-uio.h>

/* Polyfill POSIX signal constants not defined in MSVC CRT */
#ifndef SIGHUP
#define SIGHUP 1
#endif
#ifndef SIGINT
#define SIGINT 2
#endif
#ifndef SIGQUIT
#define SIGQUIT 3
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGUSR1
#define SIGUSR1 10
#endif
#ifndef SIGUSR2
#define SIGUSR2 12
#endif
#ifndef SIGPIPE
#define SIGPIPE 13
#endif
#ifndef SIGALRM
#define SIGALRM 14
#endif
#ifndef SIGTERM
#define SIGTERM 15
#endif

/* Polyfill Network constants */
#ifndef EAI_SYSTEM
#define EAI_SYSTEM 11
#endif

/* Buffer size limits */
#ifndef IOV_MAX
#define IOV_MAX 1024
#endif

#ifndef MAXPATHLEN
#define MAXPATHLEN 4096
#endif

#ifndef F_GETFD
#define F_GETFD 1
#endif
#ifndef F_SETFD
#define F_SETFD 2
#endif
#ifndef F_GETFL
#define F_GETFL 3
#endif
#ifndef F_SETFL
#define F_SETFL 4
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0x0004
#endif

static __inline void ensure_wsastartup(void) {
    static int initialized = 0;
    if (!initialized) {
        WSADATA wsaData;
        setvbuf(stdout, NULL, _IONBF, 0);
        setvbuf(stderr, NULL, _IONBF, 0);
        WSAStartup(MAKEWORD(2, 2), &wsaData);
        initialized = 1;
    }
}

static __inline int win_compat_pipe(int pipefd[2]) {
    evutil_socket_t fds[2];
    ensure_wsastartup();
    if (evutil_socketpair(AF_INET, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
    pipefd[0] = (int)fds[0];
    pipefd[1] = (int)fds[1];
    return 0;
}
#undef pipe
#define pipe win_compat_pipe

static __inline int win_compat_fcntl(intptr_t fd, int cmd, ...) {
    SOCKET s = (SOCKET)fd;

    if (cmd == F_GETFD || cmd == F_SETFD) {
        return 0;
    }
    if (cmd == F_GETFL) {
        return 0;
    }
    if (cmd == F_SETFL) {
        va_list ap;
        va_start(ap, cmd);
        int flags = va_arg(ap, int);
        va_end(ap);
        u_long mode = (flags & O_NONBLOCK) ? 1 : 0;
        if (ioctlsocket(s, FIONBIO, &mode) != 0) {
            return -1;
        }
        return 0;
    }
    return 0;
}
#undef fcntl
#define fcntl win_compat_fcntl

static __inline ssize_t win_compat_read(int fd, void *buf, size_t count) {
    int r = recv((SOCKET)fd, (char *)buf, (int)count, 0);
    if (r != SOCKET_ERROR) {
        return (ssize_t)r;
    }
    {
        int werr = WSAGetLastError();
        if (werr == WSAENOTSOCK) {
            return (ssize_t)_read(fd, buf, (unsigned int)count);
        }
        if (werr == WSAEWOULDBLOCK || werr == WSAEINPROGRESS) {
            errno = EAGAIN;
        } else if (werr == WSAECONNRESET) {
            errno = ECONNRESET;
        } else {
            errno = EIO;
        }
    }
    return -1;
}
#undef read
#define read win_compat_read

static __inline ssize_t win_compat_write(int fd, const void *buf, size_t count) {
    int r = send((SOCKET)fd, (const char *)buf, (int)count, 0);
    if (r != SOCKET_ERROR) {
        return (ssize_t)r;
    }
    {
        int werr = WSAGetLastError();
        if (werr == WSAENOTSOCK) {
            return (ssize_t)_write(fd, buf, (unsigned int)count);
        }
        if (werr == WSAEWOULDBLOCK || werr == WSAEINPROGRESS) {
            errno = EAGAIN;
        } else if (werr == WSAECONNRESET) {
            errno = ECONNRESET;
        } else {
            errno = EIO;
        }
    }
    return -1;
}
#undef write
#define write win_compat_write

static __inline int win_compat_close(int fd) {
    if (closesocket((SOCKET)fd) == 0) {
        return 0;
    }
    return _close(fd);
}
#undef close
#define close win_compat_close

static __inline int win_compat_dup2(int oldfd, int newfd) {
    int r = _dup2(oldfd, newfd);
    if (r == 0) {
        return newfd;
    }
    return -1;
}
#undef dup2
#define dup2 win_compat_dup2

static __inline int win_compat_pthread_once(pthread_once_t *once_control, void (*init_routine)(void)) {
    if (!once_control || !init_routine) return -1;
    if (InterlockedCompareExchangePointer(&once_control->p, (void *)1, NULL) == NULL) {
        init_routine();
        once_control->p = (void *)2;
    } else {
        while (once_control->p != (void *)2) {
            Sleep(1);
        }
    }
    return 0;
}
#undef pthread_once
#define pthread_once win_compat_pthread_once

static __inline int win_compat_kill(pid_t pid, int sig) {
    if (sig == SIGHUP) {
        return 0;
    }
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, (DWORD)pid);
    if (!h) {
        return 0;
    }
    TerminateProcess(h, (UINT)sig);
    CloseHandle(h);
    return 0;
}
#undef kill
#define kill win_compat_kill

static __inline pid_t win_compat_waitpid(pid_t pid, int *status, int options) {
    (void)options;
    HANDLE h = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_INFORMATION, FALSE, (DWORD)pid);
    if (h) {
        WaitForSingleObject(h, 2000);
        if (status) {
            DWORD code = 0;
            GetExitCodeProcess(h, &code);
            *status = (int)code;
        }
        CloseHandle(h);
    }
    return pid;
}
#undef waitpid
#define waitpid win_compat_waitpid

static __inline int getsubopt(char **optionp, char * const *tokens, char **valuep) {
    char *subopt;
    int i;

    *valuep = NULL;
    if (optionp == NULL || *optionp == NULL)
        return -1;

    subopt = *optionp;
    while (**optionp != '\0' && **optionp != ',' && **optionp != '=')
        (*optionp)++;

    if (**optionp == '=') {
        **optionp = '\0';
        (*optionp)++;
        *valuep = *optionp;
        while (**optionp != '\0' && **optionp != ',')
            (*optionp)++;
        if (**optionp == ',') {
            **optionp = '\0';
            (*optionp)++;
        }
    } else if (**optionp == ',') {
        **optionp = '\0';
        (*optionp)++;
    }

    for (i = 0; tokens[i] != NULL; i++) {
        if (strcmp(subopt, tokens[i]) == 0)
            return i;
    }

    if (*valuep == NULL)
        *valuep = subopt;

    return -1;
}

static __inline int setgroups(size_t size, const gid_t *list) {
    (void)size;
    (void)list;
    return 0;
}

#ifndef _STRUCT_PASSWD_DEFINED
#define _STRUCT_PASSWD_DEFINED
#include <posix-pwdgrp.h>
#endif

static __inline ssize_t getline(char **lineptr, size_t *n, FILE *stream) {
    size_t pos = 0;
    int c;

    if (lineptr == NULL || n == NULL || stream == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (*lineptr == NULL || *n == 0) {
        *n = 128;
        *lineptr = (char *)malloc(*n);
        if (*lineptr == NULL) {
            errno = ENOMEM;
            return -1;
        }
    }

    while ((c = fgetc(stream)) != EOF) {
        if (pos + 2 >= *n) {
            size_t new_size = *n * 2;
            char *new_ptr = (char *)realloc(*lineptr, new_size);
            if (new_ptr == NULL) {
                errno = ENOMEM;
                return -1;
            }
            *lineptr = new_ptr;
            *n = new_size;
        }
        (*lineptr)[pos++] = (char)c;
        if (c == 10)
            break;
    }

    if (pos == 0 && c == EOF)
        return -1;

    (*lineptr)[pos] = '\0';
    return (ssize_t)pos;
}

#endif /* _WIN32 || _MSC_VER */

#endif /* WIN_COMPAT_H */

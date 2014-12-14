#include "config.h"
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/audit.h>
#include <errno.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <asm/unistd.h>
#include "memcached.h"

#define ARG2_LO 24
#define ARG2_HI 28

#define ARCH_OFFSET 4
#define SYSCALL_NR_OFFSET 0

#define JEQ(val, dest)  BPF_JUMP(BPF_JMP + BPF_JEQ, (val), (dest), 0)
#define JNE(val, dest)  BPF_JUMP(BPF_JMP + BPF_JEQ, (val), 0, (dest))
#define JMP(dest)       BPF_JUMP(BPF_JMP, 0, (dest), 0)

#define LD_ABS(offset)  BPF_STMT(BPF_LD + BPF_W + BPF_ABS, (offset))

#define ALLOW() BPF_STMT(BPF_RET, SECCOMP_RET_ALLOW)
#define DENY()  BPF_STMT(BPF_RET, SECCOMP_RET_ERRNO + EPERM)

#if defined(__i386__)
# define LOCAL_ARCH AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define LOCAL_ARCH AUDIT_ARCH_X86_64
#endif

#if !defined(LOCAL_ARCH)
void drop_privileges(void) {
}
void drop_worker_privileges(void) {
}
#else
void drop_privileges(void) {
    struct sock_filter filter[] = {
        ALLOW(),
        LD_ABS(ARCH_OFFSET),
        JEQ(LOCAL_ARCH, 1),
        DENY(),

        LD_ABS(SYSCALL_NR_OFFSET),
        JEQ(__NR_sendto, 6),
        JEQ(__NR_rt_sigreturn, 5),
        JEQ(__NR_exit_group, 4),
        JEQ(__NR_exit, 3),
        JEQ(__NR_write, 2),
        JEQ(__NR_epoll_wait, 1),
        JNE(__NR_accept, 1),
        ALLOW(),

        // fcntl allows F_GETFL and F_SETFL only
        JNE(__NR_fcntl, 7),

        LD_ABS(ARG2_LO),
        JNE(F_GETFL, 2),
        LD_ABS(ARG2_HI),
        JEQ(0, 4),

        JNE(F_SETFL, 2),
        LD_ABS(ARG2_HI),
        JEQ(0, 1),
        DENY(),
        ALLOW(),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    int res = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (res < 0) {
        perror("enabling NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }

    res = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
    if (res < 0) {
        perror("enabling SECCOMP");
        exit(EXIT_FAILURE);
    }
}

void drop_worker_privileges(void) {
    struct sock_filter filter[] = {
        ALLOW(),
        LD_ABS(ARCH_OFFSET),
        JEQ(LOCAL_ARCH, 1),
        DENY(),

        LD_ABS(SYSCALL_NR_OFFSET),
        JEQ(__NR_rt_sigreturn, 12),
        JEQ(__NR_write, 11),
        JEQ(__NR_epoll_wait, 10),
        JEQ(__NR_futex, 9),
        JEQ(__NR_mmap, 8),
        JEQ(__NR_munmap, 7),
        JEQ(__NR_mprotect, 6),
        JEQ(__NR_epoll_ctl, 5),
        JEQ(__NR_recvfrom, 4),
        JEQ(__NR_close, 3),
        JEQ(__NR_sendmsg, 2),
        JEQ(__NR_getrusage, 1),

        DENY(),
        ALLOW(),
    };

    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    int res = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    if (res < 0) {
        perror("enabling NO_NEW_PRIVS");
        exit(EXIT_FAILURE);
    }

    res = prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
    if (res < 0) {
        perror("enabling SECCOMP");
        exit(EXIT_FAILURE);
    }
}
#endif

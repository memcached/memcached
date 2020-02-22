#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sysexits.h>

#include <assert.h>

volatile sig_atomic_t caught_sig = 0;

static void signal_handler(int which)
{
    caught_sig = which;
}

static int wait_for_process(pid_t pid)
{
    int rv = EX_SOFTWARE;
    int status = 0;
    int i = 0;
    struct sigaction sig_handler;

    memset(&sig_handler, 0, sizeof(struct sigaction));
    sig_handler.sa_handler = signal_handler;
    sig_handler.sa_flags = 0;

    sigaction(SIGALRM, &sig_handler, NULL);
    sigaction(SIGHUP, &sig_handler, NULL);
    sigaction(SIGINT, &sig_handler, NULL);
    sigaction(SIGUSR1, &sig_handler, NULL);
    sigaction(SIGTERM, &sig_handler, NULL);
    sigaction(SIGPIPE, &sig_handler, NULL);

    /* Loop forever waiting for the process to quit */
    for (i = 0; ;i++) {
        pid_t p = waitpid(pid, &status, 0);
        if (p == pid) {
            /* child exited.  Let's get out of here */
            rv = WIFEXITED(status) ?
                WEXITSTATUS(status) :
                (0x80 | WTERMSIG(status));
            break;
        } else {
            int sig = 0;
            switch (i) {
            case 0:
                /* On the first iteration, pass the signal through */
                sig = caught_sig > 0 ? caught_sig : SIGTERM;
                if (caught_sig == SIGALRM) {
                   fprintf(stderr, "Timeout.. killing the process\n");
                }
                break;
            case 1:
                sig = SIGTERM;
                break;
            default:
                sig = SIGKILL;
                break;
            }
            if (kill(pid, sig) < 0) {
                /* Kill failed.  Must have lost the process. :/ */
                perror("lost child when trying to kill");
            }
            /* Wait up to 5 seconds for the pid */
            alarm(5);
        }
    }
    return rv;
}

static int spawn_and_wait(char **argv)
{
    int rv = EX_SOFTWARE;
    pid_t pid = fork();

    switch (pid) {
    case -1:
        perror("fork");
        rv = EX_OSERR;
        break; /* NOTREACHED */
    case 0:
        execvp(argv[0], argv);
        perror("exec");
        rv = EX_SOFTWARE;
        break; /* NOTREACHED */
    default:
        rv = wait_for_process(pid);
    }
    return rv;
}

static void usage(void) {
    fprintf(stderr, "./timedrun <naptime in sec> args...\n");
    exit(-1);
}

int main(int argc, char **argv)
{
    int naptime = 0;
    if (argc < 3)
        usage();

    naptime = atoi(argv[1]);
    assert(naptime > 0 && naptime < 1800);

    alarm(naptime);

    return spawn_and_wait(argv+2);
}

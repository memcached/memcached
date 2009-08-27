#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <sysexits.h>

#include <assert.h>

static int caught = 0;

static void caught_signal(int which)
{
    caught = which;
}

static int wait_for_process(pid_t pid)
{
    int rv = EX_SOFTWARE;
    int stats = 0;
    int i = 0;
    struct sigaction sig_handler;

    sig_handler.sa_handler = caught_signal;
    sig_handler.sa_flags = 0;

    sigaction(SIGALRM, &sig_handler, NULL);
    sigaction(SIGHUP, &sig_handler, NULL);
    sigaction(SIGINT, &sig_handler, NULL);
    sigaction(SIGTERM, &sig_handler, NULL);
    sigaction(SIGPIPE, &sig_handler, NULL);

    /* Loop forever waiting for the process to quit */
    for (i = 0; ;i++) {
        pid_t p = waitpid(pid, &stats, 0);
        if (p == pid) {
            /* child exited.  Let's get out of here */
            rv = WIFEXITED(stats) ?
                WEXITSTATUS(stats) :
                (0x80 | WTERMSIG(stats));
            break;
        } else {
            int sig = 0;
            switch (i) {
            case 0:
                /* On the first iteration, pass the signal through */
                sig = caught > 0 ? caught : SIGTERM;
                if (caught == SIGALRM) {
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

static int spawn_and_wait(int argc, char **argv)
{
    int rv = EX_SOFTWARE;
    pid_t pid = fork();

    assert(argc > 1);

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

int main(int argc, char **argv)
{
    int naptime = 0;
    assert(argc > 2);

    naptime = atoi(argv[1]);
    assert(naptime > 0 && naptime < 1800);

    alarm(naptime);

    return spawn_and_wait(argc+2, argv+2);
}

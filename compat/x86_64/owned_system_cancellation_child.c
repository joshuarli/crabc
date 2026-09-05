#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

/* Test protocol target installed only at /bin/sh in a private fixture root.
 * This verifies system/popen spawn arguments and inherited state. It does
 * not parse or implement shell language. Both products and musl use this
 * exact source, with their own runtime, as the controlled exec target. */
int main(int argc, char **argv) {
    int ack_read, ack_write, release_read, release_write, status, consumed=0;
    if (argc!=3 || strcmp(argv[0],"sh") || strcmp(argv[1],"-c") ||
        sscanf(argv[2],"crabc-system-wait %d %d %d %d %d%n",
            &ack_read,&ack_write,&release_read,&release_write,&status,&consumed)!=5 ||
        argv[2][consumed] || status!=23) return 81;
    const char *environment=getenv("CRABC_SYSTEM_CANCELLATION");
    if (!environment || strcmp(environment,"source-owned-child")) return 82;
    sigset_t mask; struct sigaction interrupt, quit;
    if (sigprocmask(SIG_SETMASK,NULL,&mask) || sigaction(SIGINT,NULL,&interrupt) ||
        sigaction(SIGQUIT,NULL,&quit) || interrupt.sa_handler!=SIG_DFL || quit.sa_handler!=SIG_IGN ||
        sigismember(&mask,SIGUSR2)!=1 || sigismember(&mask,SIGCHLD)!=0) return 83;
    if (close(ack_read) || close(release_write)) return 84;
    int pid=getpid();
    if (write(ack_write,&pid,sizeof pid)!=sizeof pid || close(ack_write)) return 85;
    char release;
    if (read(release_read,&release,1)<0 || close(release_read)) return 86;
    return status;
}

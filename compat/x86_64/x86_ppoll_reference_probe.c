/* Pinned-musl Linux/x86-64 ppoll, pause, and signal-mask reference. */
#define _GNU_SOURCE 1

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t ppoll_seen;
static volatile sig_atomic_t pause_seen;

static void ppoll_handler(int signal_number)
{
    (void)signal_number;
    ppoll_seen = 1;
}

static void pause_handler(int signal_number)
{
    (void)signal_number;
    pause_seen = 1;
}

int main(void)
{
    int pipe_fds[2];
    struct pollfd fd;
    struct timespec zero = { 0, 0 };
    sigset_t empty;
    sigset_t selected;
    sigset_t previous;
    sigset_t observed;
    struct sigaction action;
    struct sigaction old_action;
    char byte;

    if (pipe(pipe_fds) != 0)
        return 10;
    fd.fd = pipe_fds[0];
    fd.events = POLLIN;
    fd.revents = 0;
    sigemptyset(&empty);
    if (ppoll(&fd, 1, &zero, &empty) != 0 || fd.revents != 0)
        return 11;
    if (write(pipe_fds[1], "x", 1) != 1)
        return 12;
    if (ppoll(&fd, 1, &zero, &empty) != 1 || !(fd.revents & POLLIN))
        return 13;
    if (read(pipe_fds[0], &byte, 1) != 1)
        return 14;
    close(pipe_fds[1]);
    fd.revents = 0;
    if (ppoll(&fd, 1, &zero, &empty) != 1 || !(fd.revents & POLLHUP))
        return 15;
    close(pipe_fds[0]);

    memset(&action, 0, sizeof(action));
    action.sa_handler = ppoll_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGUSR1, &action, &old_action) != 0)
        return 16;
    sigemptyset(&selected);
    sigaddset(&selected, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &selected, &previous) != 0)
        return 17;
    ppoll_seen = 0;
    if (raise(SIGUSR1) != 0)
        return 18;
    errno = 0;
    if (ppoll(NULL, 0, &zero, &empty) != -1 || errno != EINTR)
        return 19;
    if (sigprocmask(SIG_SETMASK, NULL, &observed) != 0 ||
        !sigismember(&observed, SIGUSR1) || !ppoll_seen)
        return 20;
    if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0 ||
        sigaction(SIGUSR1, &old_action, NULL) != 0)
        return 21;

    memset(&action, 0, sizeof(action));
    action.sa_handler = pause_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGALRM, &action, &old_action) != 0)
        return 22;
    pause_seen = 0;
    alarm(1);
    errno = 0;
    if (pause() != -1 || errno != EINTR || !pause_seen)
        return 23;
    alarm(0);
    if (sigaction(SIGALRM, &old_action, NULL) != 0)
        return 24;

    printf("ppoll=0,1,1 revents=0x0,pollin,pollhup mask-restored=1 pause=eintr\n");
    return 0;
}

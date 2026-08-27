/* Pinned-musl Linux/x86-64 pselect6 ABI and behavior reference. */
#define _GNU_SOURCE 1

#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

_Static_assert(FD_SETSIZE == 1024, "x86 fd_set descriptor count");
_Static_assert(sizeof(fd_set) == 128, "x86 fd_set size");
_Static_assert(sizeof(unsigned long) == 8, "x86 fd_set word size");
_Static_assert(SYS_pselect6 == 270, "x86 pselect6 syscall number");
_Static_assert(sizeof(struct timespec) == 16, "x86 pselect timespec size");

static volatile sig_atomic_t signal_seen;

struct kernel_sigmask {
    const unsigned long *mask;
    size_t size;
};

static void pselect_handler(int signal_number)
{
    (void)signal_number;
    signal_seen = 1;
}

static long raw_pselect6(int nfds, fd_set *readfds, fd_set *writefds,
                         fd_set *exceptfds, struct timespec *timeout,
                         const unsigned long *mask)
{
    const struct kernel_sigmask signal_argument = {
        .mask = mask,
        .size = sizeof(*mask),
    };

    return syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, timeout,
                   &signal_argument);
}

int main(void)
{
    int pipe_fds[2];
    fd_set readfds;
    sigset_t empty;
    struct timespec timeout = { 0, 0 };
    struct timespec saved_timeout;
    struct timespec raw_timeout = { 0, 0 };
    struct timeval select_timeout = { 0, 0 };
    unsigned long raw_empty = 0;
    char byte;

    if (pipe(pipe_fds) != 0)
        return 10;
    sigemptyset(&empty);

    FD_ZERO(&readfds);
    FD_SET(pipe_fds[0], &readfds);
    if (select(pipe_fds[0] + 1, &readfds, NULL, NULL, &select_timeout) != 0 ||
        FD_ISSET(pipe_fds[0], &readfds))
        return 11;
    if (write(pipe_fds[1], "s", 1) != 1)
        return 12;
    FD_ZERO(&readfds);
    FD_SET(pipe_fds[0], &readfds);
    select_timeout.tv_sec = 0;
    select_timeout.tv_usec = 0;
    if (select(pipe_fds[0] + 1, &readfds, NULL, NULL, &select_timeout) != 1 ||
        !FD_ISSET(pipe_fds[0], &readfds))
        return 13;
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 's')
        return 14;

    FD_ZERO(&readfds);
    FD_SET(pipe_fds[0], &readfds);
    saved_timeout = timeout;
    if (pselect(pipe_fds[0] + 1, &readfds, NULL, NULL, &timeout, &empty) != 0 ||
        FD_ISSET(pipe_fds[0], &readfds) ||
        memcmp(&timeout, &saved_timeout, sizeof(timeout)) != 0)
        return 15;

    if (write(pipe_fds[1], "x", 1) != 1)
        return 16;
    FD_ZERO(&readfds);
    FD_SET(pipe_fds[0], &readfds);
    if (pselect(pipe_fds[0] + 1, &readfds, NULL, NULL, &timeout, &empty) != 1 ||
        !FD_ISSET(pipe_fds[0], &readfds))
        return 17;
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'x')
        return 18;

    FD_ZERO(&readfds);
    FD_SET(pipe_fds[0], &readfds);
    raw_timeout.tv_sec = 0;
    raw_timeout.tv_nsec = 0;
    if (raw_pselect6(pipe_fds[0] + 1, &readfds, NULL, NULL, &raw_timeout,
                     &raw_empty) != 0 ||
        FD_ISSET(pipe_fds[0], &readfds))
        return 19;
    if (write(pipe_fds[1], "r", 1) != 1)
        return 20;
    FD_ZERO(&readfds);
    FD_SET(pipe_fds[0], &readfds);
    raw_timeout.tv_sec = 0;
    raw_timeout.tv_nsec = 0;
    if (raw_pselect6(pipe_fds[0] + 1, &readfds, NULL, NULL, &raw_timeout,
                     &raw_empty) != 1 ||
        !FD_ISSET(pipe_fds[0], &readfds))
        return 21;
    if (read(pipe_fds[0], &byte, 1) != 1 || byte != 'r')
        return 22;

    errno = 0;
    if (pselect(-1, NULL, NULL, NULL, &timeout, &empty) != -1 || errno != EINVAL)
        return 23;
    errno = 0;
    if (raw_pselect6(-1, NULL, NULL, NULL, &raw_timeout, &raw_empty) != -1 ||
        errno != EINVAL)
        return 24;

    {
        struct sigaction action;
        struct sigaction old_action;
        sigset_t selected;
        sigset_t previous;
        sigset_t observed;

        memset(&action, 0, sizeof(action));
        action.sa_handler = pselect_handler;
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGUSR1, &action, &old_action) != 0)
            return 25;
        sigemptyset(&selected);
        sigaddset(&selected, SIGUSR1);
        if (sigprocmask(SIG_BLOCK, &selected, &previous) != 0)
            return 26;
        signal_seen = 0;
        if (raise(SIGUSR1) != 0)
            return 27;
        FD_ZERO(&readfds);
        errno = 0;
        if (pselect(0, &readfds, NULL, NULL, &timeout, &empty) != -1 ||
            errno != EINTR || !signal_seen)
            return 28;
        signal_seen = 0;
        if (raise(SIGUSR1) != 0)
            return 29;
        raw_timeout.tv_sec = 0;
        raw_timeout.tv_nsec = 0;
        errno = 0;
        if (raw_pselect6(0, NULL, NULL, NULL, &raw_timeout, &raw_empty) != -1 ||
            errno != EINTR || !signal_seen)
            return 30;
        if (sigprocmask(SIG_SETMASK, NULL, &observed) != 0 ||
            !sigismember(&observed, SIGUSR1))
            return 31;
        if (sigprocmask(SIG_SETMASK, &previous, NULL) != 0 ||
            sigaction(SIGUSR1, &old_action, NULL) != 0)
            return 32;
    }

    close(pipe_fds[0]);
    close(pipe_fds[1]);
    printf("select=0,1 pselect=0,1 raw-pselect=0,1 invalid=musl+raw-einval timeout-preserved=1 mask-restored=musl+raw\n");
    return 0;
}

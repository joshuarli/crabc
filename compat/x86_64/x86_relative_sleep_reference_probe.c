/* Pinned-musl Linux/x86-64 relative nanosleep behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(_Alignof(struct timespec) == 8, "x86 timespec alignment");
_Static_assert(SYS_nanosleep == 35, "x86 nanosleep syscall");

static volatile sig_atomic_t signal_delivered;

static void interrupt_handler(int signal_number)
{
    (void)signal_number;
    signal_delivered = 1;
}

int main(void)
{
    struct timespec zero = { 0, 0 };
    struct timespec invalid = { 0, 1000000000L };
    struct timespec requested = { 2, 0 };
    struct timespec remaining;
    struct sigaction action = { 0 };
    struct sigaction old_action;

    if (nanosleep(&zero, NULL) != 0)
        return 1;

    errno = 0;
    if (nanosleep(&invalid, NULL) != -1 || errno != EINVAL)
        return 2;

    action.sa_handler = interrupt_handler;
    sigemptyset(&action.sa_mask);
    action.sa_flags = 0;
    if (sigaction(SIGALRM, &action, &old_action) != 0)
        return 3;
    signal_delivered = 0;
    if (ualarm(20000, 0) != 0)
        return 4;

    errno = 0;
    if (nanosleep(&requested, &remaining) != -1 || errno != EINTR ||
        !signal_delivered || remaining.tv_sec < 0 ||
        remaining.tv_nsec < 0 || remaining.tv_nsec >= 1000000000L ||
        (remaining.tv_sec == 0 && remaining.tv_nsec == 0))
        return 5;

    if (sigaction(SIGALRM, &old_action, NULL) != 0)
        return 6;
    puts("zero=complete invalid=einval interrupted=eintr remainder=positive");
    return 0;
}

#define _GNU_SOURCE 1

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <unistd.h>

extern sighandler_t bsd_signal(int, sighandler_t);
extern sighandler_t __sysv_signal(int, sighandler_t);

int main(void)
{
    const long value = 0x23456789L;
    char *encoded;
    long decoded;
    int priority;

    encoded = l64a(value);
    if (!encoded || !*encoded)
        return 1;
    decoded = a64l(encoded);
    if (decoded != value)
        return 2;
    if (a64l(l64a(0xdeadbeefL)) != (long)(int32_t)0xdeadbeef)
        return 3;
    /* a64l retains the low 32-bit payload, even though long is 64-bit. */
    if (a64l("./0123") != (long)(int32_t)((1u << 6) + (2u << 12) +
                                            (3u << 18) + (4u << 24) +
                                            (5u << 30)))
        return 4;
    if (a64l("2!") != 4)
        return 5;
    encoded = l64a(0);
    if (!encoded || *encoded)
        return 6;

    if (bsd_signal(SIGUSR1, SIG_IGN) != SIG_DFL)
        return 7;
    if (__sysv_signal(SIGUSR1, SIG_DFL) != SIG_IGN)
        return 8;

    priority = getpriority(PRIO_PROCESS, 0);
    if (priority < -20 || priority > 19)
        return 9;
    if (nice(0) != priority)
        return 10;
    if (setpriority(99, 0, priority) != -1 || errno != EINVAL)
        return 11;
    if (getpriority(99, 0) != -1 || errno != EINVAL)
        return 12;

    puts("m4 system utils exports ok");
    return 0;
}

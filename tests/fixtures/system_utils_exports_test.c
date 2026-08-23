#define _GNU_SOURCE 1

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <search.h>
#include <sys/resource.h>
#include <unistd.h>

extern sighandler_t bsd_signal(int, sighandler_t);
extern sighandler_t __sysv_signal(int, sighandler_t);

static int compare_ints(const void *left, const void *right)
{
    const int a = *(const int *)left;
    const int b = *(const int *)right;
    return (a > b) - (a < b);
}

static int compare_ints_with_direction(const void *left, const void *right, void *context)
{
    const int result = compare_ints(left, right);
    const int reverse = *(const int *)context;
    return reverse ? -result : result;
}

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

    {
        /* lsearch may append one value, so reserve that caller-owned slot. */
        int values[6] = {1, 3, 5, 7, 9};
        int key = 5;
        size_t count = 5;
        int *found = bsearch(&key, values, count, sizeof(values[0]), compare_ints);
        if (!found || *found != 5)
            return 13;
        found = lfind(&key, values, &count, sizeof(values[0]), compare_ints);
        if (!found || *found != 5)
            return 14;
        key = 6;
        found = lsearch(&key, values, &count, sizeof(values[0]), compare_ints);
        if (!found || *found != 6 || count != 6)
            return 15;

        int sortable[] = {1, 4, 2, 3};
        int reverse = 1;
        qsort_r(sortable, 4, sizeof(sortable[0]), compare_ints_with_direction, &reverse);
        if (sortable[0] != 4 || sortable[1] != 3 || sortable[2] != 2 || sortable[3] != 1)
            return 16;
    }

    puts("c-abi system utils exports ok");
    return 0;
}

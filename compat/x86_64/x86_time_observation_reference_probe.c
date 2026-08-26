/* Pinned-musl Linux/x86-64 realtime observation reference. */

#define _GNU_SOURCE 1

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stdio.h>
#include <time.h>

static int normalized(const struct timespec *value)
{
    return value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

int main(void)
{
    struct timespec before;
    struct timespec observed;
    struct timespec after;
    struct timespec cpu_before;
    struct timespec cpu_after;
    volatile unsigned long long checksum = 0;

    if (clock_gettime(CLOCK_REALTIME, &before) != 0 ||
        clock_gettime(CLOCK_REALTIME, &observed) != 0 ||
        clock_gettime(CLOCK_REALTIME, &after) != 0)
        return 1;
    if (!normalized(&before) || !normalized(&observed) || !normalized(&after) ||
        observed.tv_sec < before.tv_sec - 1 || observed.tv_sec > after.tv_sec + 1 ||
        observed.tv_nsec / 1000000L < 0 || observed.tv_nsec / 1000000L >= 1000)
        return 2;

    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_before) != 0)
        return 3;
    for (unsigned long long value = 0; value < 500000ULL; ++value)
        checksum += (value << (value & 15));
    if (clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &cpu_after) != 0)
        return 4;
    if (!normalized(&cpu_before) || !normalized(&cpu_after) ||
        cpu_after.tv_sec < cpu_before.tv_sec ||
        (cpu_after.tv_sec == cpu_before.tv_sec && cpu_after.tv_nsec < cpu_before.tv_nsec) ||
        checksum == 0)
        return 5;

    puts("realtime=normalized milliseconds=truncated process-cpu=nondecreasing");
    return 0;
}

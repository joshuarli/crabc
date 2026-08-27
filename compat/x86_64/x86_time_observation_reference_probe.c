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
    struct timespec time_before;
    struct timespec time_after;
    time_t stored;
    time_t returned;
    time_t observed_time;
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

    if (clock_gettime(CLOCK_REALTIME, &time_before) != 0)
        return 6;
    returned = time(&stored);
    observed_time = time(NULL);
    if (clock_gettime(CLOCK_REALTIME, &time_after) != 0)
        return 7;
    if (returned == (time_t)-1 || observed_time == (time_t)-1 ||
        returned != stored)
        return 8;
    if (time_before.tv_sec <= time_after.tv_sec) {
        if (returned < time_before.tv_sec - 1 ||
            returned > time_after.tv_sec + 1 ||
            observed_time < time_before.tv_sec - 1 ||
            observed_time > time_after.tv_sec + 1)
            return 9;
    } else if (returned < time_after.tv_sec - 1 ||
               returned > time_before.tv_sec + 1 ||
               observed_time < time_after.tv_sec - 1 ||
               observed_time > time_before.tv_sec + 1) {
        return 9;
    }

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

    puts("realtime=normalized milliseconds=truncated c-time=whole-second process-cpu=nondecreasing");
    return 0;
}

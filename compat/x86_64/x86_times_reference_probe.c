/* Pinned-musl Linux/x86-64 times(2) behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/times.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8, "x86 long width");
_Static_assert(sizeof(clock_t) == 8, "x86 clock_t size");
_Static_assert((clock_t)-1 < 0, "x86 clock_t signedness");
_Static_assert(sizeof(struct tms) == 32, "x86 tms size");
_Static_assert(_Alignof(struct tms) == 8, "x86 tms alignment");
_Static_assert(offsetof(struct tms, tms_utime) == 0, "x86 tms user offset");
_Static_assert(offsetof(struct tms, tms_stime) == 8, "x86 tms system offset");
_Static_assert(offsetof(struct tms, tms_cutime) == 16, "x86 tms child-user offset");
_Static_assert(offsetof(struct tms, tms_cstime) == 24,
               "x86 tms child-system offset");
_Static_assert(SYS_times == 100, "x86 times syscall number");

static int process_ticks_are_canonical(const struct tms *value)
{
    return value->tms_utime >= 0 && value->tms_stime >= 0 &&
           value->tms_cutime >= 0 && value->tms_cstime >= 0;
}

static int observation_did_not_decrease(const struct tms *before,
                                        clock_t elapsed_before,
                                        const struct tms *after,
                                        clock_t elapsed_after)
{
    /* The elapsed scalar has a kernel-defined origin and may eventually wrap;
     * this native observation compares only the normal unwrapped sequence. */
    return after->tms_utime >= before->tms_utime &&
           after->tms_stime >= before->tms_stime &&
           after->tms_cutime >= before->tms_cutime &&
           after->tms_cstime >= before->tms_cstime &&
           elapsed_after >= elapsed_before;
}

static clock_t direct_times(struct tms *output)
{
    return (clock_t)syscall(SYS_times, output);
}

int main(void)
{
    struct tms first = {0};
    struct tms direct_first = {0};
    struct tms second = {0};
    struct tms direct_second = {0};
    clock_t first_elapsed;
    clock_t direct_first_elapsed;
    clock_t second_elapsed;
    clock_t direct_second_elapsed;
    volatile uint64_t checksum = 0;

    /* The probe supplies valid output storage, just as the private Rust seam
     * does, so Linux's only documented EFAULT route is intentionally absent. */
    first_elapsed = times(&first);
    if (!process_ticks_are_canonical(&first))
        return 10;

    direct_first_elapsed = direct_times(&direct_first);
    if (!process_ticks_are_canonical(&direct_first) ||
        !observation_did_not_decrease(&first, first_elapsed, &direct_first,
                                      direct_first_elapsed))
        return 11;

    for (uint64_t value = 0; value < 100000; ++value)
        checksum = checksum + value;
    if (checksum == 0)
        return 12;

    second_elapsed = times(&second);
    if (!process_ticks_are_canonical(&second) ||
        !observation_did_not_decrease(&direct_first, direct_first_elapsed,
                                      &second, second_elapsed))
        return 13;

    direct_second_elapsed = direct_times(&direct_second);
    if (!process_ticks_are_canonical(&direct_second) ||
        !observation_did_not_decrease(&second, second_elapsed, &direct_second,
                                      direct_second_elapsed))
        return 14;

    puts("layout=tms32/8 offsets=0,8,16,24 clock_t=signed64 syscall=100 fields=nonnegative sequence=nondecreasing direct=observed");
    return 0;
}

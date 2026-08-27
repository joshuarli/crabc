/* Pinned-musl Linux/x86-64 sched_rr_get_interval(2) reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires little-endian x86-64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

struct guarded_timespec {
    struct timespec value;
    unsigned char trailing[16];
};

_Static_assert(sizeof(long) == 8, "x86 LP64 long size");
_Static_assert(sizeof(void *) == 8, "x86 LP64 pointer size");
_Static_assert(sizeof(size_t) == 8, "x86 LP64 size_t size");
_Static_assert(sizeof(pid_t) == 4, "x86 pid_t size");
_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(_Alignof(struct timespec) == 8, "x86 timespec alignment");
_Static_assert(offsetof(struct timespec, tv_sec) == 0,
               "x86 timespec seconds offset");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8,
               "x86 timespec nanoseconds offset");
_Static_assert(SYS_sched_rr_get_interval == 148,
               "x86 sched_rr_get_interval syscall number");

static int canonical_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
           value->tv_nsec < 1000000000L;
}

static int trailing_is_unchanged(const struct guarded_timespec *value)
{
    for (size_t index = 0; index < sizeof(value->trailing); ++index) {
        if (value->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

int main(void)
{
    struct guarded_timespec musl_value;
    struct guarded_timespec direct_value;
    struct guarded_timespec musl_missing;
    struct guarded_timespec direct_missing;

    memset(&musl_value, 0xa5, sizeof(musl_value));
    errno = 0;
    if (sched_rr_get_interval(0, &musl_value.value) != 0 ||
        !canonical_timespec(&musl_value.value) ||
        !trailing_is_unchanged(&musl_value))
        return 10;

    memset(&direct_value, 0xa5, sizeof(direct_value));
    errno = 0;
    if (syscall(SYS_sched_rr_get_interval, 0, &direct_value.value) != 0 ||
        !canonical_timespec(&direct_value.value) ||
        !trailing_is_unchanged(&direct_value) ||
        memcmp(&musl_value.value, &direct_value.value,
               sizeof(musl_value.value)) != 0)
        return 11;

    memset(&musl_missing, 0xa5, sizeof(musl_missing));
    errno = 0;
    if (sched_rr_get_interval((pid_t)INT_MAX, &musl_missing.value) != -1 ||
        errno != ESRCH || !trailing_is_unchanged(&musl_missing))
        return 20;

    memset(&direct_missing, 0xa5, sizeof(direct_missing));
    errno = 0;
    if (syscall(SYS_sched_rr_get_interval, (pid_t)INT_MAX,
                &direct_missing.value) != -1 || errno != ESRCH ||
        !trailing_is_unchanged(&direct_missing))
        return 21;

    puts("layout=timespec16/8 offsets=0,8 syscall=148 current=canonical direct=match missing=ESRCH");
    return 0;
}

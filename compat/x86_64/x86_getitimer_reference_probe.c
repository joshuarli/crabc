/* Pinned-musl Linux/x86-64 getitimer ABI and read-only behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

struct guarded_itimerval {
    struct itimerval value;
    unsigned char trailing[16];
};

_Static_assert(sizeof(struct timeval) == 16, "x86 timeval size");
_Static_assert(_Alignof(struct timeval) == 8, "x86 timeval alignment");
_Static_assert(offsetof(struct timeval, tv_sec) == 0, "x86 timeval seconds");
_Static_assert(offsetof(struct timeval, tv_usec) == 8, "x86 timeval microseconds");
_Static_assert(sizeof(struct itimerval) == 32, "x86 itimerval size");
_Static_assert(_Alignof(struct itimerval) == 8, "x86 itimerval alignment");
_Static_assert(offsetof(struct itimerval, it_interval) == 0,
               "x86 itimerval interval offset");
_Static_assert(offsetof(struct itimerval, it_value) == 16,
               "x86 itimerval current-value offset");
_Static_assert(offsetof(struct guarded_itimerval, trailing) == 32,
               "guard begins after the kernel record");
_Static_assert(SYS_getitimer == 36, "x86 getitimer syscall number");
_Static_assert(ITIMER_REAL == 0, "ITIMER_REAL selector");
_Static_assert(ITIMER_VIRTUAL == 1, "ITIMER_VIRTUAL selector");
_Static_assert(ITIMER_PROF == 2, "ITIMER_PROF selector");

static int canonical_timeval(const struct timeval *value)
{
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
           value->tv_usec < 1000000;
}

static int canonical_itimerval(const struct itimerval *value)
{
    return canonical_timeval(&value->it_interval) &&
           canonical_timeval(&value->it_value);
}

static int trailing_is_unchanged(const struct guarded_itimerval *value)
{
    for (size_t index = 0; index < sizeof(value->trailing); ++index) {
        if (value->trailing[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int direct_getitimer(int which, struct itimerval *value)
{
    return syscall(SYS_getitimer, which, value) == 0;
}

int main(void)
{
    static const int targets[] = {
        ITIMER_REAL,
        ITIMER_VIRTUAL,
        ITIMER_PROF,
    };
    struct guarded_itimerval invalid;

    for (size_t index = 0; index < sizeof(targets) / sizeof(targets[0]);
         ++index) {
        struct guarded_itimerval musl_value;
        struct guarded_itimerval direct_value;

        memset(&musl_value, 0xa5, sizeof(musl_value));
        if (getitimer(targets[index], &musl_value.value) != 0 ||
            !canonical_itimerval(&musl_value.value) ||
            !trailing_is_unchanged(&musl_value))
            return 10 + (int)index;

        memset(&direct_value, 0xa5, sizeof(direct_value));
        if (!direct_getitimer(targets[index], &direct_value.value) ||
            !canonical_itimerval(&direct_value.value) ||
            !trailing_is_unchanged(&direct_value))
            return 20 + (int)index;
    }

    /* Do not compare successive values: a real timer can decrement between
       the musl call and the direct syscall. This probe remains query-only. */
    memset(&invalid, 0xa5, sizeof(invalid));
    errno = 0;
    if (getitimer(3, &invalid.value) != -1 || errno != EINVAL ||
        !trailing_is_unchanged(&invalid))
        return 30;
    errno = 0;
    if (syscall(SYS_getitimer, 3, &invalid.value) != -1 || errno != EINVAL ||
        !trailing_is_unchanged(&invalid))
        return 31;

    puts("layout=timeval16/8 itimerval32/8 offsets=timeval0,8/itimerval0,16 syscall=36 selectors=0,1,2 canonical=valid direct=all-selectors invalid=EINVAL");
    return 0;
}

/* Pinned-musl Linux/x86-64 getrlimit/prlimit64 behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

_Static_assert(sizeof(unsigned long) == 8, "x86 unsigned long width");
_Static_assert(sizeof(struct rlimit) == 16, "x86 rlimit size");
_Static_assert(_Alignof(struct rlimit) == 8, "x86 rlimit alignment");
_Static_assert(offsetof(struct rlimit, rlim_cur) == 0,
               "x86 rlimit current offset");
_Static_assert(offsetof(struct rlimit, rlim_max) == 8,
               "x86 rlimit maximum offset");
_Static_assert(RLIM_INFINITY == UINT64_MAX, "x86 RLIM_INFINITY");
_Static_assert(SYS_prlimit64 == 302, "x86 prlimit64 syscall number");

_Static_assert(RLIMIT_CPU == 0, "x86 RLIMIT_CPU");
_Static_assert(RLIMIT_FSIZE == 1, "x86 RLIMIT_FSIZE");
_Static_assert(RLIMIT_DATA == 2, "x86 RLIMIT_DATA");
_Static_assert(RLIMIT_STACK == 3, "x86 RLIMIT_STACK");
_Static_assert(RLIMIT_CORE == 4, "x86 RLIMIT_CORE");
_Static_assert(RLIMIT_RSS == 5, "x86 RLIMIT_RSS");
_Static_assert(RLIMIT_NPROC == 6, "x86 RLIMIT_NPROC");
_Static_assert(RLIMIT_NOFILE == 7, "x86 RLIMIT_NOFILE");
_Static_assert(RLIMIT_MEMLOCK == 8, "x86 RLIMIT_MEMLOCK");
_Static_assert(RLIMIT_AS == 9, "x86 RLIMIT_AS");
_Static_assert(RLIMIT_LOCKS == 10, "x86 RLIMIT_LOCKS");
_Static_assert(RLIMIT_SIGPENDING == 11, "x86 RLIMIT_SIGPENDING");
_Static_assert(RLIMIT_MSGQUEUE == 12, "x86 RLIMIT_MSGQUEUE");
_Static_assert(RLIMIT_NICE == 13, "x86 RLIMIT_NICE");
_Static_assert(RLIMIT_RTPRIO == 14, "x86 RLIMIT_RTPRIO");
_Static_assert(RLIMIT_RTTIME == 15, "x86 RLIMIT_RTTIME");

static int same_limit(const struct rlimit *left, const struct rlimit *right)
{
    return left->rlim_cur == right->rlim_cur &&
           left->rlim_max == right->rlim_max;
}

static int valid_limit(const struct rlimit *limit)
{
    if (limit->rlim_cur > limit->rlim_max)
        return 0;
    return limit->rlim_cur != RLIM_INFINITY ||
           limit->rlim_max == RLIM_INFINITY;
}

static int query_prlimit64(pid_t pid, int resource, struct rlimit *result)
{
    /* A null new-limit argument makes this direct query read-only. */
    return syscall(SYS_prlimit64, pid, resource, NULL, result) == 0;
}

int main(void)
{
    static const int resources[] = {
        RLIMIT_CPU,
        RLIMIT_FSIZE,
        RLIMIT_DATA,
        RLIMIT_STACK,
        RLIMIT_CORE,
        RLIMIT_RSS,
        RLIMIT_NPROC,
        RLIMIT_NOFILE,
        RLIMIT_MEMLOCK,
        RLIMIT_AS,
        RLIMIT_LOCKS,
        RLIMIT_SIGPENDING,
        RLIMIT_MSGQUEUE,
        RLIMIT_NICE,
        RLIMIT_RTPRIO,
        RLIMIT_RTTIME,
    };
    struct rlimit nofile_first;
    struct rlimit nofile_second;
    struct rlimit nofile_explicit;
    struct rlimit nofile_direct;
    struct rlimit invalid;
    pid_t self = getpid();

    /* Every pinned selector must query successfully and preserve the
     * soft-limit <= hard-limit invariant through both read-only boundaries. */
    for (size_t index = 0; index < sizeof(resources) / sizeof(resources[0]);
         ++index) {
        struct rlimit libc_limit;
        struct rlimit direct_limit;

        if (getrlimit(resources[index], &libc_limit) != 0 ||
            !valid_limit(&libc_limit))
            return 10;
        if (!query_prlimit64(0, resources[index], &direct_limit) ||
            !valid_limit(&direct_limit) || !same_limit(&libc_limit, &direct_limit))
            return 11;
    }

    if (getrlimit(RLIMIT_NOFILE, &nofile_first) != 0 ||
        getrlimit(RLIMIT_NOFILE, &nofile_second) != 0 ||
        !valid_limit(&nofile_first) || !same_limit(&nofile_first, &nofile_second))
        return 20;

    if (self <= 0 || prlimit(self, RLIMIT_NOFILE, NULL, &nofile_explicit) != 0 ||
        !valid_limit(&nofile_explicit) ||
        !same_limit(&nofile_first, &nofile_explicit))
        return 21;
    if (!query_prlimit64(self, RLIMIT_NOFILE, &nofile_direct) ||
        !valid_limit(&nofile_direct) ||
        !same_limit(&nofile_first, &nofile_direct))
        return 22;

    errno = 0;
    if (getrlimit(-1, &invalid) != -1 || errno != EINVAL)
        return 30;

    /* Linux's PID namespace cannot assign INT_MAX, making this missing-PID
     * check stable while leaving every resource limit untouched. */
    errno = 0;
    if (prlimit((pid_t)INT_MAX, RLIMIT_NOFILE, NULL, &invalid) != -1 ||
        errno != ESRCH)
        return 31;

    puts("layout=size16 align8 offsets=0,8 unsigned-long=8 infinity=UINT64_MAX syscall=302 selectors=0..15 invariants=valid nofile=stable current-pid=equivalent invalid=EINVAL missing=ESRCH");
    return 0;
}

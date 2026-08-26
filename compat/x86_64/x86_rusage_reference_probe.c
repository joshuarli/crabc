/* Pinned-musl Linux/x86-64 getrusage behavior reference. */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <unistd.h>

struct kernel_rusage_prefix {
    struct timeval ru_utime;
    struct timeval ru_stime;
    long ru_maxrss;
    long ru_ixrss;
    long ru_idrss;
    long ru_isrss;
    long ru_minflt;
    long ru_majflt;
    long ru_nswap;
    long ru_inblock;
    long ru_oublock;
    long ru_msgsnd;
    long ru_msgrcv;
    long ru_nsignals;
    long ru_nvcsw;
    long ru_nivcsw;
};

_Static_assert(sizeof(long) == 8, "x86 long width");
_Static_assert(sizeof(struct timeval) == 16, "x86 timeval size");
_Static_assert(_Alignof(struct timeval) == 8, "x86 timeval alignment");
_Static_assert(offsetof(struct timeval, tv_sec) == 0, "x86 timeval seconds");
_Static_assert(offsetof(struct timeval, tv_usec) == 8, "x86 timeval microseconds");
_Static_assert(sizeof(struct kernel_rusage_prefix) == 144,
               "x86 initialized rusage prefix size");
_Static_assert(_Alignof(struct kernel_rusage_prefix) == 8,
               "x86 initialized rusage prefix alignment");
_Static_assert(offsetof(struct kernel_rusage_prefix, ru_utime) == 0,
               "x86 rusage user-time offset");
_Static_assert(offsetof(struct kernel_rusage_prefix, ru_stime) == 16,
               "x86 rusage system-time offset");
_Static_assert(offsetof(struct kernel_rusage_prefix, ru_maxrss) == 32,
               "x86 rusage maxrss offset");
_Static_assert(offsetof(struct kernel_rusage_prefix, ru_nivcsw) == 136,
               "x86 rusage involuntary-context-switch offset");
_Static_assert(sizeof(struct rusage) == 272, "pinned musl rusage size");
_Static_assert(_Alignof(struct rusage) == 8, "pinned musl rusage alignment");
_Static_assert(offsetof(struct rusage, ru_utime) == 0,
               "pinned musl rusage user-time offset");
_Static_assert(offsetof(struct rusage, ru_stime) == 16,
               "pinned musl rusage system-time offset");
_Static_assert(offsetof(struct rusage, ru_maxrss) == 32,
               "pinned musl rusage maxrss offset");
_Static_assert(offsetof(struct rusage, ru_nivcsw) == 136,
               "pinned musl rusage involuntary-context-switch offset");
_Static_assert(offsetof(struct rusage, __reserved) == 144,
               "pinned musl rusage reserved-tail offset");
_Static_assert(sizeof(((struct rusage *)0)->__reserved) == 128,
               "pinned musl rusage reserved-tail size");
_Static_assert(SYS_getrusage == 98, "x86 getrusage syscall number");
_Static_assert(RUSAGE_SELF == 0, "x86 RUSAGE_SELF");
_Static_assert(RUSAGE_CHILDREN == -1, "x86 RUSAGE_CHILDREN");
_Static_assert(RUSAGE_THREAD == 1, "x86 RUSAGE_THREAD");

static int canonical_time(const struct timeval *value)
{
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
           value->tv_usec < 1000000;
}

static int canonical_usage(const struct rusage *usage)
{
    return canonical_time(&usage->ru_utime) &&
           canonical_time(&usage->ru_stime) &&
           usage->ru_maxrss >= 0 && usage->ru_ixrss >= 0 &&
           usage->ru_idrss >= 0 && usage->ru_isrss >= 0 &&
           usage->ru_minflt >= 0 && usage->ru_majflt >= 0 &&
           usage->ru_nswap >= 0 && usage->ru_inblock >= 0 &&
           usage->ru_oublock >= 0 && usage->ru_msgsnd >= 0 &&
           usage->ru_msgrcv >= 0 && usage->ru_nsignals >= 0 &&
           usage->ru_nvcsw >= 0 && usage->ru_nivcsw >= 0;
}

static int time_not_decreased(const struct timeval *before,
                              const struct timeval *after)
{
    return after->tv_sec > before->tv_sec ||
           (after->tv_sec == before->tv_sec && after->tv_usec >= before->tv_usec);
}

static int usage_not_decreased(const struct rusage *before,
                               const struct rusage *after)
{
    return time_not_decreased(&before->ru_utime, &after->ru_utime) &&
           time_not_decreased(&before->ru_stime, &after->ru_stime) &&
           after->ru_maxrss >= before->ru_maxrss &&
           after->ru_ixrss >= before->ru_ixrss &&
           after->ru_idrss >= before->ru_idrss &&
           after->ru_isrss >= before->ru_isrss &&
           after->ru_minflt >= before->ru_minflt &&
           after->ru_majflt >= before->ru_majflt &&
           after->ru_nswap >= before->ru_nswap &&
           after->ru_inblock >= before->ru_inblock &&
           after->ru_oublock >= before->ru_oublock &&
           after->ru_msgsnd >= before->ru_msgsnd &&
           after->ru_msgrcv >= before->ru_msgrcv &&
           after->ru_nsignals >= before->ru_nsignals &&
           after->ru_nvcsw >= before->ru_nvcsw &&
           after->ru_nivcsw >= before->ru_nivcsw;
}

static int reserved_tail_is_unchanged(const struct rusage *usage)
{
    const unsigned char *tail = (const unsigned char *)usage +
                                offsetof(struct rusage, __reserved);

    for (size_t index = 0; index < sizeof(usage->__reserved); ++index) {
        if (tail[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int direct_getrusage(int who, void *output)
{
    return syscall(SYS_getrusage, who, output) == 0;
}

int main(void)
{
    static const int targets[] = {
        RUSAGE_SELF,
        RUSAGE_CHILDREN,
        RUSAGE_THREAD,
    };
    struct rusage first;
    struct rusage second;
    struct rusage children;
    struct rusage direct_children;
    struct rusage invalid;
    volatile uint64_t checksum = 0;

    for (size_t index = 0; index < sizeof(targets) / sizeof(targets[0]);
         ++index) {
        struct rusage usage;
        struct rusage direct_usage;

        memset(&usage, 0xa5, sizeof(usage));
        if (getrusage(targets[index], &usage) != 0 ||
            !canonical_usage(&usage) || !reserved_tail_is_unchanged(&usage))
            return 10;
        memset(&direct_usage, 0xa5, sizeof(direct_usage));
        if (!direct_getrusage(targets[index], &direct_usage) ||
            !canonical_usage(&direct_usage) ||
            !reserved_tail_is_unchanged(&direct_usage))
            return 11;
    }

    memset(&first, 0xa5, sizeof(first));
    if (getrusage(RUSAGE_SELF, &first) != 0 || !canonical_usage(&first) ||
        !reserved_tail_is_unchanged(&first))
        return 20;
    for (uint64_t value = 0; value < 100000; ++value)
        checksum = checksum + value;
    if (checksum == 0)
        return 21;
    memset(&second, 0xa5, sizeof(second));
    if (getrusage(RUSAGE_SELF, &second) != 0 || !canonical_usage(&second) ||
        !reserved_tail_is_unchanged(&second) ||
        !usage_not_decreased(&first, &second))
        return 22;

    memset(&children, 0xa5, sizeof(children));
    if (getrusage(RUSAGE_CHILDREN, &children) != 0 ||
        !canonical_usage(&children) || !reserved_tail_is_unchanged(&children))
        return 30;
    memset(&direct_children, 0xa5, sizeof(direct_children));
    if (!direct_getrusage(RUSAGE_CHILDREN, &direct_children) ||
        !canonical_usage(&direct_children) ||
        !reserved_tail_is_unchanged(&direct_children) ||
        memcmp(&children, &direct_children,
               sizeof(struct kernel_rusage_prefix)) != 0)
        return 31;

    errno = 0;
    if (getrusage(99, &invalid) != -1 || errno != EINVAL)
        return 40;
    errno = 0;
    if (syscall(SYS_getrusage, 99, &invalid) != -1 || errno != EINVAL)
        return 41;

    puts("layout=timeval16/8 prefix144/8 rusage272/8 offsets=0,16,32,136 tail=144+128 syscall=98 selectors=0,-1,1 canonical=valid self=nondecreasing direct=all-selectors children=prefix-equivalent invalid=EINVAL");
    return 0;
}

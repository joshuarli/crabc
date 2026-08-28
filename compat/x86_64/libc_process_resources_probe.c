/* Static crabc-libc x86-64 selected process-resources fixture.
 *
 * It runs first through pinned musl and then as a freestanding program linked
 * only to the selected archive. Raw fork/wait/pipe/read/write/close calls
 * contain mutations and keep one target process live; they do not select a C
 * process, pipe, descriptor, or scheduler-policy interface.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
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

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(id_t) == 4 && sizeof(pid_t) == 4,
    "x86 resource identity widths");
_Static_assert(__builtin_types_compatible_p(rlim_t, unsigned long long),
    "x86 rlim_t spelling");
_Static_assert(sizeof(struct rlimit) == 16 && _Alignof(struct rlimit) == 8 &&
    offsetof(struct rlimit, rlim_cur) == 0 &&
    offsetof(struct rlimit, rlim_max) == 8,
    "x86 rlimit layout");
_Static_assert(RLIM_INFINITY == UINT64_MAX &&
    sizeof(struct rlimit64) == sizeof(struct rlimit) &&
    __builtin_types_compatible_p(rlim64_t, rlim_t),
    "x86 rlimit aliases");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8 &&
    offsetof(struct timeval, tv_sec) == 0 &&
    offsetof(struct timeval, tv_usec) == 8,
    "x86 timeval layout");
_Static_assert(sizeof(struct kernel_rusage_prefix) == 144 &&
    _Alignof(struct kernel_rusage_prefix) == 8,
    "x86 kernel rusage prefix");
_Static_assert(sizeof(struct rusage) == 272 && _Alignof(struct rusage) == 8 &&
    offsetof(struct rusage, ru_utime) == 0 &&
    offsetof(struct rusage, ru_stime) == 16 &&
    offsetof(struct rusage, ru_maxrss) == 32 &&
    offsetof(struct rusage, ru_nivcsw) == 136 &&
    offsetof(struct rusage, __reserved) == 144 &&
    sizeof(((struct rusage *)0)->__reserved) == 128,
    "x86 public rusage layout");
_Static_assert(RLIMIT_CPU == 0 && RLIMIT_FSIZE == 1 && RLIMIT_DATA == 2 &&
    RLIMIT_STACK == 3 && RLIMIT_CORE == 4 && RLIMIT_RSS == 5 &&
    RLIMIT_NPROC == 6 && RLIMIT_NOFILE == 7 && RLIMIT_MEMLOCK == 8 &&
    RLIMIT_AS == 9 && RLIMIT_LOCKS == 10 && RLIMIT_SIGPENDING == 11 &&
    RLIMIT_MSGQUEUE == 12 && RLIMIT_NICE == 13 && RLIMIT_RTPRIO == 14 &&
    RLIMIT_RTTIME == 15 && RLIMIT_NLIMITS == 16 &&
    RLIM_NLIMITS == RLIMIT_NLIMITS,
    "x86 resource selectors");
_Static_assert(PRIO_MIN == -20 && PRIO_MAX == 20 && PRIO_PROCESS == 0 &&
    PRIO_PGRP == 1 && PRIO_USER == 2 && RUSAGE_SELF == 0 &&
    RUSAGE_CHILDREN == -1 && RUSAGE_THREAD == 1,
    "x86 priority and rusage selectors");
_Static_assert(SYS_getrusage == 98 && SYS_getpriority == 140 &&
    SYS_setpriority == 141 && SYS_prlimit64 == 302 && SYS_fork == 57 &&
    SYS_wait4 == 61 && SYS_exit == 60 && SYS_pipe == 22 && SYS_read == 0 &&
    SYS_write == 1 && SYS_close == 3 && SYS_getpid == 39 &&
    SYS_getpgid == 121 && SYS_geteuid == 107,
    "x86 selected resource and fixture syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrlimit),
    int (*)(int, struct rlimit *)), "getrlimit declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setrlimit),
    int (*)(int, const struct rlimit *)), "setrlimit declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&prlimit),
    int (*)(pid_t, int, const struct rlimit *, struct rlimit *)),
    "prlimit declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&prlimit64),
    int (*)(pid_t, int, const struct rlimit *, struct rlimit *)),
    "prlimit64 alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrlimit64),
    int (*)(int, struct rlimit *)), "getrlimit64 alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setrlimit64),
    int (*)(int, const struct rlimit *)), "setrlimit64 alias declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrusage),
    int (*)(int, struct rusage *)), "getrusage declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpriority),
    int (*)(int, id_t)), "getpriority declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setpriority),
    int (*)(int, id_t, int)), "setpriority declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nice), int (*)(int)),
    "nice declaration");

static long raw_syscall0(long number)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall1(long number, long argument1)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(argument1)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall2(long number, long argument1, long argument2)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument1, long argument2,
    long argument3)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static void raw_exit(int status) __attribute__((noreturn));

static void raw_exit(int status)
{
    (void)raw_syscall1(SYS_exit, status);
    for (;;)
        __asm__ volatile("pause" ::: "memory");
}

static void fill_bytes(void *destination, unsigned char value, size_t length)
{
    unsigned char *bytes = destination;
    size_t index;

    for (index = 0; index < length; ++index)
        bytes[index] = value;
}

static int bytes_equal(const void *left, const void *right, size_t length)
{
    const unsigned char *left_bytes = left;
    const unsigned char *right_bytes = right;
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left_bytes[index] != right_bytes[index])
            return 0;
    }
    return 1;
}

static int same_limit(const struct rlimit *left, const struct rlimit *right)
{
    return left->rlim_cur == right->rlim_cur &&
        left->rlim_max == right->rlim_max;
}

static int valid_limit(const struct rlimit *limit)
{
    return limit->rlim_cur <= limit->rlim_max &&
        (limit->rlim_cur != RLIM_INFINITY ||
         limit->rlim_max == RLIM_INFINITY);
}

static struct rlimit reversible_limit(struct rlimit original)
{
    struct rlimit changed = original;

    if (original.rlim_cur != RLIM_INFINITY &&
        original.rlim_cur < original.rlim_max) {
        ++changed.rlim_cur;
    } else if (original.rlim_cur != RLIM_INFINITY && original.rlim_cur > 0) {
        --changed.rlim_cur;
    } else if (original.rlim_max == RLIM_INFINITY) {
        changed.rlim_cur = 1;
    }
    return changed;
}

static long raw_prlimit(pid_t process_id, int resource,
    const struct rlimit *input, struct rlimit *output)
{
    return raw_syscall4(SYS_prlimit64, process_id, resource, (long)input,
        (long)output);
}

static int check_limit_queries(void)
{
    static const int resources[] = {
        RLIMIT_CPU, RLIMIT_FSIZE, RLIMIT_DATA, RLIMIT_STACK, RLIMIT_CORE,
        RLIMIT_RSS, RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_MEMLOCK, RLIMIT_AS,
        RLIMIT_LOCKS, RLIMIT_SIGPENDING, RLIMIT_MSGQUEUE, RLIMIT_NICE,
        RLIMIT_RTPRIO, RLIMIT_RTTIME,
    };
    pid_t self = (pid_t)raw_syscall0(SYS_getpid);
    struct rlimit nofile;
    struct rlimit explicit_self;
    struct rlimit alias_self;
    struct rlimit invalid;
    size_t index;

    if (self <= 0)
        return 1;
    for (index = 0; index < sizeof(resources) / sizeof(resources[0]); ++index) {
        struct rlimit candidate;
        struct rlimit direct;

        if (getrlimit(resources[index], &candidate) != 0 ||
            !valid_limit(&candidate))
            return 2;
        if (raw_prlimit(0, resources[index], NULL, &direct) != 0 ||
            !valid_limit(&direct) || !same_limit(&candidate, &direct))
            return 3;
    }
    if (getrlimit(RLIMIT_NOFILE, &nofile) != 0 ||
        prlimit(self, RLIMIT_NOFILE, NULL, &explicit_self) != 0 ||
        prlimit64(self, RLIMIT_NOFILE, NULL, &alias_self) != 0 ||
        !same_limit(&nofile, &explicit_self) ||
        !same_limit(&nofile, &alias_self))
        return 4;

    errno = 0;
    if (getrlimit(-1, &invalid) != -1 || errno != EINVAL)
        return 5;
    errno = 0;
    if (prlimit((pid_t)INT_MAX, RLIMIT_NOFILE, NULL, &invalid) != -1 ||
        errno != ESRCH)
        return 6;
    return 0;
}

static int child_limit_transaction(void)
{
    const struct rlimit inverted = { .rlim_cur = 1, .rlim_max = 0 };
    struct rlimit original;
    struct rlimit changed;
    struct rlimit old;
    struct rlimit observed;

    if (getrlimit(RLIMIT_CORE, &original) != 0 || !valid_limit(&original))
        return 1;
    changed = reversible_limit(original);
    if (!valid_limit(&changed))
        return 2;
    if (prlimit(0, RLIMIT_CORE, &changed, &old) != 0 ||
        !same_limit(&old, &original))
        return 3;
    if (getrlimit(RLIMIT_CORE, &observed) != 0 ||
        !same_limit(&observed, &changed))
        return 4;
    if (prlimit(0, RLIMIT_CORE, &original, NULL) != 0)
        return 5;
    if (getrlimit(RLIMIT_CORE, &observed) != 0 ||
        !same_limit(&observed, &original))
        return 6;
    errno = 0;
    if (setrlimit(RLIMIT_CORE, &inverted) != -1 || errno != EINVAL)
        return 7;
    return 0;
}

static int run_child_case(int (*child_case)(void))
{
    long child = raw_syscall0(SYS_fork);
    int status = -1;
    long waited;

    if (child == 0)
        raw_exit(child_case());
    if (child < 0)
        return 1;
    do {
        waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    } while (waited == -EINTR);
    if (waited != child)
        return 2;
    return status == 0 ? 0 : 3;
}

static int check_live_child_prlimit(void)
{
    int ready[2] = { -1, -1 };
    int release[2] = { -1, -1 };
    long child;
    int status = -1;
    long waited;
    int result = 0;
    char byte = 0;
    struct rlimit parent;
    struct rlimit candidate;
    struct rlimit direct;

    if (raw_syscall1(SYS_pipe, (long)ready) != 0 ||
        raw_syscall1(SYS_pipe, (long)release) != 0)
        return 1;
    if (getrlimit(RLIMIT_NOFILE, &parent) != 0 || parent.rlim_cur == 0) {
        result = 2;
        goto finish_without_child;
    }
    child = raw_syscall0(SYS_fork);
    if (child == 0) {
        struct rlimit original;
        struct rlimit changed;

        (void)raw_syscall1(SYS_close, ready[0]);
        (void)raw_syscall1(SYS_close, release[1]);
        if (getrlimit(RLIMIT_NOFILE, &original) != 0 ||
            original.rlim_cur == 0)
            raw_exit(10);
        changed = original;
        --changed.rlim_cur;
        if (setrlimit(RLIMIT_NOFILE, &changed) != 0)
            raw_exit(11);
        if (raw_syscall3(SYS_write, ready[1], (long)&byte, 1) != 1)
            raw_exit(12);
        if (raw_syscall3(SYS_read, release[0], (long)&byte, 1) != 1)
            raw_exit(13);
        raw_exit(0);
    }
    if (child < 0) {
        result = 3;
        goto finish_without_child;
    }
    (void)raw_syscall1(SYS_close, ready[1]);
    ready[1] = -1;
    (void)raw_syscall1(SYS_close, release[0]);
    release[0] = -1;
    if (raw_syscall3(SYS_read, ready[0], (long)&byte, 1) != 1) {
        result = 4;
    } else if (prlimit((pid_t)child, RLIMIT_NOFILE, NULL, &candidate) != 0 ||
        raw_prlimit((pid_t)child, RLIMIT_NOFILE, NULL, &direct) != 0 ||
        !same_limit(&candidate, &direct) ||
        candidate.rlim_cur == parent.rlim_cur) {
        result = 5;
    }
    (void)raw_syscall3(SYS_write, release[1], (long)&byte, 1);
    do {
        waited = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    } while (waited == -EINTR);
    if (result == 0 && (waited != child || status != 0))
        result = 6;

finish_without_child:
    if (ready[0] >= 0)
        (void)raw_syscall1(SYS_close, ready[0]);
    if (ready[1] >= 0)
        (void)raw_syscall1(SYS_close, ready[1]);
    if (release[0] >= 0)
        (void)raw_syscall1(SYS_close, release[0]);
    if (release[1] >= 0)
        (void)raw_syscall1(SYS_close, release[1]);
    return result;
}

static int canonical_time(const struct timeval *value)
{
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
        value->tv_usec < 1000000;
}

static int canonical_usage(const struct rusage *usage)
{
    return canonical_time(&usage->ru_utime) &&
        canonical_time(&usage->ru_stime) && usage->ru_maxrss >= 0 &&
        usage->ru_ixrss >= 0 && usage->ru_idrss >= 0 &&
        usage->ru_isrss >= 0 && usage->ru_minflt >= 0 &&
        usage->ru_majflt >= 0 && usage->ru_nswap >= 0 &&
        usage->ru_inblock >= 0 && usage->ru_oublock >= 0 &&
        usage->ru_msgsnd >= 0 && usage->ru_msgrcv >= 0 &&
        usage->ru_nsignals >= 0 && usage->ru_nvcsw >= 0 &&
        usage->ru_nivcsw >= 0;
}

static int time_not_decreased(const struct timeval *before,
    const struct timeval *after)
{
    return after->tv_sec > before->tv_sec ||
        (after->tv_sec == before->tv_sec &&
         after->tv_usec >= before->tv_usec);
}

static int usage_not_decreased(const struct rusage *before,
    const struct rusage *after)
{
    return time_not_decreased(&before->ru_utime, &after->ru_utime) &&
        time_not_decreased(&before->ru_stime, &after->ru_stime);
}

static int reserved_tail_is_unchanged(const struct rusage *usage)
{
    const unsigned char *tail = (const unsigned char *)usage +
        offsetof(struct rusage, __reserved);
    size_t index;

    for (index = 0; index < sizeof(usage->__reserved); ++index) {
        if (tail[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int check_rusage(void)
{
    static const int resources[] = {
        RUSAGE_SELF, RUSAGE_CHILDREN, RUSAGE_THREAD,
    };
    struct rusage first;
    struct rusage second;
    struct rusage children;
    struct rusage direct_children;
    struct rusage invalid;
    volatile uint64_t checksum = 0;
    size_t index;

    for (index = 0; index < sizeof(resources) / sizeof(resources[0]); ++index) {
        struct rusage usage;
        struct rusage direct;

        fill_bytes(&usage, 0xa5, sizeof(usage));
        if (getrusage(resources[index], &usage) != 0 ||
            !canonical_usage(&usage) || !reserved_tail_is_unchanged(&usage))
            return 1;
        fill_bytes(&direct, 0xa5, sizeof(direct));
        if (raw_syscall2(SYS_getrusage, resources[index], (long)&direct) != 0 ||
            !canonical_usage(&direct) || !reserved_tail_is_unchanged(&direct))
            return 2;
    }
    fill_bytes(&first, 0xa5, sizeof(first));
    if (getrusage(RUSAGE_SELF, &first) != 0 || !canonical_usage(&first) ||
        !reserved_tail_is_unchanged(&first))
        return 3;
    for (index = 0; index < 100000; ++index)
        checksum += index;
    if (checksum == 0)
        return 4;
    fill_bytes(&second, 0xa5, sizeof(second));
    if (getrusage(RUSAGE_SELF, &second) != 0 || !canonical_usage(&second) ||
        !reserved_tail_is_unchanged(&second) ||
        !usage_not_decreased(&first, &second))
        return 5;

    fill_bytes(&children, 0xa5, sizeof(children));
    fill_bytes(&direct_children, 0xa5, sizeof(direct_children));
    if (getrusage(RUSAGE_CHILDREN, &children) != 0 ||
        raw_syscall2(SYS_getrusage, RUSAGE_CHILDREN,
            (long)&direct_children) != 0 ||
        !canonical_usage(&children) || !canonical_usage(&direct_children) ||
        !reserved_tail_is_unchanged(&children) ||
        !reserved_tail_is_unchanged(&direct_children) ||
        !bytes_equal(&children, &direct_children,
            sizeof(struct kernel_rusage_prefix)))
        return 6;
    errno = 0;
    if (getrusage(99, &invalid) != -1 || errno != EINVAL)
        return 7;
    errno = 0;
    if (getrusage(RUSAGE_SELF, NULL) != -1 || errno != EFAULT)
        return 8;
    return 0;
}

static int read_priority(int which, id_t who, int *value)
{
    int result;

    errno = 0;
    result = getpriority(which, who);
    if (result < -20 || result > 19 || (result == -1 && errno != 0))
        return 0;
    *value = result;
    return 1;
}

static int check_priority_queries(void)
{
    const id_t process_id = (id_t)raw_syscall0(SYS_getpid);
    const id_t group_id = (id_t)raw_syscall1(SYS_getpgid, 0);
    const id_t user_id = (id_t)raw_syscall0(SYS_geteuid);
    int process;
    int process_shorthand;
    int process_group;
    int process_group_shorthand;
    int user;
    int user_shorthand;
    long encoded;

    if (process_id == 0 || group_id == 0 ||
        !read_priority(PRIO_PROCESS, process_id, &process) ||
        !read_priority(PRIO_PROCESS, 0, &process_shorthand) ||
        !read_priority(PRIO_PGRP, group_id, &process_group) ||
        !read_priority(PRIO_PGRP, 0, &process_group_shorthand) ||
        !read_priority(PRIO_USER, user_id, &user) ||
        !read_priority(PRIO_USER, 0, &user_shorthand) ||
        process != process_shorthand ||
        process_group != process_group_shorthand || user != user_shorthand)
        return 1;
    encoded = raw_syscall2(SYS_getpriority, PRIO_PROCESS, process_id);
    if (encoded < 1 || encoded > 40 || 20 - (int)encoded != process)
        return 2;
    errno = 0;
    if (getpriority(PRIO_PROCESS, (id_t)INT_MAX) != -1 || errno != ESRCH)
        return 3;
    errno = 0;
    if (getpriority(99, 0) != -1 || errno != EINVAL)
        return 4;
    return 0;
}

static int child_priority_and_nice(void)
{
    long raw_result;
    int result;

    if (setpriority(PRIO_PROCESS, 0, 19) != 0)
        return 1;
    errno = 0;
    if (getpriority(PRIO_PROCESS, 0) != 19 || errno != 0)
        return 2;
    if (raw_syscall2(SYS_getpriority, PRIO_PROCESS, 0) != 1)
        return 3;
    errno = 0;
    if (setpriority(99, 0, 0) != -1 || errno != EINVAL)
        return 4;
    errno = 0;
    if (setpriority(PRIO_PROCESS, (id_t)INT_MAX, 19) != -1 || errno != ESRCH)
        return 5;
    errno = 0;
    if (setpriority(PRIO_PGRP, (id_t)INT_MAX, 19) != -1 || errno != ESRCH)
        return 6;
    errno = 0;
    if (setpriority(PRIO_USER, (id_t)UINT_MAX, 19) != -1 || errno != ESRCH)
        return 7;
    errno = 0;
    if (nice(0) != 19 || errno != 0)
        return 8;
    /* musl leaves a prior errno untouched when both priority calls succeed. */
    errno = EINVAL;
    if (nice(0) != 19 || errno != EINVAL)
        return 9;
    errno = 0;
    if (nice(INT_MAX) != 19 || errno != 0)
        return 10;

    raw_result = raw_syscall3(SYS_setpriority, PRIO_PROCESS, 0, 18);
    if (raw_result == -EACCES) {
        errno = 0;
        if (nice(-1) != -1 || errno != EPERM)
            return 11;
    } else if (raw_result == 0) {
        errno = 0;
        if (nice(0) != 18 || errno != 0)
            return 12;
        raw_result = raw_syscall3(SYS_setpriority, PRIO_PROCESS, 0, -1);
        if (raw_result == 0) {
            errno = 0;
            result = getpriority(PRIO_PROCESS, 0);
            if (result != -1 || errno != 0)
                return 13;
        }
    } else {
        return 14;
    }
    return 0;
}

int crabc_x86_64_process_resources_probe(void)
{
    int status;

    status = check_limit_queries();
    if (status != 0)
        return 10 + status;
    status = run_child_case(child_limit_transaction);
    if (status != 0)
        return 20 + status;
    status = check_live_child_prlimit();
    if (status != 0)
        return 30 + status;
    status = check_rusage();
    if (status != 0)
        return 40 + status;
    status = check_priority_queries();
    if (status != 0)
        return 50 + status;
    status = run_child_case(child_priority_and_nice);
    if (status != 0)
        return 60 + status;
    return 0;
}

#ifndef CRABC_PROCESS_RESOURCES_FREESTANDING
int main(void)
{
    return crabc_x86_64_process_resources_probe();
}
#endif

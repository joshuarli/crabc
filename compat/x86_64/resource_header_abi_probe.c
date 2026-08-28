/*
 * Native Linux/x86-64 compile-only <sys/resource.h> ABI probe.
 *
 * Pinned musl 1.2.6 owns the selected public resource record, constants,
 * aliases, and declaration contract. The runner compiles this source both
 * in strict C11 mode and with GNU plus large-file selectors. It establishes
 * header evidence only; it neither links nor selects a C runtime.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/resource.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(id_t) == 4,
    "resource header unconditionally exposes x86 id_t");
_Static_assert(__builtin_types_compatible_p(id_t, unsigned int),
    "x86 id_t spelling");
_Static_assert(sizeof(rlim_t) == 8, "x86 rlim_t width");
_Static_assert(__builtin_types_compatible_p(rlim_t, unsigned long long),
    "x86 rlim_t spelling");
_Static_assert(sizeof(struct rlimit) == 16, "x86 rlimit size");
_Static_assert(_Alignof(struct rlimit) == 8, "x86 rlimit alignment");
_Static_assert(offsetof(struct rlimit, rlim_cur) == 0,
    "x86 rlimit current offset");
_Static_assert(offsetof(struct rlimit, rlim_max) == 8,
    "x86 rlimit maximum offset");
_Static_assert(RLIM_INFINITY == UINT64_MAX,
    "x86 infinite resource limit");
_Static_assert(__builtin_types_compatible_p(__typeof__(RLIM_INFINITY),
    unsigned long long), "x86 infinite-limit type");

_Static_assert(sizeof(struct rusage) == 272, "x86 public rusage size");
_Static_assert(_Alignof(struct rusage) == 8, "x86 public rusage alignment");
_Static_assert(offsetof(struct rusage, ru_utime) == 0,
    "x86 rusage user-time offset");
_Static_assert(offsetof(struct rusage, ru_stime) == 16,
    "x86 rusage system-time offset");
_Static_assert(offsetof(struct rusage, ru_maxrss) == 32,
    "x86 rusage maximum-resident offset");
_Static_assert(offsetof(struct rusage, ru_nivcsw) == 136,
    "x86 rusage involuntary-context-switch offset");
_Static_assert(offsetof(struct rusage, __reserved) == 144,
    "x86 rusage caller-resident tail offset");
_Static_assert(sizeof(((struct rusage *)0)->__reserved) == 128,
    "x86 rusage caller-resident tail size");

_Static_assert(PRIO_MIN == -20 && PRIO_MAX == 20 &&
    PRIO_PROCESS == 0 && PRIO_PGRP == 1 && PRIO_USER == 2,
    "x86 priority constants");
_Static_assert(RUSAGE_SELF == 0 && RUSAGE_CHILDREN == -1 && RUSAGE_THREAD == 1,
    "x86 rusage selectors");
_Static_assert(RLIMIT_CPU == 0 && RLIMIT_FSIZE == 1 && RLIMIT_DATA == 2 &&
    RLIMIT_STACK == 3 && RLIMIT_CORE == 4 && RLIMIT_RSS == 5 &&
    RLIMIT_NPROC == 6 && RLIMIT_NOFILE == 7 && RLIMIT_MEMLOCK == 8 &&
    RLIMIT_AS == 9 && RLIMIT_LOCKS == 10 && RLIMIT_SIGPENDING == 11 &&
    RLIMIT_MSGQUEUE == 12 && RLIMIT_NICE == 13 && RLIMIT_RTPRIO == 14 &&
    RLIMIT_RTTIME == 15 && RLIMIT_NLIMITS == 16 &&
    RLIM_NLIMITS == RLIMIT_NLIMITS,
    "x86 resource selectors");

_Static_assert(__builtin_types_compatible_p(__typeof__(&getrlimit),
    int (*)(int, struct rlimit *)), "getrlimit declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setrlimit),
    int (*)(int, const struct rlimit *)), "setrlimit declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrusage),
    int (*)(int, struct rusage *)), "getrusage declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpriority),
    int (*)(int, id_t)), "getpriority declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setpriority),
    int (*)(int, id_t, int)), "setpriority declaration");

#if defined(_GNU_SOURCE)
_Static_assert(sizeof(pid_t) == 4 &&
    __builtin_types_compatible_p(pid_t, int), "x86 GNU pid_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&prlimit),
    int (*)(pid_t, int, const struct rlimit *, struct rlimit *)),
    "prlimit declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&prlimit64),
    int (*)(pid_t, int, const struct rlimit *, struct rlimit *)),
    "prlimit64 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nice), int (*)(int)),
    "nice declaration");
#endif

#if defined(_LARGEFILE64_SOURCE)
_Static_assert(sizeof(struct rlimit64) == sizeof(struct rlimit),
    "large-file rlimit alias");
_Static_assert(__builtin_types_compatible_p(rlim64_t, rlim_t),
    "large-file rlim type alias");
_Static_assert(RLIM64_INFINITY == RLIM_INFINITY &&
    RLIM64_SAVED_CUR == RLIM_SAVED_CUR &&
    RLIM64_SAVED_MAX == RLIM_SAVED_MAX,
    "x86 infinite resource-limit aliases");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getrlimit64),
    int (*)(int, struct rlimit *)), "getrlimit64 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setrlimit64),
    int (*)(int, const struct rlimit *)), "setrlimit64 declaration");
#endif

int crabc_x86_64_resource_header_abi_probe(void)
{
    return RLIMIT_NLIMITS + PRIO_MAX + RUSAGE_THREAD;
}

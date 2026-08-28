/* C++ companion for the native Linux/x86-64 <sys/resource.h> ABI probe. */

#include <stddef.h>
#include <stdint.h>
#include <sys/resource.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

using getrlimit_type = int (*)(int, struct rlimit *);
using setrlimit_type = int (*)(int, const struct rlimit *);
using getrusage_type = int (*)(int, struct rusage *);
using getpriority_type = int (*)(int, id_t);
using setpriority_type = int (*)(int, id_t, int);
#if defined(_GNU_SOURCE)
using prlimit_type = int (*)(pid_t, int, const struct rlimit *,
    struct rlimit *);
#endif

static_assert(sizeof(id_t) == 4 && __is_same(id_t, unsigned int),
    "C++ resource id_t");
static_assert(sizeof(rlim_t) == 8 && __is_same(rlim_t, unsigned long long),
    "C++ rlim_t spelling");
static_assert(sizeof(struct rlimit) == 16 && alignof(struct rlimit) == 8,
    "C++ rlimit layout");
static_assert(RLIM_INFINITY == UINT64_MAX &&
    __is_same(decltype(RLIM_INFINITY), unsigned long long),
    "C++ infinite resource limit");

static_assert(sizeof(struct rusage) == 272 && alignof(struct rusage) == 8,
    "C++ rusage layout");
static_assert(offsetof(struct rusage, ru_utime) == 0 &&
    offsetof(struct rusage, ru_stime) == 16 &&
    offsetof(struct rusage, __reserved) == 144,
    "C++ rusage offsets");
static_assert(sizeof(((struct rusage *)0)->__reserved) == 128,
    "C++ rusage reserved tail");

static_assert(PRIO_MIN == -20 && PRIO_MAX == 20 && RUSAGE_THREAD == 1,
    "C++ resource constants");
static_assert(RLIMIT_NLIMITS == 16 && RLIM_NLIMITS == RLIMIT_NLIMITS,
    "C++ resource selector count");
static_assert(__is_same(decltype(&getrlimit), getrlimit_type),
    "C++ getrlimit declaration");
static_assert(__is_same(decltype(&setrlimit), setrlimit_type),
    "C++ setrlimit declaration");
static_assert(__is_same(decltype(&getrusage), getrusage_type),
    "C++ getrusage declaration");
static_assert(__is_same(decltype(&getpriority), getpriority_type),
    "C++ getpriority declaration");
static_assert(__is_same(decltype(&setpriority), setpriority_type),
    "C++ setpriority declaration");

#if defined(_GNU_SOURCE)
static_assert(sizeof(pid_t) == 4 && __is_same(pid_t, int), "C++ GNU pid_t");
static_assert(__is_same(decltype(&prlimit), prlimit_type),
    "C++ prlimit declaration");
static_assert(__is_same(decltype(&prlimit64), prlimit_type),
    "C++ prlimit64 declaration");
static_assert(__is_same(decltype(&nice), int (*)(int)), "C++ nice declaration");
#endif

#if defined(_LARGEFILE64_SOURCE)
static_assert(sizeof(struct rlimit64) == sizeof(struct rlimit),
    "C++ rlimit large-file alias");
static_assert(__is_same(rlim64_t, rlim_t), "C++ rlim type alias");
static_assert(RLIM64_INFINITY == RLIM_INFINITY,
    "C++ infinite-limit alias");
static_assert(__is_same(decltype(&getrlimit64), getrlimit_type),
    "C++ getrlimit64 declaration");
static_assert(__is_same(decltype(&setrlimit64), setrlimit_type),
    "C++ setrlimit64 declaration");
#endif

int crabc_x86_64_resource_header_abi_probe_cpp()
{
    return RLIMIT_NLIMITS + PRIO_MAX + RUSAGE_THREAD;
}

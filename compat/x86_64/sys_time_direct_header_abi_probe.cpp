/* C++17 companion for the Linux/x86-64 direct <sys/time.h> ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/time.h>

static_assert(sizeof(struct timeval) == 16 && alignof(struct timeval) == 8,
              "x86 timeval ABI");
static_assert(__builtin_offsetof(struct timeval, tv_sec) == 0 &&
                  __builtin_offsetof(struct timeval, tv_usec) == 8,
              "x86 timeval offsets");
static_assert(sizeof(struct itimerval) == 32 && alignof(struct itimerval) == 8,
              "x86 itimerval ABI");
static_assert(__builtin_offsetof(struct itimerval, it_interval) == 0 &&
                  __builtin_offsetof(struct itimerval, it_value) == 16,
              "x86 itimerval offsets");
static_assert(ITIMER_REAL == 0 && ITIMER_VIRTUAL == 1 && ITIMER_PROF == 2,
              "x86 interval timer identifiers");

using gettimeofday_signature = int (*)(struct timeval *__restrict, void *__restrict);
using getitimer_signature = int (*)(int, struct itimerval *);
using setitimer_signature = int (*)(int, const struct itimerval *__restrict,
                                    struct itimerval *__restrict);
using utimes_signature = int (*)(const char *, const struct timeval *);

static_assert(__is_same(decltype(&gettimeofday), gettimeofday_signature),
              "gettimeofday C++ declaration");
static_assert(__is_same(decltype(&getitimer), getitimer_signature),
              "getitimer C++ declaration");
static_assert(__is_same(decltype(&setitimer), setitimer_signature),
              "setitimer C++ declaration");
static_assert(__is_same(decltype(&utimes), utimes_signature),
              "utimes C++ declaration");

__attribute__((used)) static gettimeofday_signature sys_time_cxx_gettimeofday =
    gettimeofday;
__attribute__((used)) static getitimer_signature sys_time_cxx_getitimer = getitimer;
__attribute__((used)) static setitimer_signature sys_time_cxx_setitimer = setitimer;
__attribute__((used)) static utimes_signature sys_time_cxx_utimes = utimes;

#if defined(CRABC_SYS_TIME_REQUIRE_GNU_BSD)
static_assert(sizeof(struct timezone) == 8 && alignof(struct timezone) == 4,
              "x86 timezone ABI");
static_assert(__builtin_offsetof(struct timezone, tz_minuteswest) == 0 &&
                  __builtin_offsetof(struct timezone, tz_dsttime) == 4,
              "x86 timezone offsets");

using futimes_signature = int (*)(int, const struct timeval *);
using futimesat_signature = int (*)(int, const char *, const struct timeval *);
using lutimes_signature = int (*)(const char *, const struct timeval *);
using settimeofday_signature = int (*)(const struct timeval *,
                                       const struct timezone *);
using adjtime_signature = int (*)(const struct timeval *__restrict,
                                  struct timeval *__restrict);

static_assert(__is_same(decltype(&futimes), futimes_signature),
              "futimes C++ declaration");
static_assert(__is_same(decltype(&futimesat), futimesat_signature),
              "futimesat C++ declaration");
static_assert(__is_same(decltype(&lutimes), lutimes_signature),
              "lutimes C++ declaration");
static_assert(__is_same(decltype(&settimeofday), settimeofday_signature),
              "settimeofday C++ declaration");
static_assert(__is_same(decltype(&adjtime), adjtime_signature),
              "adjtime C++ declaration");

__attribute__((used)) static futimes_signature sys_time_cxx_futimes = futimes;
__attribute__((used)) static futimesat_signature sys_time_cxx_futimesat = futimesat;
__attribute__((used)) static lutimes_signature sys_time_cxx_lutimes = lutimes;
__attribute__((used)) static settimeofday_signature sys_time_cxx_settimeofday =
    settimeofday;
__attribute__((used)) static adjtime_signature sys_time_cxx_adjtime = adjtime;

static int exercise_gnu_bsd_timer_macros()
{
    struct timeval first = { 1, 2 };
    struct timeval second = { 3, 4 };
    struct timeval result;
    int selected = timerisset(&first) + timercmp(&first, &second, <);

    /* Musl deliberately exposes these as comma expressions, not statements. */
    return selected + (
        timerclear(&result),
        timeradd(&first, &second, &result),
        timersub(&second, &first, &result),
        static_cast<int>(result.tv_usec)
    );
}
#endif

#if defined(CRABC_SYS_TIME_REQUIRE_GNU)
static long exercise_gnu_time_conversion_macros()
{
    struct timeval timeval_value = { 1, 2 };
    struct timespec timespec_value;

    return (
        TIMEVAL_TO_TIMESPEC(&timeval_value, &timespec_value),
        TIMESPEC_TO_TIMEVAL(&timeval_value, &timespec_value),
        timeval_value.tv_usec + timespec_value.tv_nsec
    );
}
#endif

/* These opt-in references must fail outside their selected feature modes. */
#if defined(CRABC_SYS_TIME_REQUIRE_GNU_BSD_HIDDEN)
using hidden_futimes_signature = int (*)(int, const struct timeval *);
__attribute__((used)) static hidden_futimes_signature sys_time_gnu_bsd_must_be_hidden =
    futimes;
#endif

#if defined(CRABC_SYS_TIME_REQUIRE_GNU_HIDDEN)
#if !defined(TIMEVAL_TO_TIMESPEC)
#error "TIMEVAL_TO_TIMESPEC must stay hidden outside GNU selection"
#endif
static void sys_time_gnu_must_be_hidden()
{
    struct timeval timeval_value = { 0, 0 };
    struct timespec timespec_value;

    TIMEVAL_TO_TIMESPEC(&timeval_value, &timespec_value);
}
#endif

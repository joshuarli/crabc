/* Selected Linux/x86-64 direct <sys/time.h> declaration and layout facts. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/time.h>

_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8,
               "x86 timeval ABI");
_Static_assert(offsetof(struct timeval, tv_sec) == 0 &&
                   offsetof(struct timeval, tv_usec) == 8,
               "x86 timeval offsets");
_Static_assert(sizeof(struct itimerval) == 32 && _Alignof(struct itimerval) == 8,
               "x86 itimerval ABI");
_Static_assert(offsetof(struct itimerval, it_interval) == 0 &&
                   offsetof(struct itimerval, it_value) == 16,
               "x86 itimerval offsets");
_Static_assert(ITIMER_REAL == 0 && ITIMER_VIRTUAL == 1 && ITIMER_PROF == 2,
               "x86 interval timer identifiers");

typedef int (*gettimeofday_signature)(struct timeval *__restrict,
                                      void *__restrict);
typedef int (*getitimer_signature)(int, struct itimerval *);
typedef int (*setitimer_signature)(int, const struct itimerval *__restrict,
                                   struct itimerval *__restrict);
typedef int (*utimes_signature)(const char *, const struct timeval *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&gettimeofday),
                                             gettimeofday_signature),
               "gettimeofday declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getitimer),
                                             getitimer_signature),
               "getitimer declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setitimer),
                                             setitimer_signature),
               "setitimer declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&utimes), utimes_signature),
               "utimes declaration");

#if defined(CRABC_SYS_TIME_REQUIRE_GNU_BSD)
_Static_assert(sizeof(struct timezone) == 8 && _Alignof(struct timezone) == 4,
               "x86 timezone ABI");
_Static_assert(offsetof(struct timezone, tz_minuteswest) == 0 &&
                   offsetof(struct timezone, tz_dsttime) == 4,
               "x86 timezone offsets");

typedef int (*futimes_signature)(int, const struct timeval *);
typedef int (*futimesat_signature)(int, const char *, const struct timeval *);
typedef int (*lutimes_signature)(const char *, const struct timeval *);
typedef int (*settimeofday_signature)(const struct timeval *,
                                      const struct timezone *);
typedef int (*adjtime_signature)(const struct timeval *__restrict,
                                 struct timeval *__restrict);

_Static_assert(__builtin_types_compatible_p(__typeof__(&futimes), futimes_signature),
               "futimes declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&futimesat),
                                             futimesat_signature),
               "futimesat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lutimes), lutimes_signature),
               "lutimes declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&settimeofday),
                                             settimeofday_signature),
               "settimeofday declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&adjtime), adjtime_signature),
               "adjtime declaration");

static int exercise_gnu_bsd_timer_macros(void)
{
    struct timeval first = { 1, 2 };
    struct timeval second = { 3, 4 };
    struct timeval result;
    int selected = timerisset(&first) + timercmp(&first, &second, <);

    timerclear(&result);
    timeradd(&first, &second, &result);
    timersub(&second, &first, &result);
    return selected + (int)result.tv_usec;
}
#endif

#if defined(CRABC_SYS_TIME_REQUIRE_GNU)
static long exercise_gnu_time_conversion_macros(void)
{
    struct timeval timeval_value = { 1, 2 };
    struct timespec timespec_value;

    TIMEVAL_TO_TIMESPEC(&timeval_value, &timespec_value);
    TIMESPEC_TO_TIMEVAL(&timeval_value, &timespec_value);
    return timeval_value.tv_usec + timespec_value.tv_nsec;
}
#endif

/* These opt-in references must fail outside their selected feature modes. */
#if defined(CRABC_SYS_TIME_REQUIRE_GNU_BSD_HIDDEN)
static futimes_signature sys_time_gnu_bsd_must_be_hidden = futimes;
#endif

#if defined(CRABC_SYS_TIME_REQUIRE_GNU_HIDDEN)
#if !defined(TIMEVAL_TO_TIMESPEC)
#error "TIMEVAL_TO_TIMESPEC must stay hidden outside GNU selection"
#endif
static void sys_time_gnu_must_be_hidden(void)
{
    struct timeval timeval_value = { 0, 0 };
    struct timespec timespec_value;

    TIMEVAL_TO_TIMESPEC(&timeval_value, &timespec_value);
}
#endif

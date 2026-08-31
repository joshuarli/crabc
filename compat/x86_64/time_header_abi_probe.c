/*
 * Native x86-64 compile-only <time.h> ABI probe.
 *
 * The selected facts mirror the pinned musl 1.2.6 public header: LP64 time
 * types, timespec/itimerspec/tm records, clock constants, GNU tm aliases,
 * and the POSIX timer function signatures.  This fixture intentionally does
 * not link a C runtime.
 */
#define _GNU_SOURCE 1

#include <stddef.h>
#include <time.h>

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native x86-64 LP64"
#endif

_Static_assert(sizeof(time_t) == 8, "x86 time_t");
_Static_assert(sizeof(clock_t) == 8, "x86 clock_t");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t");
_Static_assert(sizeof(timer_t) == 8, "x86 timer_t");

_Static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
_Static_assert(offsetof(struct timespec, tv_sec) == 0, "timespec tv_sec");
_Static_assert(offsetof(struct timespec, tv_nsec) == 8, "timespec tv_nsec");
_Static_assert(sizeof(struct itimerspec) == 32, "x86 itimerspec size");
_Static_assert(offsetof(struct itimerspec, it_interval) == 0,
               "itimerspec interval");
_Static_assert(offsetof(struct itimerspec, it_value) == 16,
               "itimerspec value");

_Static_assert(sizeof(struct tm) == 56, "x86 tm size");
_Static_assert(offsetof(struct tm, tm_sec) == 0, "tm_sec");
_Static_assert(offsetof(struct tm, tm_isdst) == 32, "tm_isdst");
_Static_assert(offsetof(struct tm, tm_gmtoff) == 40, "tm_gmtoff");
_Static_assert(offsetof(struct tm, tm_zone) == 48, "tm_zone");

_Static_assert(CLOCK_REALTIME == 0, "CLOCK_REALTIME");
_Static_assert(CLOCK_MONOTONIC == 1, "CLOCK_MONOTONIC");
_Static_assert(CLOCK_PROCESS_CPUTIME_ID == 2, "CLOCK_PROCESS_CPUTIME_ID");
_Static_assert(CLOCK_THREAD_CPUTIME_ID == 3, "CLOCK_THREAD_CPUTIME_ID");
_Static_assert(CLOCK_MONOTONIC_RAW == 4, "CLOCK_MONOTONIC_RAW");
_Static_assert(CLOCK_REALTIME_COARSE == 5, "CLOCK_REALTIME_COARSE");
_Static_assert(CLOCK_MONOTONIC_COARSE == 6, "CLOCK_MONOTONIC_COARSE");
_Static_assert(CLOCK_BOOTTIME == 7, "CLOCK_BOOTTIME");
_Static_assert(CLOCK_REALTIME_ALARM == 8, "CLOCK_REALTIME_ALARM");
_Static_assert(CLOCK_BOOTTIME_ALARM == 9, "CLOCK_BOOTTIME_ALARM");
_Static_assert(CLOCK_SGI_CYCLE == 10, "CLOCK_SGI_CYCLE");
_Static_assert(CLOCK_TAI == 11, "CLOCK_TAI");
_Static_assert(TIMER_ABSTIME == 1, "TIMER_ABSTIME");
_Static_assert(TIME_UTC == 1, "TIME_UTC");

static clock_t (*clock_signature)(void) = clock;
static time_t (*time_signature)(time_t *) = time;
static time_t (*mktime_signature)(struct tm *) = mktime;
static time_t (*timegm_signature)(struct tm *) = timegm;
static size_t (*strftime_signature)(char *, size_t, const char *,
                                    const struct tm *) = strftime;
static struct tm *(*gmtime_signature)(const time_t *) = gmtime;
static struct tm *(*localtime_signature)(const time_t *) = localtime;
static int (*timespec_get_signature)(struct timespec *, int) = timespec_get;
static struct tm *(*gmtime_r_signature)(const time_t *, struct tm *) = gmtime_r;
static struct tm *(*localtime_r_signature)(const time_t *, struct tm *) = localtime_r;
static size_t (*strftime_l_signature)(char *, size_t, const char *,
                                      const struct tm *, locale_t) = strftime_l;
static int (*clock_gettime_signature)(clockid_t, struct timespec *) = clock_gettime;
static int (*clock_nanosleep_signature)(clockid_t, int, const struct timespec *,
                                        struct timespec *) = clock_nanosleep;
static int (*timer_create_signature)(clockid_t, struct sigevent *, timer_t *) = timer_create;
static int (*timer_settime_signature)(timer_t, int, const struct itimerspec *,
                                      struct itimerspec *) = timer_settime;

int main(void)
{
    struct tm calendar = { 0 };
    calendar.tm_gmtoff = 0;
    calendar.tm_zone = NULL;
    (void)clock_signature;
    (void)time_signature;
    (void)mktime_signature;
    (void)timegm_signature;
    (void)strftime_signature;
    (void)gmtime_signature;
    (void)localtime_signature;
    (void)timespec_get_signature;
    (void)gmtime_r_signature;
    (void)localtime_r_signature;
    (void)strftime_l_signature;
    (void)clock_gettime_signature;
    (void)clock_nanosleep_signature;
    (void)timer_create_signature;
    (void)timer_settime_signature;
    return calendar.tm_zone != NULL;
}

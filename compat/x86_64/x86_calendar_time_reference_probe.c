/*
 * Pinned-musl/raw Linux/x86-64 civil-time reference.
 *
 * The raw helper below proves the narrow Linux wall-clock boundary used by
 * the staged Rust facade: gettimeofday(2) writes one LP64 timeval through
 * SYS_gettimeofday with a null legacy timezone pointer.  The UTC and local
 * calendar checks then use pinned musl's C/POSIX APIs as an external oracle.
 *
 * The POSIX TZ check deliberately changes TZ and invokes tzset(3), but only
 * in this short-lived oracle process.  The Rust facade does neither: its
 * local-calendar projection receives immutable POSIX/TZif rules explicitly,
 * never calls C time APIs, and never reads or mutates process-global TZ
 * state.  This fixture therefore selects neither a C time ABI nor public
 * x86-64 runtime support.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8 &&
                   sizeof(size_t) == 8 && sizeof(time_t) == 8,
               "x86 LP64 scalar widths");
_Static_assert((time_t)-1 < (time_t)0, "x86 time_t is signed");
_Static_assert(sizeof(struct timeval) == 16, "x86 timeval size");
_Static_assert(_Alignof(struct timeval) == 8, "x86 timeval alignment");
_Static_assert(offsetof(struct timeval, tv_sec) == 0,
               "x86 timeval seconds offset");
_Static_assert(offsetof(struct timeval, tv_usec) == 8,
               "x86 timeval microseconds offset");
_Static_assert(SYS_gettimeofday == 96, "x86 gettimeofday syscall number");

enum {
    GUARD_SIZE = 16,
    GUARD_BYTE = 0xa5,
};

struct guarded_timeval {
    struct timeval value;
    unsigned char trailing[GUARD_SIZE];
};

_Static_assert(offsetof(struct guarded_timeval, trailing) == sizeof(struct timeval),
               "gettimeofday guard begins after timeval");

struct utc_anchor {
    time_t seconds;
    int year;
    int month;
    int day;
    int hour;
    int minute;
    int second;
    int weekday;
    int yearday;
};

static int timeval_is_normalized(const struct timeval *value)
{
    return value->tv_usec >= 0 && value->tv_usec < 1000000;
}

static int trailing_is_unchanged(const struct guarded_timeval *value)
{
    size_t index;

    for (index = 0; index < sizeof(value->trailing); index++) {
        if (value->trailing[index] != GUARD_BYTE)
            return 0;
    }
    return 1;
}

/*
 * Linux/x86-64 syscall arguments are rdi (timeval output pointer) and rsi
 * (nullable legacy timezone pointer).  The staged native boundary always
 * passes null for rsi: timezone state belongs to explicit `TimeZone` input,
 * not to a process-global C record.
 */
static int raw_gettimeofday(struct guarded_timeval *value)
{
    memset(value, GUARD_BYTE, sizeof(*value));
    return syscall(SYS_gettimeofday, &value->value, NULL) == 0 &&
           timeval_is_normalized(&value->value) && trailing_is_unchanged(value);
}

static int utc_anchor_matches(const struct utc_anchor *anchor)
{
    struct tm calendar;
    struct tm inverse;

    if (gmtime_r(&anchor->seconds, &calendar) == NULL)
        return 0;
    if (calendar.tm_year != anchor->year - 1900 ||
        calendar.tm_mon != anchor->month - 1 ||
        calendar.tm_mday != anchor->day || calendar.tm_hour != anchor->hour ||
        calendar.tm_min != anchor->minute || calendar.tm_sec != anchor->second ||
        calendar.tm_wday != anchor->weekday || calendar.tm_yday != anchor->yearday ||
        calendar.tm_isdst != 0 || calendar.tm_gmtoff != 0 ||
        calendar.tm_zone == NULL || strcmp(calendar.tm_zone, "UTC") != 0)
        return 0;

    /* `timegm` mutates its input, so retain the gmtime_r result separately. */
    inverse = calendar;
    return timegm(&inverse) == anchor->seconds &&
           inverse.tm_year == calendar.tm_year &&
           inverse.tm_mon == calendar.tm_mon &&
           inverse.tm_mday == calendar.tm_mday &&
           inverse.tm_hour == calendar.tm_hour &&
           inverse.tm_min == calendar.tm_min &&
           inverse.tm_sec == calendar.tm_sec && inverse.tm_wday == calendar.tm_wday &&
           inverse.tm_yday == calendar.tm_yday && inverse.tm_isdst == 0 &&
           inverse.tm_gmtoff == 0 && inverse.tm_zone != NULL &&
           strcmp(inverse.tm_zone, "UTC") == 0;
}

static int local_anchor_matches(time_t seconds, int year, int month, int day,
                                int hour, int minute, int second, int weekday,
                                int yearday, int is_daylight_saving,
                                long seconds_east_of_utc,
                                const char *abbreviation)
{
    struct tm calendar;

    if (localtime_r(&seconds, &calendar) == NULL)
        return 0;
    return calendar.tm_year == year - 1900 && calendar.tm_mon == month - 1 &&
           calendar.tm_mday == day && calendar.tm_hour == hour &&
           calendar.tm_min == minute && calendar.tm_sec == second &&
           calendar.tm_wday == weekday && calendar.tm_yday == yearday &&
           calendar.tm_isdst == is_daylight_saving &&
           calendar.tm_gmtoff == seconds_east_of_utc &&
           calendar.tm_zone != NULL &&
           strcmp(calendar.tm_zone, abbreviation) == 0;
}

int main(void)
{
    static const struct utc_anchor utc_anchors[] = {
        { 0, 1970, 1, 1, 0, 0, 0, 4, 0 },
        { -1, 1969, 12, 31, 23, 59, 59, 3, 364 },
        { 951827696, 2000, 2, 29, 12, 34, 56, 2, 59 },
        { -2208988800LL, 1900, 1, 1, 0, 0, 0, 1, 0 },
        { -5359564800LL, 1800, 3, 1, 0, 0, 0, 6, 59 },
        { 4107542400LL, 2100, 3, 1, 0, 0, 0, 1, 59 },
        { 13574649600LL, 2400, 3, 1, 0, 0, 0, 3, 60 },
    };
    struct guarded_timeval first;
    struct guarded_timeval second;
    size_t index;

    /* Keep the direct syscall query-only: wall-clock adjustment is separate. */
    if (!raw_gettimeofday(&first) || !raw_gettimeofday(&second))
        return 1;

    for (index = 0; index < sizeof(utc_anchors) / sizeof(utc_anchors[0]);
         index++) {
        if (!utc_anchor_matches(&utc_anchors[index]))
            return 10 + (int)index;
    }

    /*
     * A POSIX string avoids system zoneinfo selection.  This particular rule
     * is the same immutable input used by the native local-calendar tests:
     * standard UTC-05:00, daylight UTC-04:00, second Sunday in March through
     * first Sunday in November at the POSIX-default 02:00 local transition.
     */
    if (setenv("TZ", "EST5EDT4,M3.2.0/2,M11.1.0/2", 1) != 0)
        return 30;
    tzset();

    if (!local_anchor_matches(1710053999LL, 2024, 3, 10, 1, 59, 59, 0, 69,
                              0, -18000, "EST"))
        return 31;
    if (!local_anchor_matches(1710054000LL, 2024, 3, 10, 3, 0, 0, 0, 69, 1,
                              -14400, "EDT"))
        return 32;
    if (!local_anchor_matches(1730613599LL, 2024, 11, 3, 1, 59, 59, 0, 307,
                              1, -14400, "EDT"))
        return 33;
    if (!local_anchor_matches(1730613600LL, 2024, 11, 3, 1, 0, 0, 0, 307, 0,
                              -18000, "EST"))
        return 34;

    puts("syscall=gettimeofday:96 abi=rdi-timeval:rsi-null layout=timeval16/8:offsets=0,8 raw=normalized:record-bounded utc=gmtime_r:timegm:epoch:pre-epoch:leap:400-year tz=POSIX-EST5EDT4-M3.2.0-M11.1.0 dst=start-gap:end-fold native=rule-input-only:no-c-time-abi:no-TZ-global c-api-selection=excluded");
    return 0;
}

/* Static crabc-libc x86-64 fixed-UTC timegm fixture.
 *
 * The same project-header C body first executes through pinned musl 1.2.6
 * and then through a freestanding candidate linked solely with the selected
 * crabc archive. It admits exactly GNU/BSD timegm's caller-owned, mutable UTC
 * struct-tm normalization. It does not select timezone/environment state,
 * local conversion, calendar formatting/parsing, clock observation or
 * mutation, timers, cancellation, CRT, loader, sysroot, or public x86
 * support.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#if defined(CRABC_TIMEGM_ORACLE_EMIT) || \
    (defined(CRABC_TIMEGM_RECORD) && !defined(CRABC_TIMEGM_FREESTANDING))
#include <stdio.h>
#endif

_Static_assert(sizeof(time_t) == 8, "x86 time_t width");
_Static_assert(sizeof(struct tm) == 56 && _Alignof(struct tm) == 8,
    "x86 struct tm layout");
_Static_assert(offsetof(struct tm, tm_sec) == 0 &&
    offsetof(struct tm, tm_min) == 4 &&
    offsetof(struct tm, tm_hour) == 8 &&
    offsetof(struct tm, tm_mday) == 12 &&
    offsetof(struct tm, tm_mon) == 16 &&
    offsetof(struct tm, tm_year) == 20 &&
    offsetof(struct tm, tm_wday) == 24 &&
    offsetof(struct tm, tm_yday) == 28 &&
    offsetof(struct tm, tm_isdst) == 32 &&
    offsetof(struct tm, tm_gmtoff) == 40 &&
    offsetof(struct tm, tm_zone) == 48,
    "x86 struct tm field offsets");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timegm),
    time_t (*)(struct tm *)), "timegm declaration");

static int same_tm(const struct tm *left, const struct tm *right)
{
    return left->tm_sec == right->tm_sec &&
        left->tm_min == right->tm_min &&
        left->tm_hour == right->tm_hour &&
        left->tm_mday == right->tm_mday &&
        left->tm_mon == right->tm_mon &&
        left->tm_year == right->tm_year &&
        left->tm_wday == right->tm_wday &&
        left->tm_yday == right->tm_yday &&
        left->tm_isdst == right->tm_isdst &&
        left->tm_gmtoff == right->tm_gmtoff &&
        left->tm_zone == right->tm_zone;
}

static int has_utc_zone(const struct tm *value)
{
    return value->tm_zone != NULL && value->tm_zone[0] == 'U' &&
        value->tm_zone[1] == 'T' && value->tm_zone[2] == 'C' &&
        value->tm_zone[3] == '\0';
}

static int check_normalized(const struct tm *value, int second, int minute,
    int hour, int month_day, int month, int year, int week_day, int year_day)
{
    return value->tm_sec == second && value->tm_min == minute &&
        value->tm_hour == hour && value->tm_mday == month_day &&
        value->tm_mon == month && value->tm_year == year &&
        value->tm_wday == week_day && value->tm_yday == year_day &&
        value->tm_isdst == 0 && value->tm_gmtoff == 0 && has_utc_zone(value);
}

static int epoch(void)
{
    struct tm value = {
        .tm_mday = 1,
        .tm_year = 70,
        .tm_wday = 6,
        .tm_yday = 6,
        .tm_isdst = 1,
        .tm_gmtoff = 99,
        .tm_zone = "not-utc",
    };

    errno = E2BIG;
    if (timegm(&value) != 0 || errno != E2BIG)
        return 1;
    return !check_normalized(&value, 0, 0, 0, 1, 0, 70, 4, 0);
}

static int negative_month(void)
{
    struct tm value = {
        .tm_mday = 1,
        .tm_mon = -1,
        .tm_year = 70,
        .tm_isdst = -1,
        .tm_gmtoff = -99,
        .tm_zone = "not-utc",
    };

    errno = ERANGE;
    if (timegm(&value) != (time_t)-2678400 || errno != ERANGE)
        return 1;
    return !check_normalized(&value, 0, 0, 0, 1, 11, 69, 1, 334);
}

static int leap_carry(void)
{
    struct tm value = {
        .tm_sec = 60,
        .tm_min = 59,
        .tm_hour = 23,
        .tm_mday = 29,
        .tm_mon = 1,
        .tm_year = 100,
        .tm_isdst = 1,
        .tm_gmtoff = 1,
        .tm_zone = "not-utc",
    };

    errno = E2BIG;
    if (timegm(&value) != (time_t)951868800 || errno != E2BIG)
        return 1;
    return !check_normalized(&value, 0, 0, 0, 1, 2, 100, 3, 60);
}

static int valid_minus_one(void)
{
    struct tm value = {
        .tm_sec = 59,
        .tm_min = 59,
        .tm_hour = 23,
        .tm_mday = 31,
        .tm_mon = 11,
        .tm_year = 69,
        .tm_isdst = 1,
        .tm_gmtoff = 1,
        .tm_zone = "not-utc",
    };

    errno = ERANGE;
    if (timegm(&value) != (time_t)-1 || errno != ERANGE)
        return 1;
    return !check_normalized(&value, 59, 59, 23, 31, 11, 69, 3, 364);
}

static int overflow(void)
{
    const char *const sentinel = (const char *)(uintptr_t)0x1122334455667788ULL;
    struct tm value = {
        .tm_sec = -7,
        .tm_min = 8,
        .tm_hour = -9,
        .tm_mday = 10,
        .tm_mon = INT_MAX,
        .tm_year = INT_MAX,
        .tm_wday = -11,
        .tm_yday = 12,
        .tm_isdst = -13,
        .tm_gmtoff = 14,
        .tm_zone = sentinel,
    };
    const struct tm before = value;

    errno = 0;
    if (timegm(&value) != (time_t)-1 || errno != EOVERFLOW)
        return 1;
    return !same_tm(&value, &before);
}

/* Each case starts with deliberately stale derived fields. The oracle records
 * the whole scalar result, while pointer identity is checked only on failure.
 * tm_mday=INT_MIN is excluded: the C oracle subtracts one in signed int before
 * widening it, so that one input has undefined signed overflow.
 */
struct boundary_case {
    const char *name;
    struct tm input;
    int incoming_errno;
};

#define BOUNDARY(name, year, month, day, hour, minute, second, error) \
    { name, { .tm_sec = second, .tm_min = minute, .tm_hour = hour, \
        .tm_mday = day, .tm_mon = month, .tm_year = year, \
        .tm_wday = -123, .tm_yday = -234, .tm_isdst = 7, \
        .tm_gmtoff = 2222, .tm_zone = "input-zone" }, error }

static const struct boundary_case boundaries[] = {
    BOUNDARY("pre-epoch-day", 69, 11, 30, 23, 59, 59, E2BIG),
    BOUNDARY("negative-epoch", 69, 11, 31, 23, 59, 58, ERANGE),
    BOUNDARY("epoch-next", 70, 0, 1, 0, 0, 1, E2BIG),
    BOUNDARY("leap-1896", -4, 1, 29, 23, 59, 59, ERANGE),
    BOUNDARY("century-1900", 0, 1, 29, 0, 0, 0, E2BIG),
    BOUNDARY("leap-1996", 96, 1, 29, 23, 59, 59, ERANGE),
    BOUNDARY("leap-2000", 100, 1, 29, 23, 59, 59, E2BIG),
    BOUNDARY("century-2100", 200, 1, 29, 23, 59, 59, ERANGE),
    BOUNDARY("leap-2400", 500, 1, 29, 23, 59, 59, E2BIG),
    BOUNDARY("march-from-leap", 100, 1, 30, 0, 0, 0, ERANGE),
    BOUNDARY("march-from-common", 200, 1, 29, 0, 0, 0, E2BIG),
    BOUNDARY("previous-year-month", 70, -12, 1, 0, 0, 0, ERANGE),
    BOUNDARY("previous-year-month-minus-one", 70, -13, 1, 0, 0, 0, E2BIG),
    BOUNDARY("previous-year-month-minus-25", 70, -25, 1, 0, 0, 0, ERANGE),
    BOUNDARY("next-year-month", 70, 12, 1, 0, 0, 0, E2BIG),
    BOUNDARY("two-years-ahead-month", 70, 24, 1, 0, 0, 0, ERANGE),
    BOUNDARY("minimum-month", 70, INT_MIN, 1, 0, 0, 0, E2BIG),
    BOUNDARY("maximum-month", 70, INT_MAX, 1, 0, 0, 0, ERANGE),
    BOUNDARY("previous-day", 70, 0, 0, 0, 0, 0, E2BIG),
    BOUNDARY("negative-day", 70, 0, -1, 0, 0, 0, ERANGE),
    BOUNDARY("day-after-january", 70, 0, 32, 0, 0, 0, E2BIG),
    BOUNDARY("day-366", 70, 0, 366, 0, 0, 0, ERANGE),
    BOUNDARY("minimum-defined-day", 70, 0, INT_MIN + 1, 0, 0, 0, E2BIG),
    BOUNDARY("maximum-day", 70, 0, INT_MAX, 0, 0, 0, ERANGE),
    BOUNDARY("negative-hour", 70, 0, 1, -1, 0, 0, E2BIG),
    BOUNDARY("hour-carry", 70, 0, 1, 24, 0, 0, ERANGE),
    BOUNDARY("negative-minute", 70, 0, 1, 0, -1, 0, E2BIG),
    BOUNDARY("minute-carry", 70, 0, 1, 0, 60, 0, ERANGE),
    BOUNDARY("negative-second", 70, 0, 1, 0, 0, -1, E2BIG),
    BOUNDARY("second-carry", 70, 0, 1, 0, 0, 60, ERANGE),
    BOUNDARY("maximum-time-fields", 70, 0, 1, INT_MAX, INT_MAX, INT_MAX, E2BIG),
    BOUNDARY("minimum-time-fields", 70, 0, 1, INT_MIN, INT_MIN, INT_MIN, ERANGE),
    BOUNDARY("minimum-year", INT_MIN, 0, 1, 0, 0, 0, E2BIG),
    BOUNDARY("maximum-year", INT_MAX, 0, 1, 0, 0, 0, ERANGE),
    BOUNDARY("year-overflow-positive", INT_MAX, 12, 1, 0, 0, 0, E2BIG),
    BOUNDARY("year-overflow-negative", INT_MIN, -12, 1, 0, 0, 0, ERANGE),
    BOUNDARY("combined-positive", INT_MAX, INT_MAX, INT_MAX,
        INT_MAX, INT_MAX, INT_MAX, E2BIG),
    BOUNDARY("combined-negative", INT_MIN, INT_MIN, INT_MIN + 1,
        INT_MIN, INT_MIN, INT_MIN, ERANGE),
};

struct boundary_result {
    long long seconds;
    int error;
    int fields[9];
    long offset;
    int utc_zone;
    int unchanged;
};
_Static_assert(sizeof(struct boundary_result) == 64, "fixed result record size");

static struct boundary_result run_boundary(const struct boundary_case *test)
{
    struct tm value = test->input;
    struct boundary_result result;

    errno = test->incoming_errno;
    result.seconds = (long long)timegm(&value);
    result.error = errno;
    result.fields[0] = value.tm_sec;
    result.fields[1] = value.tm_min;
    result.fields[2] = value.tm_hour;
    result.fields[3] = value.tm_mday;
    result.fields[4] = value.tm_mon;
    result.fields[5] = value.tm_year;
    result.fields[6] = value.tm_wday;
    result.fields[7] = value.tm_yday;
    result.fields[8] = value.tm_isdst;
    result.offset = value.tm_gmtoff;
    result.utc_zone = has_utc_zone(&value);
    result.unchanged = same_tm(&value, &test->input);
    return result;
}

#ifdef CRABC_TIMEGM_ORACLE_EMIT
static int emit_oracle(void)
{
    size_t index;

    puts("static const struct boundary_result oracle_results[] = {");
    for (index = 0; index < sizeof(boundaries) / sizeof(boundaries[0]); index++) {
        const struct boundary_result value = run_boundary(&boundaries[index]);
        printf("    { %lldLL, %d, { %d, %d, %d, %d, %d, %d, %d, %d, %d }, %ldL, %d, %d },\n",
            value.seconds, value.error, value.fields[0], value.fields[1],
            value.fields[2], value.fields[3], value.fields[4], value.fields[5],
            value.fields[6], value.fields[7], value.fields[8], value.offset,
            value.utc_zone, value.unchanged);
    }
    puts("};");
    return ferror(stdout) != 0;
}
#elif defined(CRABC_TIMEGM_EXPECTED)
#include "timegm_oracle_results.h"
_Static_assert(sizeof(oracle_results) / sizeof(oracle_results[0]) ==
    sizeof(boundaries) / sizeof(boundaries[0]), "oracle case count");
#ifdef CRABC_TIMEGM_RECORD
static struct boundary_result observed_results[
    sizeof(boundaries) / sizeof(boundaries[0])];

/* Fixture output records contain only scalar results, never process pointers.
 * The freestanding fixture writes them after all timegm calls have completed.
 */
static int emit_records(void)
{
#ifdef CRABC_TIMEGM_FREESTANDING
    long written;

    __asm__ __volatile__("syscall" : "=a"(written) : "a"(1L), "D"(1L),
        "S"(observed_results), "d"(sizeof(observed_results)) :
        "rcx", "r11", "memory");
    return written != (long)sizeof(observed_results);
#else
    return fwrite(observed_results, sizeof(observed_results), 1, stdout) != 1;
#endif
}
#endif

static int check_boundaries(void)
{
    size_t index;
    size_t field;

    for (index = 0; index < sizeof(boundaries) / sizeof(boundaries[0]); index++) {
        const struct boundary_result actual = run_boundary(&boundaries[index]);
        const struct boundary_result *expected = &oracle_results[index];
#ifdef CRABC_TIMEGM_RECORD
        observed_results[index] = actual;
#endif

        if (actual.seconds != expected->seconds || actual.error != expected->error ||
            actual.offset != expected->offset ||
            actual.utc_zone != expected->utc_zone ||
            actual.unchanged != expected->unchanged)
            return (int)index + 1;
        for (field = 0; field < 9; field++) {
            if (actual.fields[field] != expected->fields[field])
                return (int)index + 1;
        }
    }
#ifdef CRABC_TIMEGM_RECORD
    return emit_records();
#else
    return 0;
#endif
}
#endif

int crabc_x86_64_timegm_probe(void)
{
    int status = epoch();

    if (status != 0)
        return 10 + status;
    status = negative_month();
    if (status != 0)
        return 20 + status;
    status = leap_carry();
    if (status != 0)
        return 30 + status;
    status = valid_minus_one();
    if (status != 0)
        return 40 + status;
    status = overflow();
    if (status != 0)
        return 50 + status;
#ifdef CRABC_TIMEGM_EXPECTED
    status = check_boundaries();
    if (status != 0)
        return 60 + status;
#endif
    return 0;
}

#ifndef CRABC_TIMEGM_FREESTANDING
int main(void)
{
#ifdef CRABC_TIMEGM_ORACLE_EMIT
    if (crabc_x86_64_timegm_probe() != 0)
        return 1;
    return emit_oracle();
#else
    return crabc_x86_64_timegm_probe();
#endif
}
#endif

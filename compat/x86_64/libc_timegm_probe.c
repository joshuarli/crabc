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
    return status == 0 ? 0 : 50 + status;
}

#ifndef CRABC_TIMEGM_FREESTANDING
int main(void)
{
    return crabc_x86_64_timegm_probe();
}
#endif

/*
 * One installed-header numeric and clock/calendar composition object.
 *
 * It uses exact representable floating values, source-visible end pointers
 * and errno boundaries. Calendar state comes from explicit POSIX TZ strings
 * and one supplied TZif file, never a host zoneinfo file or wall-clock transcript.
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

_Static_assert(sizeof(long) == 8, "x86-64 time_t and stream scalars");
_Static_assert(sizeof(long double) == 16, "x86-64 x87 long double storage");
_Static_assert(sizeof(wchar_t) == 4, "x86-64 wide conversion units");

static int equal_text(const char *actual, const char *expected)
{
    while (*actual != '\0' || *expected != '\0') {
        if (*actual != *expected)
            return 0;
        ++actual;
        ++expected;
    }
    return 1;
}

static int valid_timespec(const struct timespec *value)
{
    return value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static int not_before(const struct timespec *before, const struct timespec *after)
{
    return after->tv_sec > before->tv_sec ||
        (after->tv_sec == before->tv_sec && after->tv_nsec >= before->tv_nsec);
}

static int same_civil(const struct tm *left, const struct tm *right)
{
    return left->tm_sec == right->tm_sec && left->tm_min == right->tm_min &&
        left->tm_hour == right->tm_hour && left->tm_mday == right->tm_mday &&
        left->tm_mon == right->tm_mon && left->tm_year == right->tm_year &&
        left->tm_isdst == right->tm_isdst;
}

static int numeric_locale(void)
{
    char *end;
    wchar_t *wide_end;
    double signed_zero;
    locale_t c_locale;
    locale_t utf8_locale;
    locale_t previous;

    if (setlocale(LC_ALL, "C.UTF-8") == NULL)
        return 1;
    errno = EDOM;
    if (strtof("0x1.8p+1tail", &end) != 3.0f || *end != 't' || errno != EDOM)
        return 2;
    errno = EAGAIN;
    if (strtod(" 6.25z", &end) != 6.25 || *end != 'z' || errno != EAGAIN)
        return 3;
    errno = EINTR;
    if (strtold("-0x1.8p+2q", &end) != -6.0L || *end != 'q' || errno != EINTR)
        return 4;
    errno = 0;
    if (strtod("1e9999", &end) <= DBL_MAX || *end != '\0' || errno != ERANGE)
        return 5;

    c_locale = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    utf8_locale = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    if (c_locale == (locale_t)0 || utf8_locale == (locale_t)0)
        return 6;
    previous = uselocale(utf8_locale);
    if (previous == (locale_t)0)
        return 7;
    errno = EILSEQ;
    if (strtod_l("7.5!", &end, c_locale) != 7.5 || *end != '!' || errno != EILSEQ ||
        uselocale((locale_t)0) != utf8_locale)
        return 8;
    if (uselocale(previous) != utf8_locale)
        return 9;
    freelocale(c_locale);
    freelocale(utf8_locale);

    errno = EDOM;
    if (wcstof(L" 0x1.cp+1x", &wide_end) != 3.5f || *wide_end != L'x' || errno != EDOM)
        return 10;
    errno = EAGAIN;
    if (wcstod(L"6.25y", &wide_end) != 6.25 || *wide_end != L'y' || errno != EAGAIN)
        return 11;
    errno = EINTR;
    if (wcstold(L"-0x1.8p+2z", &wide_end) != -6.0L || *wide_end != L'z' || errno != EINTR)
        return 12;
    errno = EDOM;
    signed_zero = strtod("-0x0p0!", &end);
    if (signed_zero != 0.0 || !signbit(signed_zero) || *end != '!' || errno != EDOM)
        return 13;
    errno = 0;
    if (strtod("0x1p-1074?", &end) != 0x1p-1074 || *end != '?' || errno != 0)
        return 14;
    errno = 0;
    if (strtod("0x1p-1075?", &end) != 0.0 || *end != '?' || errno != ERANGE)
        return 15;
    return 0;
}

static int integer_boundaries(void)
{
    char *end;
    const char *partial = "  -0xz";
    const char *empty = "  +q";
    const char *invalid_base = "19";

    errno = EDOM;
    if (strtol("9223372036854775807!", &end, 10) != LONG_MAX ||
        *end != '!' || errno != EDOM)
        return 40;
    errno = 0;
    if (strtol("9223372036854775808!", &end, 10) != LONG_MAX ||
        *end != '!' || errno != ERANGE)
        return 41;
    errno = EDOM;
    if (strtoll("-9223372036854775808!", &end, 10) != LLONG_MIN ||
        *end != '!' || errno != EDOM)
        return 42;
    errno = 0;
    if (strtoll("-9223372036854775809!", &end, 10) != LLONG_MIN ||
        *end != '!' || errno != ERANGE)
        return 43;
    errno = EDOM;
    if (strtoumax("-1!", &end, 10) != UINTMAX_MAX || *end != '!' || errno != EDOM)
        return 44;
    errno = 0;
    if (strtoull("18446744073709551616!", &end, 10) != ULLONG_MAX ||
        *end != '!' || errno != ERANGE)
        return 45;
    errno = EDOM;
    if (strtol(partial, &end, 0) != 0 || end != partial + 4 || errno != EDOM)
        return 46;
    errno = EDOM;
    if (strtol(empty, &end, 10) != 0 || end != empty || errno != EINVAL)
        return 47;
    errno = EDOM;
    if (strtol(invalid_base, &end, 1) != 0 || end != invalid_base || errno != EINVAL)
        return 48;
    errno = EDOM;
    if (strtoimax("0X7fffffffffffffff!", &end, 0) != INTMAX_MAX ||
        *end != '!' || errno != EDOM)
        return 49;
    return 0;
}

static void *thread_numeric_state(void *argument)
{
    char *end;
    locale_t local = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    locale_t previous;
    int *other_errno = argument;

    if (local == (locale_t)0 || (previous = uselocale(local)) == (locale_t)0 ||
        other_errno == &errno)
        return (void *)1;
    errno = 0;
    if (strtol("9223372036854775808x", &end, 10) != LONG_MAX ||
        *end != 'x' || errno != ERANGE || uselocale((locale_t)0) != local)
        return (void *)2;
    char *input = malloc(128);
    if (input == NULL) {
        uselocale(previous);
        freelocale(local);
        return (void *)3;
    }
    memcpy(input, " 6.25!", sizeof " 6.25!");
    errno = EDOM;
    double value = strtod_l(input, &end, local);
    int converted = value == 6.25 && end == input + 5 && errno == EDOM &&
        uselocale((locale_t)0) == local;
    free(input);
    uselocale(previous);
    freelocale(local);
    return converted ? (void *)0 : (void *)4;
}

static int threaded_numeric_state(void)
{
    pthread_t thread;
    void *result;
    int *main_errno = &errno;

    errno = EDOM;
    if (pthread_create(&thread, NULL, thread_numeric_state, main_errno) != 0)
        return 50;
    if (pthread_join(thread, &result) != 0 || result != (void *)0 || errno != EDOM)
        return 51;
    /* The allocating worker has retired. Caller-owned errno and live locale
     * handles must still compose with narrow and wide floating conversion. */
    return numeric_locale();
}

static int clocks(void)
{
    struct timespec realtime_before;
    struct timespec realtime_after;
    struct timespec monotonic_before;
    struct timespec monotonic_after;
    time_t stored;
    time_t observed;

    errno = EDOM;
    if (clock_gettime(CLOCK_REALTIME, &realtime_before) != 0 || errno != EDOM ||
        !valid_timespec(&realtime_before))
        return 20;
    if (clock_gettime(CLOCK_MONOTONIC, &monotonic_before) != 0 ||
        !valid_timespec(&monotonic_before) ||
        clock_gettime(CLOCK_MONOTONIC, &monotonic_after) != 0 ||
        !valid_timespec(&monotonic_after) || !not_before(&monotonic_before, &monotonic_after))
        return 21;
    observed = time(&stored);
    if (observed == (time_t)-1 || observed != stored ||
        clock_gettime(CLOCK_REALTIME, &realtime_after) != 0 ||
        !valid_timespec(&realtime_after))
        return 22;
    errno = EDOM;
    if (clock_gettime((clockid_t)-1, &realtime_after) != -1 || errno != EINVAL)
        return 23;
    /* Realtime is externally adjustable.  These calls prove only normalized
     * records; they never establish an ordering or exact wall-clock transcript. */
    return 0;
}

static int calendar(void)
{
    static const char utc_text[] = "2020-03-01 00:00:00";
    static const char winter_text[] = "2021-01-15 12:00:00 -0500 EST";
    static const char summer_text[] = "2021-07-15 12:00:00 -0400 EDT";
    struct tm normalized = {
        .tm_year = 120, .tm_mon = 1, .tm_mday = 30, .tm_isdst = -1,
    };
    struct tm local;
    struct tm parsed = { .tm_isdst = -1 };
    struct tm winter = {
        .tm_year = 121, .tm_mon = 0, .tm_mday = 15, .tm_hour = 12, .tm_isdst = -1,
    };
    struct tm summer = {
        .tm_year = 121, .tm_mon = 6, .tm_mday = 15, .tm_hour = 12, .tm_isdst = -1,
    };
    char text[48];
    char *tail;
    time_t normalized_time;
    time_t winter_time;
    time_t summer_time;

    if (setlocale(LC_ALL, "C") == NULL || setenv("TZ", "UTC0", 1) != 0)
        return 30;
    tzset();
    normalized_time = mktime(&normalized);
    if (normalized_time == (time_t)-1 || normalized.tm_year != 120 || normalized.tm_mon != 2 ||
        normalized.tm_mday != 1 || normalized.tm_hour != 0 || normalized.tm_min != 0 ||
        normalized.tm_sec != 0 || normalized.tm_isdst != 0 ||
        localtime_r(&normalized_time, &local) != &local || !same_civil(&normalized, &local))
        return 31;
    if (strftime(text, sizeof(text), "%F %T", &local) != 19 || !equal_text(text, utc_text))
        return 32;
    tail = strptime(text, "%F %T", &parsed);
    if (tail == NULL || *tail != '\0' || mktime(&parsed) != normalized_time ||
        localtime_r(&normalized_time, &local) != &local || !same_civil(&parsed, &local))
        return 33;

    if (setenv("TZ", "EST5EDT,M3.2.0/2,M11.1.0/2", 1) != 0)
        return 34;
    tzset();
    winter_time = mktime(&winter);
    if (winter_time == (time_t)-1 || localtime_r(&winter_time, &local) != &local ||
        !same_civil(&winter, &local) || local.tm_isdst != 0 ||
        strftime(text, sizeof(text), "%F %T %z %Z", &local) != 29 ||
        !equal_text(text, winter_text))
        return 35;
    summer_time = mktime(&summer);
    if (summer_time == (time_t)-1 || localtime_r(&summer_time, &local) != &local ||
        !same_civil(&summer, &local) || local.tm_isdst != 1 ||
        strftime(text, sizeof(text), "%F %T %z %Z", &local) != 29 ||
        !equal_text(text, summer_text))
        return 36;
    {
        static const struct {
            time_t epoch;
            int hour;
            int daylight;
            long offset;
            const char *name;
        } edges[] = {
            { 1615705199, 1, 0, -18000, "EST" },
            { 1615705200, 3, 1, -14400, "EDT" },
            { 1636264799, 1, 1, -14400, "EDT" },
            { 1636264800, 1, 0, -18000, "EST" },
        };
        unsigned int i;
        for (i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
            time_t epoch = edges[i].epoch;
            struct tm inverse;
            errno = EDOM;
            if (localtime_r(&epoch, &local) != &local || errno != EDOM ||
                local.tm_hour != edges[i].hour || local.tm_isdst != edges[i].daylight ||
                local.tm_gmtoff != edges[i].offset ||
                !equal_text(local.tm_zone, edges[i].name))
                return 37;
            inverse = local;
            errno = EDOM;
            if (mktime(&inverse) != epoch || errno != EDOM || !same_civil(&inverse, &local))
                return 38;
        }
    }
    if (setenv("TZ", "UTC0", 1) != 0)
        return 39;
    tzset();
    errno = EDOM;
    if (localtime_r(&summer_time, &local) != &local || errno != EDOM ||
        local.tm_hour != 16 || local.tm_isdst != 0 || local.tm_gmtoff != 0 ||
        !equal_text(local.tm_zone, "UTC"))
        return 52;
    return 0;
}

static int calendar_tzif(const char *path)
{
    static const struct {
        time_t epoch;
        long offset;
        int daylight;
        const char *name;
    } edges[] = {
        { 99999, 0, 0, "STD" },
        { 100000, 1800, 1, "DST" },
        { 199999, 1800, 1, "DST" },
        { 200000, 0, 0, "STD" },
        { 1704067200, 0, 0, "STD" },
        { 1710054000, 1800, 1, "DST" },
    };
    char setting[4096];
    struct tm local;
    struct tm folded;
    time_t fold_epoch = 200500;
    unsigned int i;

    if (snprintf(setting, sizeof(setting), ":%s", path) <= 0 ||
        strlen(setting) >= sizeof(setting) - 1 || setenv("TZ", setting, 1) != 0)
        return 53;
    tzset();
    for (i = 0; i < sizeof(edges) / sizeof(edges[0]); ++i) {
        time_t epoch = edges[i].epoch;
        errno = EDOM;
        if (localtime_r(&epoch, &local) != &local || errno != EDOM ||
            local.tm_gmtoff != edges[i].offset || local.tm_isdst != edges[i].daylight ||
            !equal_text(local.tm_zone, edges[i].name))
            return 54;
    }
    if (gmtime_r(&fold_epoch, &folded) != &folded)
        return 55;
    folded.tm_isdst = 0;
    if (mktime(&folded) != 200500 || folded.tm_isdst != 0 || folded.tm_gmtoff != 0)
        return 56;
    folded.tm_isdst = 1;
    if (mktime(&folded) != 198700 || folded.tm_isdst != 1 || folded.tm_gmtoff != 1800)
        return 57;
    return 0;
}

int main(int argc, char **argv)
{
    int status;

    if (argc != 2)
        return 58;

    status = numeric_locale();
    if (status != 0)
        return status;
    status = integer_boundaries();
    if (status != 0)
        return status;
    status = threaded_numeric_state();
    if (status != 0)
        return status;
    status = clocks();
    if (status != 0)
        return status;
    status = calendar();
    if (status != 0)
        return status;
    status = calendar_tzif(argv[1]);
    if (status != 0)
        return status;
    puts("owned-numeric-calendar-products-ok");
    return 0;
}

/* Static crabc-libc x86-64 selected time-observation fixture.
 *
 * The same project-header C body is intended to execute first through pinned
 * musl 1.2.6 and then through a freestanding executable linked solely with
 * the selected crabc libc.a.  It specifies a deliberately bounded direct
 * clock-observation block: clock(3), time(3), timespec_get(3),
 * clock_getres(3), and gettimeofday(3). The separate scalar difftime
 * fixture owns the binary64 conversion. This artifact does not select
 * calendar or timezone state, clock mutation, POSIX timers, cancellation,
 * CRT, loader, sysroot, or public x86 support.
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
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(time_t) == 8 && sizeof(clock_t) == 8,
    "x86 time scalar widths");
_Static_assert(sizeof(struct timespec) == 16 &&
    _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec field offsets");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8,
    "x86 timeval layout");
_Static_assert(offsetof(struct timeval, tv_sec) == 0 &&
    offsetof(struct timeval, tv_usec) == 8,
    "x86 timeval field offsets");
_Static_assert(SYS_gettimeofday == 96 && SYS_clock_gettime == 228 &&
    SYS_clock_getres == 229,
    "x86 selected time syscall numbers");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1 &&
    CLOCK_PROCESS_CPUTIME_ID == 2 && TIME_UTC == 1,
    "selected clock constants");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock),
    clock_t (*)(void)), "clock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&time),
    time_t (*)(time_t *)), "time declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&timespec_get),
    int (*)(struct timespec *, int)), "timespec_get declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_getres),
    int (*)(clockid_t, struct timespec *)), "clock_getres declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&gettimeofday),
    int (*)(struct timeval *restrict, void *restrict)),
    "gettimeofday declaration");

static int normalized_timespec(const struct timespec *value)
{
    return value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static int normalized_timeval(const struct timeval *value)
{
    return value->tv_usec >= 0 && value->tv_usec < 1000000L;
}

static int not_before(const struct timespec *left, const struct timespec *right)
{
    return left->tv_sec > right->tv_sec ||
        (left->tv_sec == right->tv_sec && left->tv_nsec >= right->tv_nsec);
}

/* Use the same small Linux write boundary in both executable forms. */
static void write_bytes(int descriptor, const char *bytes, size_t length)
{
    while (length != 0) {
        long written;
        __asm__ volatile ("syscall" : "=a"(written)
            : "a"((long)SYS_write), "D"((long)descriptor),
              "S"(bytes), "d"(length) : "rcx", "r11", "memory");
        if (written <= 0)
            return;
        bytes += written;
        length -= (size_t)written;
    }
}

static void write_text(int descriptor, const char *text)
{
    const char *end = text;
    while (*end)
        ++end;
    write_bytes(descriptor, text, (size_t)(end - text));
}

static void write_number(int descriptor, long value)
{
    char digits[24];
    size_t length = 0;
    unsigned long magnitude;
    if (value < 0) {
        write_bytes(descriptor, "-", 1);
        magnitude = 0UL - (unsigned long)value;
    } else {
        magnitude = (unsigned long)value;
    }
    do {
        digits[length++] = (char)('0' + magnitude % 10);
        magnitude /= 10;
    } while (magnitude);
    for (size_t left = 0, right = length - 1; left < right; ++left, --right) {
        char digit = digits[left];
        digits[left] = digits[right];
        digits[right] = digit;
    }
    write_bytes(descriptor, digits, length);
}

/* stdout holds comparable categories; stderr retains the observed scalars. */
static void record(const char *name, long result, long observed_errno,
    long output, long temporal, long raw_first, long raw_second)
{
    for (int stream = 1; stream <= 2; ++stream) {
        write_text(stream, name);
        write_bytes(stream, " ", 1);
        write_number(stream, stream == 1 ? result : raw_first);
        write_bytes(stream, " ", 1);
        write_number(stream, observed_errno);
        write_bytes(stream, " ", 1);
        write_number(stream, output);
        write_bytes(stream, " ", 1);
        write_number(stream, stream == 1 ? temporal : raw_second);
        write_bytes(stream, "\n", 1);
    }
}

static int in_realtime_window(long seconds, const struct timespec *before,
    const struct timespec *after)
{
    return seconds >= before->tv_sec - 1 && seconds <= after->tv_sec + 1;
}

static int check_wall_clock_and_errno(void)
{
    struct timespec before;
    struct timespec after;
    struct timespec c11;
    struct timespec resolution;
    struct timeval wall;
    struct timeval zoned_wall;
    long timezone_words[2] = { 0x1234, 0x5678 };
    time_t stored;
    time_t returned;
    time_t null_returned;
    int time_errno;
    int null_time_errno;
    int wall_result;
    int wall_errno;
    int null_wall_result;
    int null_wall_errno;
    int zone_result;
    int zone_errno;
    int null_zone_result;
    int null_zone_errno;
    int c11_result;
    int c11_errno;
    int resolution_result;
    int resolution_errno;
    const int preserved_errno = ERANGE;

    errno = preserved_errno;
    if (clock_gettime(CLOCK_REALTIME, &before) != 0 ||
        !normalized_timespec(&before))
        return 1;
    stored = -17;
    returned = time(&stored);
    time_errno = errno;
    null_returned = time(NULL);
    null_time_errno = errno;
    wall.tv_sec = -17;
    wall.tv_usec = -17;
    wall_result = gettimeofday(&wall, NULL);
    wall_errno = errno;
    null_wall_result = gettimeofday(NULL, NULL);
    null_wall_errno = errno;
    zoned_wall.tv_sec = -17;
    zoned_wall.tv_usec = -17;
    zone_result = gettimeofday(&zoned_wall, timezone_words);
    zone_errno = errno;
    null_zone_result = gettimeofday(NULL, timezone_words);
    null_zone_errno = errno;
    c11.tv_sec = -17;
    c11.tv_nsec = -17;
    c11_result = timespec_get(&c11, TIME_UTC);
    c11_errno = errno;
    resolution.tv_sec = -17;
    resolution.tv_nsec = -17;
    resolution_result = clock_getres(CLOCK_MONOTONIC, &resolution);
    resolution_errno = errno;
    if (clock_gettime(CLOCK_REALTIME, &after) != 0 ||
        !normalized_timespec(&after) || !not_before(&after, &before))
        return 8;
    record("realtime.before", 0, preserved_errno, normalized_timespec(&before),
        1, before.tv_sec, before.tv_nsec);
    record("realtime.after", 0, preserved_errno, normalized_timespec(&after),
        not_before(&after, &before), after.tv_sec, after.tv_nsec);
    record("time.loc", returned > 0, time_errno, returned == stored,
        in_realtime_window(returned, &before, &after), returned, stored);
    record("time.null", null_returned > 0, null_time_errno, 1,
        in_realtime_window(null_returned, &before, &after), null_returned, 0);
    record("gettimeofday.value", wall_result, wall_errno,
        normalized_timeval(&wall), in_realtime_window(wall.tv_sec, &before, &after),
        wall.tv_sec, wall.tv_usec);
    record("gettimeofday.null", null_wall_result, null_wall_errno, 1, 1,
        null_wall_result, 0);
    record("gettimeofday.zone", zone_result, zone_errno,
        normalized_timeval(&zoned_wall) &&
        timezone_words[0] == 0x1234 && timezone_words[1] == 0x5678,
        in_realtime_window(zoned_wall.tv_sec, &before, &after),
        zoned_wall.tv_sec, zoned_wall.tv_usec);
    record("gettimeofday.null_zone", null_zone_result, null_zone_errno,
        timezone_words[0] == 0x1234 && timezone_words[1] == 0x5678, 1,
        timezone_words[0], timezone_words[1]);
    record("timespec_get.utc", c11_result, c11_errno,
        normalized_timespec(&c11), in_realtime_window(c11.tv_sec, &before, &after),
        c11.tv_sec, c11.tv_nsec);
    record("clock_getres.value", resolution_result, resolution_errno,
        normalized_timespec(&resolution) &&
        (resolution.tv_sec != 0 || resolution.tv_nsec != 0), 1,
        resolution.tv_sec, resolution.tv_nsec);
    if (returned <= 0 || returned != stored || time_errno != preserved_errno ||
        !in_realtime_window(returned, &before, &after))
        return 2;
    if (null_returned <= 0 || null_time_errno != preserved_errno ||
        !in_realtime_window(null_returned, &before, &after))
        return 3;
    if (wall_result != 0 || wall_errno != preserved_errno ||
        !normalized_timeval(&wall) ||
        !in_realtime_window(wall.tv_sec, &before, &after))
        return 4;
    if (null_wall_result != 0 || null_wall_errno != preserved_errno ||
        zone_result != 0 || zone_errno != preserved_errno ||
        !normalized_timeval(&zoned_wall) ||
        !in_realtime_window(zoned_wall.tv_sec, &before, &after) ||
        null_zone_result != 0 || null_zone_errno != preserved_errno ||
        timezone_words[0] != 0x1234 || timezone_words[1] != 0x5678)
        return 5;
    if (c11_result != TIME_UTC || c11_errno != preserved_errno ||
        !normalized_timespec(&c11) ||
        !in_realtime_window(c11.tv_sec, &before, &after))
        return 6;
    if (resolution_result != 0 || resolution_errno != preserved_errno ||
        !normalized_timespec(&resolution) ||
        (resolution.tv_sec == 0 && resolution.tv_nsec == 0))
        return 7;
    return 0;
}

static int check_cpu_clock(void)
{
    clock_t before;
    clock_t after;
    volatile unsigned long long checksum = 0;
    const int preserved_errno = E2BIG;

    errno = preserved_errno;
    before = clock();
    for (unsigned long long value = 0; value < 500000ULL; ++value)
        checksum += value << (value & 15);
    after = clock();
    record("clock.cpu", before >= 0, errno, after >= before, checksum != 0,
        before, after);
    if (before < 0 || after < before || checksum == 0 ||
        errno != preserved_errno)
        return 1;
    return 0;
}

static int check_error_conventions(void)
{
    struct timespec value;
    int result;
    int observed_errno;

    errno = 0;
    value.tv_sec = -17;
    value.tv_nsec = -17;
    result = clock_getres(-1, &value);
    observed_errno = errno;
    record("clock_getres.invalid", result, observed_errno,
        value.tv_sec == -17 && value.tv_nsec == -17, 1,
        value.tv_sec, value.tv_nsec);
    if (result != -1 || observed_errno != EINVAL ||
        value.tv_sec != -17 || value.tv_nsec != -17)
        return 1;
    errno = ERANGE;
    result = clock_getres(CLOCK_MONOTONIC, NULL);
    observed_errno = errno;
    record("clock_getres.null", result, observed_errno, 1, 1, result, 0);
    if (result != 0 || observed_errno != ERANGE)
        return 2;
    value.tv_sec = -17;
    value.tv_nsec = -17;
    result = timespec_get(&value, 0);
    observed_errno = errno;
    record("timespec_get.invalid", result, observed_errno,
        value.tv_sec == -17 && value.tv_nsec == -17, 1,
        value.tv_sec, value.tv_nsec);
    if (result != 0 || observed_errno != ERANGE ||
        value.tv_sec != -17 || value.tv_nsec != -17)
        return 3;
    result = timespec_get(NULL, 0);
    observed_errno = errno;
    record("timespec_get.null_invalid", result, observed_errno, 1, 1,
        result, 0);
    if (result != 0 || observed_errno != ERANGE)
        return 4;
    return 0;
}

int crabc_x86_64_time_observation_probe(void)
{
    int status = check_wall_clock_and_errno();

    if (status != 0)
        return 10 + status;
    status = check_cpu_clock();
    if (status != 0)
        return 30 + status;
    status = check_error_conventions();
    return status == 0 ? 0 : 50 + status;
}

#ifndef CRABC_TIME_OBSERVATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_time_observation_probe();
}
#endif

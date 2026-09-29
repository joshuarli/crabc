/* Native x86-64 static clock observation differential.
 * The same project-header body runs with pinned musl and selected crabc libc.
 * Live values are checked by bounds and order; the output names each clock.
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
#include <time.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec layout");
_Static_assert(offsetof(struct timespec, tv_sec) == 0 &&
    offsetof(struct timespec, tv_nsec) == 8, "x86 timespec field offsets");
_Static_assert(SYS_clock_gettime == 228 && SYS_clock_getres == 229,
    "x86 clock query syscall numbers");
_Static_assert(CLOCK_REALTIME == 0 && CLOCK_MONOTONIC == 1 &&
    CLOCK_PROCESS_CPUTIME_ID == 2 && CLOCK_THREAD_CPUTIME_ID == 3 &&
    CLOCK_MONOTONIC_RAW == 4 && CLOCK_REALTIME_COARSE == 5 &&
    CLOCK_MONOTONIC_COARSE == 6 && CLOCK_BOOTTIME == 7 &&
    CLOCK_REALTIME_ALARM == 8 && CLOCK_BOOTTIME_ALARM == 9 &&
    CLOCK_TAI == 11, "Linux clock selector values");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_gettime),
    int (*)(clockid_t, struct timespec *)), "clock_gettime declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&clock_getres),
    int (*)(clockid_t, struct timespec *)), "clock_getres declaration");

static int normalized(const struct timespec *value)
{
    return value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static int not_before(const struct timespec *later,
    const struct timespec *earlier)
{
    return later->tv_sec > earlier->tv_sec ||
        (later->tv_sec == earlier->tv_sec &&
         later->tv_nsec >= earlier->tv_nsec);
}

static int monotonic_clock(clockid_t clock_id)
{
    return clock_id == CLOCK_MONOTONIC ||
        clock_id == CLOCK_PROCESS_CPUTIME_ID ||
        clock_id == CLOCK_THREAD_CPUTIME_ID ||
        clock_id == CLOCK_MONOTONIC_RAW ||
        clock_id == CLOCK_MONOTONIC_COARSE ||
        clock_id == CLOCK_BOOTTIME ||
        clock_id == CLOCK_BOOTTIME_ALARM;
}

static long raw_clock_query(long number, clockid_t clock_id,
    struct timespec *output)
{
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "0"(number), "D"((long)clock_id), "S"(output)
        : "rcx", "r11", "memory");
    return result;
}

/* A raw write keeps this fixture independent of the candidate's I/O ABI. */
static int emit_clock(clockid_t clock_id)
{
    char line[2] = { "0123456789AB"[clock_id], '\n' };
    long result;
    __asm__ volatile("syscall" : "=a"(result)
        : "0"(1L), "D"(1L), "S"(line), "d"(2L)
        : "rcx", "r11", "memory");
    return result == 2;
}

static int check_clock(clockid_t clock_id)
{
    struct timespec before = { -1, -1 };
    struct timespec after = { -1, -1 };
    struct timespec resolution = { -1, -1 };
    struct timespec raw_resolution = { -1, -1 };
    struct timespec raw_time = { -1, -1 };
    const int preserved_errno = ERANGE;

    errno = preserved_errno;
    if (clock_gettime(clock_id, &before) != 0 ||
        !normalized(&before) ||
        (monotonic_clock(clock_id) && before.tv_sec < 0) ||
        errno != preserved_errno)
        return 1;
    if (clock_getres(clock_id, &resolution) != 0 ||
        !normalized(&resolution) || resolution.tv_sec < 0 ||
        (resolution.tv_sec == 0 && resolution.tv_nsec == 0) ||
        errno != preserved_errno)
        return 2;
    if (raw_clock_query(SYS_clock_getres, clock_id, &raw_resolution) != 0 ||
        raw_resolution.tv_sec != resolution.tv_sec ||
        raw_resolution.tv_nsec != resolution.tv_nsec)
        return 3;
    /* Linux permits a null resolution destination; the clock stays usable. */
    if (clock_getres(clock_id, NULL) != 0 || errno != preserved_errno)
        return 4;
    if (raw_clock_query(SYS_clock_gettime, clock_id, &raw_time) != 0 ||
        !normalized(&raw_time) ||
        (monotonic_clock(clock_id) && raw_time.tv_sec < 0))
        return 5;
    if (clock_gettime(clock_id, &after) != 0 ||
        !normalized(&after) ||
        (monotonic_clock(clock_id) && after.tv_sec < 0) ||
        errno != preserved_errno)
        return 6;
    /* CPU and monotonic clocks cannot step backward between these reads. */
    if (monotonic_clock(clock_id)) {
        if (!not_before(&raw_time, &before) ||
            !not_before(&after, &raw_time))
            return 7;
    }
    return emit_clock(clock_id) ? 0 : 8;
}

static int check_rejected_clock(clockid_t clock_id)
{
    struct timespec time_value = { 0x12345678L, 0x76543210L };
    struct timespec resolution = { 0x12345678L, 0x76543210L };

    errno = 0;
    if (clock_gettime(clock_id, &time_value) != -1 || errno != EINVAL ||
        time_value.tv_sec != 0x12345678L ||
        time_value.tv_nsec != 0x76543210L)
        return 1;
    errno = 0;
    if (clock_getres(clock_id, &resolution) != -1 || errno != EINVAL ||
        resolution.tv_sec != 0x12345678L ||
        resolution.tv_nsec != 0x76543210L)
        return 2;
    errno = 0;
    if (clock_getres(clock_id, NULL) != -1 || errno != EINVAL)
        return 3;
    return 0;
}

int crabc_x86_64_clock_gettime_probe(void)
{
    static const clockid_t clocks[] = {
        CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID,
        CLOCK_THREAD_CPUTIME_ID, CLOCK_MONOTONIC_RAW,
        CLOCK_REALTIME_COARSE, CLOCK_MONOTONIC_COARSE, CLOCK_BOOTTIME,
        CLOCK_REALTIME_ALARM, CLOCK_BOOTTIME_ALARM, CLOCK_TAI,
    };
    for (size_t index = 0; index < sizeof(clocks) / sizeof(clocks[0]); ++index) {
        int status = check_clock(clocks[index]);
        if (status != 0)
            return 10 + (int)index * 8 + status;
    }
    {
        int status = check_rejected_clock(-1);
        if (status != 0)
            return 110 + status;
    }
    return 0;
}

#ifndef CRABC_CLOCK_GETTIME_FREESTANDING
int main(void)
{
    return crabc_x86_64_clock_gettime_probe();
}
#endif

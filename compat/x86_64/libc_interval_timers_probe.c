/*
 * Pinned-musl Linux/x86-64 interval-timer C ABI differential body.
 *
 * The same project-header body runs through pinned musl and the selected
 * true-static archive.  It selects only getitimer/setitimer: exact LP64
 * records, all three Linux interval-timer selectors, complete old-setting
 * exchange, canonical output, stale-errno success, and invalid-input
 * preservation.  Raw syscalls are fixture plumbing for setup and comparison;
 * they are not additional C ABI providers.
 */

#define _POSIX_C_SOURCE 200809L

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <sys/time.h>

struct guarded_itimerval {
    struct itimerval value;
    unsigned char trailing[16];
};

typedef int (*getitimer_signature)(int, struct itimerval *);
typedef int (*setitimer_signature)(int, const struct itimerval *,
    struct itimerval *);

_Static_assert(sizeof(long) == 8 && sizeof(int) == 4,
    "x86 LP64 scalar widths");
_Static_assert(sizeof(struct timeval) == 16 && _Alignof(struct timeval) == 8,
    "x86 timeval layout");
_Static_assert(offsetof(struct timeval, tv_sec) == 0 &&
    offsetof(struct timeval, tv_usec) == 8, "x86 timeval offsets");
_Static_assert(sizeof(struct itimerval) == 32 &&
    _Alignof(struct itimerval) == 8, "x86 itimerval layout");
_Static_assert(offsetof(struct itimerval, it_interval) == 0 &&
    offsetof(struct itimerval, it_value) == 16, "x86 itimerval offsets");
_Static_assert(offsetof(struct guarded_itimerval, trailing) == 32,
    "tail sentinels begin after the kernel record");
_Static_assert(SYS_write == 1 && SYS_getitimer == 36 && SYS_setitimer == 38,
    "x86 interval-timer syscall numbers");
_Static_assert(ITIMER_REAL == 0 && ITIMER_VIRTUAL == 1 && ITIMER_PROF == 2,
    "x86 interval-timer selectors");
_Static_assert(__builtin_types_compatible_p(__typeof__(&getitimer),
    getitimer_signature), "getitimer declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setitimer),
    setitimer_signature), "setitimer declaration");

static const struct itimerval first_setting = {
    { 11, 0 },
    { 120, 0 },
};

static const struct itimerval second_setting = {
    { 13, 0 },
    { 240, 0 },
};

static const struct itimerval disarmed_setting = {
    { 0, 0 },
    { 0, 0 },
};

static const struct itimerval invalid_setting = {
    { 0, 0 },
    { 0, 1000000 },
};

static const struct itimerval one_shot_setting = {
    { 0, 0 },
    { 180, 0 },
};

static long raw_syscall2(long number, long argument_one, long argument_two)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_getitimer(int which, struct itimerval *value)
{
    return (int)raw_syscall2(SYS_getitimer, which, (long)(void *)value);
}

static int raw_setitimer(int which, const struct itimerval *new_value,
    struct itimerval *old_value)
{
    return (int)raw_syscall3(SYS_setitimer, which, (long)(void *)new_value,
        (long)(void *)old_value);
}

static int report_stage(const char *message, unsigned long length)
{
    return raw_syscall3(SYS_write, 1, (long)(const void *)message,
        (long)length) == (long)length ? 0 : 1;
}

static void fill_bytes(void *address, unsigned char value, unsigned long count)
{
    unsigned char *bytes = address;

    for (unsigned long index = 0; index < count; ++index)
        bytes[index] = value;
}

static int bytes_are(const unsigned char *bytes, unsigned long count,
    unsigned char value)
{
    for (unsigned long index = 0; index < count; ++index) {
        if (bytes[index] != value)
            return 0;
    }
    return 1;
}

static int canonical_timeval(const struct timeval *value)
{
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
        value->tv_usec < 1000000;
}

static int trailing_is_unchanged(const struct guarded_itimerval *value)
{
    return bytes_are(value->trailing, sizeof(value->trailing), 0xa5);
}

static int record_is_unchanged(const struct guarded_itimerval *value)
{
    return bytes_are((const unsigned char *)value, sizeof(*value), 0xa5);
}

static int timeval_is_zero(const struct timeval *value)
{
    return value->tv_sec == 0 && value->tv_usec == 0;
}

static int old_matches_setting(const struct itimerval *old,
    const struct itimerval *setting)
{
    return old->it_interval.tv_sec == setting->it_interval.tv_sec &&
        old->it_interval.tv_usec == setting->it_interval.tv_usec &&
        canonical_timeval(&old->it_value) &&
        (old->it_value.tv_sec != 0 || old->it_value.tv_usec != 0) &&
        old->it_value.tv_sec <= setting->it_value.tv_sec;
}

static int check_getitimer_queries(void)
{
    static const int selectors[] = { ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF };

    for (unsigned long index = 0; index < sizeof(selectors) / sizeof(selectors[0]);
         ++index) {
        struct guarded_itimerval value;

        if (raw_setitimer(selectors[index], &disarmed_setting, 0) != 0)
            return 1;
        fill_bytes(&value, 0xa5, sizeof(value));
        errno = ERANGE;
        if (getitimer(selectors[index], &value.value) != 0 ||
            errno != ERANGE || !timeval_is_zero(&value.value.it_interval) ||
            !timeval_is_zero(&value.value.it_value) ||
            !trailing_is_unchanged(&value))
            return 2 + (int)index;
    }
    return 0;
}

static int check_setitimer_exchange(void)
{
    static const int selectors[] = { ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF };

    for (unsigned long index = 0; index < sizeof(selectors) / sizeof(selectors[0]);
         ++index) {
        struct guarded_itimerval old;

        if (raw_setitimer(selectors[index], &disarmed_setting, 0) != 0)
            return 1;
        fill_bytes(&old, 0xa5, sizeof(old));
        errno = ERANGE;
        if (setitimer(selectors[index], &first_setting, &old.value) != 0 ||
            errno != ERANGE || !timeval_is_zero(&old.value.it_interval) ||
            !timeval_is_zero(&old.value.it_value) ||
            !trailing_is_unchanged(&old))
            return 10 + (int)index;

        fill_bytes(&old, 0xa5, sizeof(old));
        errno = ERANGE;
        if (setitimer(selectors[index], &second_setting, &old.value) != 0 ||
            errno != ERANGE || !old_matches_setting(&old.value, &first_setting) ||
            !trailing_is_unchanged(&old))
            return 20 + (int)index;

        fill_bytes(&old, 0xa5, sizeof(old));
        errno = ERANGE;
        if (setitimer(selectors[index], &disarmed_setting, &old.value) != 0 ||
            errno != ERANGE || !old_matches_setting(&old.value, &second_setting) ||
            !trailing_is_unchanged(&old))
            return 30 + (int)index;

        fill_bytes(&old, 0xa5, sizeof(old));
        errno = ERANGE;
        if (setitimer(selectors[index], &one_shot_setting, &old.value) != 0 ||
            errno != ERANGE || !timeval_is_zero(&old.value.it_interval) ||
            !timeval_is_zero(&old.value.it_value) ||
            !trailing_is_unchanged(&old))
            return 40 + (int)index;

        fill_bytes(&old, 0xa5, sizeof(old));
        if (getitimer(selectors[index], &old.value) != 0 ||
            !timeval_is_zero(&old.value.it_interval) ||
            !old_matches_setting(&old.value, &one_shot_setting) ||
            !trailing_is_unchanged(&old))
            return 50 + (int)index;

        if (setitimer(selectors[index], &disarmed_setting, 0) != 0)
            return 60 + (int)index;
    }
    return 0;
}

static int check_invalid_inputs(void)
{
    struct guarded_itimerval old;
    struct guarded_itimerval value;
    struct itimerval invalid;
    static const struct timeval invalid_fields[] = {
        { -1, 0 }, { 0, -1 }, { 0, 1000000 },
    };

    if (raw_setitimer(ITIMER_REAL, &first_setting, 0) != 0)
        return 1;
    fill_bytes(&old, 0xa5, sizeof(old));
    errno = 0;
    if (setitimer(ITIMER_REAL, &invalid_setting, &old.value) != -1 ||
        errno != EINVAL || !record_is_unchanged(&old))
        return 2;

    for (unsigned long field = 0; field < 2; ++field) {
        for (unsigned long index = 0;
             index < sizeof(invalid_fields) / sizeof(invalid_fields[0]);
             ++index) {
            invalid = first_setting;
            if (field == 0)
                invalid.it_interval = invalid_fields[index];
            else
                invalid.it_value = invalid_fields[index];
            fill_bytes(&old, 0xa5, sizeof(old));
            errno = 0;
            if (setitimer(ITIMER_REAL, &invalid, &old.value) != -1 ||
                errno != EINVAL || !record_is_unchanged(&old))
                return 10 + (int)(field * 3 + index);
            fill_bytes(&value, 0xa5, sizeof(value));
            if (raw_getitimer(ITIMER_REAL, &value.value) != 0 ||
                !old_matches_setting(&value.value, &first_setting) ||
                !trailing_is_unchanged(&value))
                return 20 + (int)(field * 3 + index);
        }
    }

    fill_bytes(&value, 0xa5, sizeof(value));
    errno = 0;
    if (getitimer(3, &value.value) != -1 || errno != EINVAL ||
        !record_is_unchanged(&value))
        return 3;

    fill_bytes(&old, 0xa5, sizeof(old));
    errno = 0;
    if (setitimer(3, &disarmed_setting, &old.value) != -1 ||
        errno != EINVAL || !record_is_unchanged(&old))
        return 4;

    fill_bytes(&value, 0xa5, sizeof(value));
    errno = 0;
    if (getitimer(-1, &value.value) != -1 || errno != EINVAL ||
        !record_is_unchanged(&value))
        return 30;

    errno = 0;
    if (getitimer(3, (struct itimerval *)1) != -1 || errno != EINVAL)
        return 31;
    errno = 0;
    if (setitimer(3, (const struct itimerval *)1, &old.value) != -1 ||
        errno != EFAULT || !record_is_unchanged(&old))
        return 32;

    fill_bytes(&value, 0xa5, sizeof(value));
    if (raw_getitimer(ITIMER_REAL, &value.value) != 0 ||
        !old_matches_setting(&value.value, &first_setting) ||
        !trailing_is_unchanged(&value))
        return 33;

    errno = 0;
    if (setitimer(ITIMER_REAL, &second_setting,
            (struct itimerval *)1) != -1 || errno != EFAULT)
        return 34;
    fill_bytes(&value, 0xa5, sizeof(value));
    if (raw_getitimer(ITIMER_REAL, &value.value) != 0 ||
        !old_matches_setting(&value.value, &second_setting) ||
        !trailing_is_unchanged(&value))
        return 35;

    errno = 0;
    if (getitimer(ITIMER_REAL, 0) != -1 || errno != EFAULT)
        return 5;
    if (setitimer(ITIMER_REAL, &disarmed_setting, 0) != 0)
        return 6;
    return 0;
}

int crabc_x86_64_interval_timers_probe(void)
{
    int status = check_getitimer_queries();

    if (status != 0)
        return 10 + status;
    if (report_stage("getitimer-disarmed=ok\n",
            sizeof("getitimer-disarmed=ok\n") - 1) != 0)
        return 90;
    status = check_setitimer_exchange();
    if (status != 0)
        return 20 + status;
    if (report_stage("setitimer-snapshot-disarm-rearm=ok\n",
            sizeof("setitimer-snapshot-disarm-rearm=ok\n") - 1) != 0)
        return 91;
    status = check_invalid_inputs();
    if (status != 0)
        return 100 + status;
    if (report_stage("invalid-fields-precedence-commit=ok\n",
            sizeof("invalid-fields-precedence-commit=ok\n") - 1) != 0)
        return 92;
    return 0;
}

#ifndef CRABC_INTERVAL_TIMERS_FREESTANDING
int main(void)
{
    return crabc_x86_64_interval_timers_probe();
}
#endif

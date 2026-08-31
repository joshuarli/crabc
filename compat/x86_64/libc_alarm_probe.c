/*
 * Pinned-musl Linux/x86-64 alarm differential and static-candidate body.
 *
 * The same one-symbol project-header body first runs through pinned musl
 * 1.2.6 and then through the selected `-nostdlib -static` candidate. It
 * verifies the historical ITIMER_REAL replacement only: a fractional prior
 * value rounds upward, the replacement is a one-shot whole-second record,
 * a later alarm(0) returns the prior remainder, and the second disarm returns
 * zero. Fixture-local raw setitimer calls seed and inspect timer state; they
 * do not select the public setitimer API, handler, mask, or delivery policy.
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
#include <unistd.h>

struct guarded_itimerval {
    struct itimerval value;
    unsigned char trailing[16];
};

_Static_assert(sizeof(long) == 8 && sizeof(unsigned int) == 4,
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
_Static_assert(SYS_setitimer == 38, "x86 setitimer syscall number");
_Static_assert(ITIMER_REAL == 0, "x86 real interval-timer selector");
_Static_assert(__builtin_types_compatible_p(__typeof__(&alarm),
    unsigned int (*)(unsigned int)), "alarm declaration");

static const struct itimerval fractional_seed = {
    { 0, 0 },
    { 604800, 999999 },
};

static const struct itimerval disarmed = {
    { 0, 0 },
    { 0, 0 },
};

static long raw_setitimer_real(const struct itimerval *new_value,
    struct itimerval *old_value)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"((long)SYS_setitimer), "D"((long)ITIMER_REAL),
          "S"(new_value), "d"(old_value)
        : "rcx", "r11", "memory");
    return result;
}

static void fill_bytes(void *address, unsigned char value, size_t count)
{
    unsigned char *bytes = address;

    for (size_t index = 0; index < count; ++index)
        bytes[index] = value;
}

static int bytes_equal(const unsigned char *bytes, size_t count,
    unsigned char value)
{
    for (size_t index = 0; index < count; ++index) {
        if (bytes[index] != value)
            return 0;
    }
    return 1;
}

static int timeval_is_zero(const struct timeval *value)
{
    return value->tv_sec == 0 && value->tv_usec == 0;
}

static int remaining_seconds(const struct timeval *value, long maximum)
{
    return value->tv_sec >= 0 && value->tv_usec >= 0 &&
        value->tv_usec < 1000000 &&
        (value->tv_sec != 0 || value->tv_usec != 0) &&
        value->tv_sec <= maximum;
}

static int check_fractional_rounding_and_one_shot(void)
{
    struct guarded_itimerval old;

    if (raw_setitimer_real(&fractional_seed, NULL) != 0)
        return 1;
    errno = ERANGE;
    if (alarm(120U) != 604801U || errno != ERANGE)
        return 2;

    fill_bytes(&old, 0xa5, sizeof(old));
    errno = ERANGE;
    if (raw_setitimer_real(&disarmed, &old.value) != 0 || errno != ERANGE)
        return 3;
    if (!timeval_is_zero(&old.value.it_interval) ||
        !remaining_seconds(&old.value.it_value, 120) ||
        !bytes_equal(old.trailing, sizeof(old.trailing), 0xa5))
        return 4;
    return 0;
}

static int check_disarm_return(void)
{
    unsigned int prior;

    if (raw_setitimer_real(&fractional_seed, NULL) != 0)
        return 1;
    errno = ERANGE;
    if (alarm(120U) != 604801U || errno != ERANGE)
        return 2;
    errno = ERANGE;
    prior = alarm(0U);
    if (prior == 0 || prior > 120U || errno != ERANGE)
        return 3;
    errno = ERANGE;
    if (alarm(0U) != 0U || errno != ERANGE)
        return 4;
    return 0;
}

int crabc_x86_64_alarm_probe(void)
{
    int status = check_fractional_rounding_and_one_shot();

    if (status != 0)
        return 10 + status;
    status = check_disarm_return();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_ALARM_FREESTANDING
int main(void)
{
    return crabc_x86_64_alarm_probe();
}
#endif

/*
 * Pinned-musl Linux/x86-64 ualarm differential and static-candidate body.
 *
 * The same one-symbol project-header body first runs through pinned musl
 * 1.2.6 and then through the selected `-nostdlib -static` candidate. It
 * proves only the historical ITIMER_REAL microsecond adapter: a clean timer
 * acquires requested periodic fields, replacing a subsecond seed returns its
 * old remainder, and Linux rejects a one-million-microsecond field while
 * retaining the prior timer state. Fixture-local raw setitimer calls contain
 * setup and inspection; they do not select the public setitimer API, handler,
 * mask, wait, or delivery policy.
 */

#define _GNU_SOURCE 1

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
_Static_assert(__builtin_types_compatible_p(__typeof__(&ualarm),
    unsigned int (*)(unsigned int, unsigned int)), "ualarm declaration");

static const struct itimerval disarmed = {
    { 0, 0 },
    { 0, 0 },
};

static const struct itimerval return_seed = {
    { 0, 100000 },
    { 0, 800000 },
};

static const struct itimerval invalid_seed = {
    { 0, 200000 },
    { 0, 700000 },
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

static int interval_is(const struct timeval *value, long microseconds)
{
    return value->tv_sec == 0 && value->tv_usec == microseconds;
}

static int remaining_subsecond(const struct timeval *value, long maximum)
{
    return value->tv_sec == 0 && value->tv_usec > 0 &&
        value->tv_usec <= maximum;
}

static int disarm_and_expect(struct guarded_itimerval *old,
    long expected_interval, long maximum_remaining)
{
    fill_bytes(old, 0xa5, sizeof(*old));
    errno = ERANGE;
    if (raw_setitimer_real(&disarmed, &old->value) != 0 || errno != ERANGE)
        return 1;
    if (!interval_is(&old->value.it_interval, expected_interval) ||
        !remaining_subsecond(&old->value.it_value, maximum_remaining) ||
        !bytes_equal(old->trailing, sizeof(old->trailing), 0xa5))
        return 2;
    return 0;
}

static int check_clean_install_and_query(void)
{
    struct guarded_itimerval old;
    int status;

    if (raw_setitimer_real(&disarmed, 0) != 0)
        return 1;
    errno = ERANGE;
    if (ualarm(200000U, 300000U) != 0U || errno != ERANGE)
        return 2;
    status = disarm_and_expect(&old, 300000, 200000);
    return status == 0 ? 0 : 2 + status;
}

static int check_prior_remainder_return(void)
{
    struct guarded_itimerval old;
    unsigned int prior;
    int status;

    if (raw_setitimer_real(&return_seed, 0) != 0)
        return 1;
    errno = ERANGE;
    prior = ualarm(500000U, 0U);
    if (prior == 0U || prior > 800000U || errno != ERANGE)
        return 2;
    status = disarm_and_expect(&old, 0, 500000);
    return status == 0 ? 0 : 2 + status;
}

static int check_invalid_boundary_preserves_state(void)
{
    struct guarded_itimerval old;
    int status;

    if (raw_setitimer_real(&invalid_seed, 0) != 0)
        return 1;
    errno = 0;
    /* Musl leaves its old record indeterminate here; assert errno/state only. */
    (void)ualarm(1000000U, 0U);
    if (errno != EINVAL)
        return 2;
    status = disarm_and_expect(&old, 200000, 700000);
    return status == 0 ? 0 : 2 + status;
}

int crabc_x86_64_ualarm_probe(void)
{
    int status = check_clean_install_and_query();

    if (status != 0)
        return 10 + status;
    status = check_prior_remainder_return();
    if (status != 0)
        return 20 + status;
    status = check_invalid_boundary_preserves_state();
    return status == 0 ? 0 : 30 + status;
}

#ifndef CRABC_UALARM_FREESTANDING
int main(void)
{
    return crabc_x86_64_ualarm_probe();
}
#endif

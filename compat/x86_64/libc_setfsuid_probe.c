/*
 * Pinned-musl Linux/x86-64 setfsuid differential body.
 *
 * Linux's setfsuid raw result is the prior filesystem UID, not a conventional
 * zero-or-error status. The same body first compares a raw syscall with the
 * C spelling, then makes only a current-effective-UID request inside the
 * disposable reference/candidate process. It intentionally proves stale errno
 * on ordinary returns rather than inventing a detectable permission failure.
 */

#include <errno.h>
#include <stdint.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>
#include <sys/types.h>

_Static_assert(sizeof(uid_t) == 4 && _Alignof(uid_t) == 4,
    "x86 uid_t ABI");
_Static_assert((uid_t)-1 > (uid_t)0, "x86 uid_t is unsigned");
_Static_assert(SYS_setfsuid == 122,
    "Linux 5.10 x86 setfsuid syscall number");
_Static_assert(SYS_geteuid == 107, "Linux 5.10 x86 geteuid syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setfsuid),
    int (*)(uid_t)), "setfsuid declaration");

static long raw_setfsuid(uid_t user_id)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_setfsuid), "D"((unsigned long)user_id)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static long raw_geteuid(void)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_geteuid)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static int check_query(int failure)
{
    const uid_t before = (uid_t)raw_setfsuid((uid_t)-1);

    errno = ERANGE;
    if ((uid_t)setfsuid((uid_t)-1) != before)
        return failure;
    if (errno != ERANGE)
        return failure + 1;
    return (uid_t)raw_setfsuid((uid_t)-1) == before ? 0 : failure + 2;
}

static int check_current_effective_request(int failure)
{
    const uid_t before = (uid_t)raw_setfsuid((uid_t)-1);
    const uid_t effective = (uid_t)raw_geteuid();

    errno = E2BIG;
    if ((uid_t)setfsuid(effective) != before)
        return failure;
    if (errno != E2BIG)
        return failure + 1;
    if ((uid_t)raw_setfsuid((uid_t)-1) != effective)
        return failure + 2;

    errno = E2BIG;
    if ((uid_t)setfsuid(effective) != effective)
        return failure + 3;
    return errno == E2BIG ? 0 : failure + 4;
}

int crabc_x86_64_setfsuid_probe(void)
{
    int failure = check_query(10);

    if (failure)
        return failure;
    return check_current_effective_request(20);
}

#ifndef CRABC_SETFSUID_FREESTANDING
int main(void)
{
    return crabc_x86_64_setfsuid_probe();
}
#endif

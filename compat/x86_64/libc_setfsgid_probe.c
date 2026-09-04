/*
 * Pinned-musl Linux/x86-64 setfsgid differential body.
 *
 * Linux's setfsgid raw result is the prior filesystem GID, not a conventional
 * zero-or-error status. The same body first compares a raw syscall with the
 * C spelling, then makes only a current-effective-GID request inside the
 * disposable reference/candidate process. It intentionally proves stale errno
 * on ordinary returns rather than inventing a detectable permission failure.
 */

#include <errno.h>
#include <stdint.h>
#include <sys/fsuid.h>
#include <sys/syscall.h>

_Static_assert(sizeof(gid_t) == 4 && _Alignof(gid_t) == 4,
    "x86 gid_t ABI");
_Static_assert((gid_t)-1 > (gid_t)0, "x86 gid_t is unsigned");
_Static_assert(SYS_setfsgid == 123,
    "Linux 5.10 x86 setfsgid syscall number");
_Static_assert(SYS_getegid == 108, "Linux 5.10 x86 getegid syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&setfsgid),
    int (*)(gid_t)), "setfsgid declaration");

static long raw_setfsgid(gid_t group_id)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_setfsgid), "D"((unsigned long)group_id)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static long raw_getegid(void)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_getegid)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static int check_query(int failure)
{
    const gid_t before = (gid_t)raw_setfsgid((gid_t)-1);

    errno = ERANGE;
    if ((gid_t)setfsgid((gid_t)-1) != before)
        return failure;
    if (errno != ERANGE)
        return failure + 1;
    return (gid_t)raw_setfsgid((gid_t)-1) == before ? 0 : failure + 2;
}

static int check_current_effective_request(int failure)
{
    const gid_t before = (gid_t)raw_setfsgid((gid_t)-1);
    const gid_t effective = (gid_t)raw_getegid();

    errno = E2BIG;
    if ((gid_t)setfsgid(effective) != before)
        return failure;
    if (errno != E2BIG)
        return failure + 1;
    if ((gid_t)raw_setfsgid((gid_t)-1) != effective)
        return failure + 2;

    errno = E2BIG;
    if ((gid_t)setfsgid(effective) != effective)
        return failure + 3;
    return errno == E2BIG ? 0 : failure + 4;
}

int crabc_x86_64_setfsgid_probe(void)
{
    int failure = check_query(10);

    if (failure)
        return failure;
    return check_current_effective_request(20);
}

#ifndef CRABC_SETFSGID_FREESTANDING
int main(void)
{
    return crabc_x86_64_setfsgid_probe();
}
#endif

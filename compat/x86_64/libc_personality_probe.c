/*
 * Pinned-musl Linux/x86-64 personality differential body.
 *
 * Linux accepts the unsigned-long all-ones word as a non-mutating query and
 * returns the current execution personality rather than a zero status. This
 * body compares that raw query with the C spelling twice, proving ordinary
 * stale errno without requesting a changed execution personality.
 */

#include <errno.h>
#include <stdint.h>
#include <sys/personality.h>
#include <sys/syscall.h>

_Static_assert(sizeof(unsigned long) == 8 && _Alignof(unsigned long) == 8,
    "x86 unsigned long ABI");
_Static_assert(SYS_personality == 135,
    "Linux 5.10 x86 personality syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&personality),
    int (*)(unsigned long)), "personality declaration");

static long raw_personality(unsigned long persona)
{
    long result;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"((long)SYS_personality), "D"(persona)
        : "cc", "rcx", "r11", "memory");
    return result;
}

static int check_query(int failure)
{
    const unsigned long query = 0xffffffffUL;
    const long before = raw_personality(query);

    if (before < 0)
        return failure;
    errno = ERANGE;
    if (personality(query) != (int)before)
        return failure + 1;
    if (errno != ERANGE)
        return failure + 2;
    if (raw_personality(query) != before)
        return failure + 3;

    errno = E2BIG;
    if (personality(query) != (int)before)
        return failure + 4;
    return errno == E2BIG ? 0 : failure + 5;
}

int crabc_x86_64_personality_probe(void)
{
    return check_query(10);
}

#ifndef CRABC_PERSONALITY_FREESTANDING
int main(void)
{
    return crabc_x86_64_personality_probe();
}
#endif

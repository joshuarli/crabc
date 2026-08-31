/*
 * Pinned-musl Linux/x86-64 sigaddset/sigdelset/sigfillset differential body.
 *
 * These POSIX helpers touch only musl's first public sigset_t word on x86-64.
 * The shared body proves their success/error ordering, the 32--34 reserved
 * range, first-word mutation, untouched tail sentinels, and stale errno. The
 * freestanding candidate links only these helpers and initial-TLS errno; it
 * has no action, mask, delivery, wait, descriptor, or timer plumbing.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <signal.h>

enum {
    SIGSET_WORDS = 128 / sizeof(unsigned long),
};

_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 public sigset_t layout");
_Static_assert(SIGSET_WORDS == 16, "x86 public sigset_t word count");
_Static_assert(SIGRTMIN == 35, "musl x86 application realtime minimum");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigaddset),
    int (*)(sigset_t *, int)), "POSIX sigaddset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigdelset),
    int (*)(sigset_t *, int)), "POSIX sigdelset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigfillset),
    int (*)(sigset_t *)), "POSIX sigfillset declaration");

int crabc_x86_64_sigset_mutation_probe(void)
{
    sigset_t filled = {0};
    sigset_t added = {0};
    sigset_t deleted = {0};
    sigset_t invalid_add = {0};
    sigset_t invalid_del = {0};
    unsigned long *filled_words = (unsigned long *)(void *)&filled;
    unsigned long *added_words = (unsigned long *)(void *)&added;
    unsigned long *deleted_words = (unsigned long *)(void *)&deleted;
    unsigned long *invalid_add_words = (unsigned long *)(void *)&invalid_add;
    unsigned long *invalid_del_words = (unsigned long *)(void *)&invalid_del;

    /* sigfillset writes its x86 first word and retains both tail sentinels. */
    filled_words[0] = 0;
    filled_words[1] = 0x1111111111111111UL;
    filled_words[SIGSET_WORDS - 1] = 0x2222222222222222UL;
    errno = ERANGE;
    if (sigfillset(&filled) != 0 || errno != ERANGE)
        return 1;
    if (filled_words[0] != 0xfffffffc7fffffffUL ||
        filled_words[1] != 0x1111111111111111UL ||
        filled_words[SIGSET_WORDS - 1] != 0x2222222222222222UL)
        return 2;

    /* Add a low and realtime application bit; the tail sentinel survives. */
    added_words[0] = 0x1000000000000000UL;
    added_words[1] = 0x3333333333333333UL;
    added_words[SIGSET_WORDS - 1] = 0x4444444444444444UL;
    errno = ERANGE;
    if (sigaddset(&added, SIGUSR1) != 0 || errno != ERANGE ||
        sigaddset(&added, SIGRTMIN) != 0 || errno != ERANGE)
        return 3;
    if (added_words[0] != 0x1000000400000200UL ||
        added_words[1] != 0x3333333333333333UL ||
        added_words[SIGSET_WORDS - 1] != 0x4444444444444444UL)
        return 4;

    /* Deletion has the same one-word boundary and stale-errno success rule. */
    deleted_words[0] = 0xffffffffffffffffUL;
    deleted_words[1] = 0x5555555555555555UL;
    deleted_words[SIGSET_WORDS - 1] = 0x6666666666666666UL;
    errno = ERANGE;
    if (sigdelset(&deleted, SIGUSR2) != 0 || errno != ERANGE ||
        sigdelset(&deleted, SIGRTMIN) != 0 || errno != ERANGE)
        return 5;
    if (deleted_words[0] != 0xfffffffbfffff7ffUL ||
        deleted_words[1] != 0x5555555555555555UL ||
        deleted_words[SIGSET_WORDS - 1] != 0x6666666666666666UL)
        return 6;

    /* Invalid input fails before dereferencing and leaves storage untouched. */
    invalid_add_words[0] = 0x0123456789abcdefUL;
    invalid_add_words[1] = 0x7777777777777777UL;
    invalid_add_words[SIGSET_WORDS - 1] = 0x8888888888888888UL;
    errno = ERANGE;
    if (sigaddset(&invalid_add, 0) != -1 || errno != EINVAL)
        return 7;
    if (invalid_add_words[0] != 0x0123456789abcdefUL ||
        invalid_add_words[1] != 0x7777777777777777UL ||
        invalid_add_words[SIGSET_WORDS - 1] != 0x8888888888888888UL)
        return 8;
    errno = ERANGE;
    if (sigaddset((sigset_t *)0, 0) != -1 || errno != EINVAL)
        return 9;

    invalid_del_words[0] = 0xfedcba9876543210UL;
    invalid_del_words[1] = 0x9999999999999999UL;
    invalid_del_words[SIGSET_WORDS - 1] = 0xaaaaaaaaaaaaaaaaUL;
    errno = ERANGE;
    if (sigdelset(&invalid_del, SIGRTMIN - 3) != -1 || errno != EINVAL)
        return 10;
    if (invalid_del_words[0] != 0xfedcba9876543210UL ||
        invalid_del_words[1] != 0x9999999999999999UL ||
        invalid_del_words[SIGSET_WORDS - 1] != 0xaaaaaaaaaaaaaaaaUL)
        return 11;
    errno = ERANGE;
    if (sigdelset((sigset_t *)0, 65) != -1 || errno != EINVAL)
        return 12;

    return 0;
}

#ifndef CRABC_SIGSET_MUTATION_FREESTANDING
int main(void)
{
    return crabc_x86_64_sigset_mutation_probe();
}
#endif

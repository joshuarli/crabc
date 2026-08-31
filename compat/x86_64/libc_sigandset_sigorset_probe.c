/*
 * Pinned-musl Linux/x86-64 `sigandset`/`sigorset` differential and static body.
 *
 * Each selected GNU helper reads both first public sigset_t words, writes only
 * the destination first word, returns zero, and preserves an already-set errno.
 * This shared body makes the ignored tail and destination/operand aliasing
 * observable. The freestanding candidate links only these helpers and the
 * initial-TLS errno seam; it has no signal action, mask, delivery, wait, or
 * descriptor plumbing.
 */

#define _GNU_SOURCE 1

#include <errno.h>
#include <signal.h>

enum {
    SIGSET_WORDS = 128 / sizeof(unsigned long),
};

_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
    "x86 public sigset_t layout");
_Static_assert(SIGSET_WORDS == 16, "x86 public sigset_t word count");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigandset),
    int (*)(sigset_t *, const sigset_t *, const sigset_t *)),
    "GNU sigandset declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigorset),
    int (*)(sigset_t *, const sigset_t *, const sigset_t *)),
    "GNU sigorset declaration");

int crabc_x86_64_sigandset_sigorset_probe(void)
{
    sigset_t and_left = {0};
    sigset_t and_right = {0};
    sigset_t and_dest = {0};
    sigset_t or_left = {0};
    sigset_t or_right = {0};
    sigset_t or_dest = {0};
    sigset_t and_left_alias = {0};
    sigset_t and_alias_right = {0};
    sigset_t or_left_alias = {0};
    sigset_t or_right_alias = {0};
    unsigned long *and_left_words = (unsigned long *)(void *)&and_left;
    unsigned long *and_right_words = (unsigned long *)(void *)&and_right;
    unsigned long *and_dest_words = (unsigned long *)(void *)&and_dest;
    unsigned long *or_left_words = (unsigned long *)(void *)&or_left;
    unsigned long *or_right_words = (unsigned long *)(void *)&or_right;
    unsigned long *or_dest_words = (unsigned long *)(void *)&or_dest;
    unsigned long *and_left_alias_words =
        (unsigned long *)(void *)&and_left_alias;
    unsigned long *and_alias_right_words =
        (unsigned long *)(void *)&and_alias_right;
    unsigned long *or_left_alias_words =
        (unsigned long *)(void *)&or_left_alias;
    unsigned long *or_right_alias_words =
        (unsigned long *)(void *)&or_right_alias;

    /* AND: each tail sentinel must remain entirely caller-resident. */
    and_left_words[0] = 0xf0f0f0f00f0f0f0fUL;
    and_left_words[1] = 0x1111111111111111UL;
    and_left_words[SIGSET_WORDS - 1] = 0x2222222222222222UL;
    and_right_words[0] = 0x0ff00ff0ff00ff00UL;
    and_right_words[1] = 0x3333333333333333UL;
    and_right_words[SIGSET_WORDS - 1] = 0x4444444444444444UL;
    and_dest_words[0] = 0x5555555555555555UL;
    and_dest_words[1] = 0x6666666666666666UL;
    and_dest_words[SIGSET_WORDS - 1] = 0x7777777777777777UL;
    errno = ERANGE;
    if (sigandset(&and_dest, &and_left, &and_right) != 0 || errno != ERANGE)
        return 1;
    if (and_dest_words[0] != 0x00f000f00f000f00UL ||
        and_dest_words[1] != 0x6666666666666666UL ||
        and_dest_words[SIGSET_WORDS - 1] != 0x7777777777777777UL)
        return 2;
    if (and_left_words[0] != 0xf0f0f0f00f0f0f0fUL ||
        and_left_words[1] != 0x1111111111111111UL ||
        and_left_words[SIGSET_WORDS - 1] != 0x2222222222222222UL ||
        and_right_words[0] != 0x0ff00ff0ff00ff00UL ||
        and_right_words[1] != 0x3333333333333333UL ||
        and_right_words[SIGSET_WORDS - 1] != 0x4444444444444444UL)
        return 3;

    /* OR has the same one-word write boundary and stale-errno rule. */
    or_left_words[0] = 0x0123456789abcdefUL;
    or_left_words[1] = 0x8888888888888888UL;
    or_left_words[SIGSET_WORDS - 1] = 0x9999999999999999UL;
    or_right_words[0] = 0xfedcba9876543210UL;
    or_right_words[1] = 0xaaaaaaaaaaaaaaaaUL;
    or_right_words[SIGSET_WORDS - 1] = 0xbbbbbbbbbbbbbbbbUL;
    or_dest_words[0] = 0xccccccccccccccccUL;
    or_dest_words[1] = 0xddddddddddddddddUL;
    or_dest_words[SIGSET_WORDS - 1] = 0xeeeeeeeeeeeeeeeeUL;
    errno = ERANGE;
    if (sigorset(&or_dest, &or_left, &or_right) != 0 || errno != ERANGE)
        return 4;
    if (or_dest_words[0] != 0xffffffffffffffffUL ||
        or_dest_words[1] != 0xddddddddddddddddUL ||
        or_dest_words[SIGSET_WORDS - 1] != 0xeeeeeeeeeeeeeeeeUL)
        return 5;
    if (or_left_words[0] != 0x0123456789abcdefUL ||
        or_left_words[1] != 0x8888888888888888UL ||
        or_left_words[SIGSET_WORDS - 1] != 0x9999999999999999UL ||
        or_right_words[0] != 0xfedcba9876543210UL ||
        or_right_words[1] != 0xaaaaaaaaaaaaaaaaUL ||
        or_right_words[SIGSET_WORDS - 1] != 0xbbbbbbbbbbbbbbbbUL)
        return 6;

    /* Musl reads both operands before writing, including dest == left. */
    and_left_alias_words[0] = 0xff00ff00ff00ff00UL;
    and_left_alias_words[1] = 0x123456789abcdef0UL;
    and_left_alias_words[SIGSET_WORDS - 1] = 0x0123456789abcdefUL;
    and_alias_right_words[0] = 0x0f0f0f0f0f0f0f0fUL;
    and_alias_right_words[1] = 0xfedcba9876543210UL;
    and_alias_right_words[SIGSET_WORDS - 1] = 0x0fedcba987654321UL;
    errno = ERANGE;
    if (sigandset(&and_left_alias, &and_left_alias, &and_alias_right) != 0 ||
        errno != ERANGE)
        return 7;
    if (and_left_alias_words[0] != 0x0f000f000f000f00UL ||
        and_left_alias_words[1] != 0x123456789abcdef0UL ||
        and_left_alias_words[SIGSET_WORDS - 1] != 0x0123456789abcdefUL ||
        and_alias_right_words[0] != 0x0f0f0f0f0f0f0f0fUL ||
        and_alias_right_words[1] != 0xfedcba9876543210UL ||
        and_alias_right_words[SIGSET_WORDS - 1] != 0x0fedcba987654321UL)
        return 8;

    /* The complementary dest == right OR case retains the same source order. */
    or_left_alias_words[0] = 0x00ff00ff00ff00ffUL;
    or_left_alias_words[1] = 0x13579bdf2468ace0UL;
    or_left_alias_words[SIGSET_WORDS - 1] = 0x02468ace13579bdfUL;
    or_right_alias_words[0] = 0xf000f000f000f000UL;
    or_right_alias_words[1] = 0x1111222233334444UL;
    or_right_alias_words[SIGSET_WORDS - 1] = 0x5555666677778888UL;
    errno = ERANGE;
    if (sigorset(&or_right_alias, &or_left_alias, &or_right_alias) != 0 ||
        errno != ERANGE)
        return 9;
    if (or_right_alias_words[0] != 0xf0fff0fff0fff0ffUL ||
        or_right_alias_words[1] != 0x1111222233334444UL ||
        or_right_alias_words[SIGSET_WORDS - 1] != 0x5555666677778888UL ||
        or_left_alias_words[0] != 0x00ff00ff00ff00ffUL ||
        or_left_alias_words[1] != 0x13579bdf2468ace0UL ||
        or_left_alias_words[SIGSET_WORDS - 1] != 0x02468ace13579bdfUL)
        return 10;

    return 0;
}

#ifndef CRABC_SIGANDSET_SIGORSET_FREESTANDING
int main(void)
{
    return crabc_x86_64_sigandset_sigorset_probe();
}
#endif

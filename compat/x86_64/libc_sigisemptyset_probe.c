/*
 * Pinned-musl Linux/x86-64 `sigisemptyset` differential and static body.
 *
 * The selected GNU predicate reads only musl's first public sigset_t word.
 * This shared body makes tail-only bits observable, proves no caller storage
 * is written, and preserves an already-set errno value on both result paths.
 * The freestanding candidate links only the predicate and initial-TLS errno
 * seam; it has no signal action, mask, delivery, wait, or descriptor plumbing.
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
_Static_assert(__builtin_types_compatible_p(__typeof__(&sigisemptyset),
    int (*)(const sigset_t *)), "GNU sigisemptyset declaration");

int crabc_x86_64_sigisemptyset_probe(void)
{
    sigset_t tail_only = {0};
    sigset_t first_word = {0};
    unsigned long *tail_words = (unsigned long *)(void *)&tail_only;
    unsigned long *first_words = (unsigned long *)(void *)&first_word;

    /* tail-only: musl's one-word predicate must ignore both tail sentinels. */
    tail_words[1] = 0x0123456789abcdefUL;
    tail_words[SIGSET_WORDS - 1] = 0xfedcba9876543210UL;
    errno = ERANGE;
    if (sigisemptyset(&tail_only) != 1 || errno != ERANGE)
        return 1;
    if (tail_words[0] != 0 || tail_words[1] != 0x0123456789abcdefUL ||
        tail_words[SIGSET_WORDS - 1] != 0xfedcba9876543210UL)
        return 2;

    first_words[0] = 1UL;
    first_words[1] = 0x1111111111111111UL;
    first_words[SIGSET_WORDS - 1] = 0x2222222222222222UL;
    errno = ERANGE;
    if (sigisemptyset(&first_word) != 0 || errno != ERANGE)
        return 3;
    if (first_words[0] != 1UL || first_words[1] != 0x1111111111111111UL ||
        first_words[SIGSET_WORDS - 1] != 0x2222222222222222UL)
        return 4;

    return 0;
}

#ifndef CRABC_SIGISEMPTYSET_FREESTANDING
int main(void)
{
    return crabc_x86_64_sigisemptyset_probe();
}
#endif

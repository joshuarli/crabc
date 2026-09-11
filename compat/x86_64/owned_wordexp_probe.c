/* Owned static Linux/x86-64 wordexp/wordfree installed-product probe.
 *
 * This workload is deliberately ordinary C: pinned musl 1.2.6 and both
 * installed crabc static modes compile the same source against the project
 * headers.  It exercises the source's shell protocol, NUL-delimited words,
 * hardened WRDE_NOCMD scanner, offset/append/reuse ownership, syntax and
 * unset-variable results, and allocation cleanup.  It does not treat a
 * static executable as evidence for dlopen or a general shell subsystem.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "owned wordexp probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wordexp.h>

_Static_assert(sizeof(wordexp_t) == 24, "x86-64 wordexp_t layout");
_Static_assert(_Alignof(wordexp_t) == 8, "x86-64 wordexp_t alignment");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wordexp),
    int (*)(const char *restrict, wordexp_t *restrict, int)),
    "wordexp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wordfree),
    void (*)(wordexp_t *)), "wordfree declaration");

static int check_words(const wordexp_t *words, size_t count,
    const char *const expected[])
{
    size_t index;

    if (words->we_wordc != count || words->we_wordv == NULL)
        return 0;
    for (index = 0; index < count; ++index) {
        if (strcmp(words->we_wordv[words->we_offs + index], expected[index]) != 0)
            return 0;
    }
    return words->we_wordv[words->we_offs + count] == NULL;
}

/* `wordfree` must retire all caller-visible allocation ownership and make a
 * second release inert. This is a source-compatible observable cleanup check
 * that stays within the sealed installed driver's normal link contract. */
static int check_freed(wordexp_t *words)
{
    wordfree(words);
    return words->we_wordv == NULL && words->we_wordc == 0;
}

static int check_initial_error(const char *expression, int flags, int expected)
{
    wordexp_t words = { 0 };

    if (wordexp(expression, &words, flags) != expected)
        return 0;
    return words.we_wordc == 0 && words.we_wordv == NULL;
}

static int ordinary_and_nocmd_cases(void)
{
    static const char *const ordinary[] = { "one", "two" };
    static const char *const positional[] = { "$1" };
    static const char *const environment[] = { "bar", "baz" };
    static const char *const empty[] = { "" };
    static const char *const arithmetic[] = { "3" };
    static const char *const nested[] = { "6" };
    static const char *const nested_brace[] = { "{" };
    static const char *const escaped_nested_brace[] = { "\\{" };
    static const char *const no_words[] = { NULL };
    wordexp_t words = { 0 };

    if (wordexp("one two", &words, 0) != 0 ||
        !check_words(&words, 2, ordinary))
        return 1;
    if (!check_freed(&words))
        return 2;

    if (wordexp("$1", &words, 0) != 0 ||
        !check_words(&words, 1, positional))
        return 3;
    if (!check_freed(&words))
        return 4;

    if (wordexp("$CRABC_WORDEXP", &words, 0) != 0 ||
        !check_words(&words, 2, environment))
        return 5;
    if (!check_freed(&words))
        return 6;

    if (wordexp("\"\"", &words, 0) != 0 || !check_words(&words, 1, empty))
        return 7;
    if (!check_freed(&words))
        return 8;

    /* Musl's source accepts WRDE_UNDEF but does not enable set -u. */
    if (wordexp("$CRABC_WORDEXP_MISSING", &words, WRDE_UNDEF) != 0 ||
        !check_words(&words, 0, no_words))
        return 9;
    if (!check_freed(&words))
        return 10;

    if (wordexp("$((1+2))", &words, WRDE_NOCMD) != 0 ||
        !check_words(&words, 1, arithmetic))
        return 11;
    if (!check_freed(&words))
        return 12;

    /* Nested arithmetic includes parameter expansion and remains non-command
     * syntax; this prevents the scanner from rejecting it as `$(`. */
    if (wordexp("$(($((1+${CRABC_WORDEXP_MISSING-$((1+1))}))+3))",
            &words, WRDE_NOCMD) != 0 || !check_words(&words, 1, nested))
        return 13;
    if (!check_freed(&words))
        return 14;

    /* These quote/parameter combinations are easy to misclassify as naked
     * braces. They remain source-compatible non-command expansions. */
    if (wordexp("\"${CRABC_WORDEXP_MISSING-{}\"", &words, WRDE_NOCMD) != 0 ||
        !check_words(&words, 1, nested_brace))
        return 15;
    if (!check_freed(&words))
        return 16;
    if (wordexp("\"${CRABC_WORDEXP_MISSING-\\{}\"", &words, WRDE_NOCMD) != 0 ||
        !check_words(&words, 1, escaped_nested_brace))
        return 17;
    if (!check_freed(&words))
        return 18;

    if (!check_initial_error("$(printf bad)", WRDE_NOCMD, WRDE_CMDSUB) ||
        !check_initial_error("`printf bad`", WRDE_NOCMD, WRDE_CMDSUB) ||
        !check_initial_error("one; two", WRDE_NOCMD, WRDE_BADCHAR))
        return 19;
    /* A syntax error still creates and tears down the shell stream. */
    if (!check_initial_error("one )", 0, WRDE_SYNTAX))
        return 20;
    return 0;
}

static int offsets_append_reuse(void)
{
    static const char *const alpha[] = { "alpha" };
    static const char *const appended[] = { "alpha", "beta", "gamma" };
    static const char *const old[] = { "old" };
    static const char *const replacement[] = { "replacement" };
    wordexp_t words = { 0 };

    words.we_offs = 2;
    if (wordexp("alpha", &words, WRDE_DOOFFS) != 0 ||
        !check_words(&words, 1, alpha) || words.we_wordv[0] != NULL ||
        words.we_wordv[1] != NULL)
        return 1;
    if (wordexp("beta gamma", &words, WRDE_DOOFFS | WRDE_APPEND) != 0 ||
        !check_words(&words, 3, appended))
        return 2;
    if (!check_freed(&words))
        return 3;

    if (wordexp("old", &words, 0) != 0 || !check_words(&words, 1, old))
        return 4;
    if (wordexp("replacement", &words, WRDE_REUSE) != 0 ||
        !check_words(&words, 1, replacement))
        return 5;
    return check_freed(&words) ? 0 : 6;
}

/* Musl's child exits after its private `/bin/sh` exec fails; the parent sees
 * the result pipe close before the NUL sentinel and reports WRDE_SYNTAX.
 * Keep this separate mode so the runner can execute the exact same C source
 * in private roots with absent, non-executable, and invalid shell images. */
static int unavailable_shell_case(void)
{
    wordexp_t words = { 0 };

    /* The child owns its exec errno. Musl's parent returns the missing-stream
     * syntax result without publishing that child-only value. */
    errno = ERANGE;
    if (wordexp("literal", &words, 0) != WRDE_SYNTAX)
        return 1;
    if (words.we_wordc != 0 || words.we_wordv != NULL)
        return 2;
    if (errno != ERANGE)
        return 3;
    wordfree(&words);
    return 0;
}

/* This expression never starts a shell: `WRDE_NOCMD` must classify it in the
 * lexical preflight. Pinned musl 1.2.6 increments its arithmetic-paren count
 * for `$((`, reaches zero at the inner `*)`, then rejects the following `;`
 * as `WRDE_BADCHAR`. Keep a real command-substitution control beside it so a
 * source-shaped scanner does not accidentally weaken that boundary. */
static int source_nocmd_case(void)
{
    if (!check_initial_error(
            "$((case $A in a) echo x ;; *) echo y ;; esac))",
            WRDE_NOCMD, WRDE_BADCHAR))
        return 1;
    if (!check_initial_error("$(echo x)", WRDE_NOCMD, WRDE_CMDSUB))
        return 2;
    return 0;
}

/* The separately named POSIX correction cells share this ordinary public C
 * translation unit.  The installed driver therefore seals one object before
 * linking it unchanged to the pinned-musl oracle and every owned product. */
#include "owned_wordexp_posix_probe.c"

int main(int argc, char *argv[])
{
    int result;

    if (argc == 2 && strcmp(argv[1], "--shell-unavailable") == 0) {
        result = unavailable_shell_case();
        if (result != 0)
            return 64 + result;
        puts("owned-wordexp-shell-unavailable: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--nocmd-source") == 0) {
        result = source_nocmd_case();
        if (result != 0)
            return 96 + result;
        puts("owned-wordexp-nocmd-source: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-quiet") == 0) {
        result = posix_quiet_case();
        if (result != 0) {
            if (result == 4)
                puts("owned-wordexp-posix-quiet: SOURCE-RED diagnostic-present");
            return 80 + result;
        }
        puts("owned-wordexp-posix-quiet: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd") == 0) {
        result = posix_nocmd_case();
        if (result != 0) {
            if (result == 1)
                puts("owned-wordexp-posix-nocmd: SOURCE-RED parameter-brace-rejected");
            return 112 + result;
        }
        puts("owned-wordexp-posix-nocmd: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-escaped-control") == 0) {
        result = posix_nocmd_escaped_brace_control_case();
        if (result != 0) {
            if (result == 4)
                puts("owned-wordexp-posix-nocmd-escaped-control: NOCMD-RED command-marker-created");
            return 128 + result;
        }
        puts("owned-wordexp-posix-nocmd-escaped-control: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-arithmetic-control") == 0) {
        result = posix_nocmd_arithmetic_command_control_case();
        if (result != 0) {
            if (result == 2)
                puts("owned-wordexp-posix-nocmd-arithmetic-control: SOURCE-RED parameter-brace-rejected");
            if (result == 4)
                puts("owned-wordexp-posix-nocmd-arithmetic-control: SOURCE-RED command-marker-created");
            return 160 + result;
        }
        puts("owned-wordexp-posix-nocmd-arithmetic-control: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-pattern-control") == 0) {
        result = posix_nocmd_pattern_control_case();
        if (result != 0) {
            if (result == 4)
                puts("owned-wordexp-posix-nocmd-pattern-control: NOCMD-RED command-marker-created");
            return 176 + result;
        }
        puts("owned-wordexp-posix-nocmd-pattern-control: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-arithmetic-delimiter-control") == 0) {
        result = posix_nocmd_arithmetic_delimiter_control_case();
        if (result != 0) {
            if (result == 4)
                puts("owned-wordexp-posix-nocmd-arithmetic-delimiter-control: SOURCE-RED command-marker-created");
            return 192 + result;
        }
        puts("owned-wordexp-posix-nocmd-arithmetic-delimiter-control: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-continuation-control") == 0) {
        result = posix_nocmd_continuation_command_control_case();
        if (result != 0) {
            if (result == 4)
                puts("owned-wordexp-posix-nocmd-continuation-control: SOURCE-RED command-marker-created");
            return 208 + result;
        }
        puts("owned-wordexp-posix-nocmd-continuation-control: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-dollar-single-control") == 0) {
        result = posix_nocmd_dollar_single_control_case();
        if (result != 0) {
            if (result == 4)
                puts("owned-wordexp-posix-nocmd-dollar-single-control: SOURCE-RED command-marker-created");
            return 224 + result;
        }
        puts("owned-wordexp-posix-nocmd-dollar-single-control: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-comment-control") == 0) {
        result = posix_nocmd_comment_control_case();
        if (result != 0) {
            if (result == 4)
                puts("owned-wordexp-posix-nocmd-comment-control: SOURCE-RED command-marker-created");
            return 240 + result;
        }
        puts("owned-wordexp-posix-nocmd-comment-control: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--posix-nocmd-positional") == 0) {
        result = posix_nocmd_positional_case();
        if (result != 0) {
            if (result == 1)
                puts("owned-wordexp-posix-nocmd-positional: SOURCE-RED positional-parameter-rejected");
            return 136 + result;
        }
        puts("owned-wordexp-posix-nocmd-positional: PASS");
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--undef-source-observation") == 0) {
        result = posix_undef_source_observation();
        if (result != 0)
            return 144 + result;
        puts("owned-wordexp-undef-source-observation: SOURCE-RED");
        return 0;
    }
    if (argc != 1)
        return 127;
    result = source_nocmd_case();
    if (result != 0)
        return 96 + result;
    result = ordinary_and_nocmd_cases();
    if (result != 0)
        return result;
    result = offsets_append_reuse();
    if (result != 0)
        return 32 + result;
    puts("owned-wordexp: PASS");
    return 0;
}

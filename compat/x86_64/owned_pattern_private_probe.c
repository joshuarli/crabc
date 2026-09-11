/*
 * Freestanding private witness for the unselected shell-pattern boundary.
 *
 * It declares its __crabc_test_shell_* entry points itself.  The runner
 * compiles those only with crabc_owned_pattern_private_test, so this has no
 * installed header, public flag, or normal-product export.
 *
 * POSIX.1-2024 Issue 8 Shell Command Language 2.14.1 and 2.14.3 requires
 * quote removal to retain enough information to distinguish quoted pattern
 * syntax. A zero mask byte is eligible syntax; one is a protected literal.
 * The NUL cell is present in both byte arrays and has mask zero.
 */

#include <locale.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

enum {
    SHELL_GLOB_NO_ACTIVE_PATTERN = 0,
    SHELL_GLOB_NO_MATCH = 1,
    SHELL_GLOB_MATCHES = 2,
};

extern int __crabc_test_shell_match(
    const unsigned char *pattern,
    const unsigned char *protection,
    size_t pattern_length,
    const unsigned char *text,
    size_t text_length
);
extern int __crabc_test_shell_glob(
    const unsigned char *pattern,
    const unsigned char *protection,
    size_t pattern_length,
    size_t *match_count
);
extern int __crabc_test_shell_glob_contains(
    const unsigned char *pattern,
    const unsigned char *protection,
    size_t pattern_length,
    const unsigned char *expected,
    size_t expected_length
);

static int failure_line;

#define CHECK(condition) do { \
    if (!(condition)) { \
        failure_line = __LINE__; \
        return -1; \
    } \
} while (0)

#define MATCH(pattern, protection, text) \
    __crabc_test_shell_match((pattern), (protection), sizeof(pattern), (text), sizeof(text) - 1)

#define GLOB(pattern, protection, count) \
    __crabc_test_shell_glob((pattern), (protection), sizeof(pattern), &(count))

#define GLOB_CONTAINS(pattern, protection, expected) \
    __crabc_test_shell_glob_contains( \
        (pattern), (protection), sizeof(pattern), (expected), sizeof(expected) - 1 \
    )

static int protected_single_character_cases(void)
{
    static const unsigned char star[] = { '*', 0 };
    static const unsigned char question[] = { '?', 0 };
    static const unsigned char open[] = { '[', 0 };
    static const unsigned char close[] = { ']', 0 };
    static const unsigned char bang[] = { '!', 0 };
    static const unsigned char dash[] = { '-', 0 };
    static const unsigned char protected[] = { 1, 0 };
    static const unsigned char raw[] = { 0, 0 };
    static const unsigned char a[] = { 'a', 0 };

    CHECK(MATCH(star, protected, star) == 1);
    CHECK(MATCH(star, protected, a) == 0);
    CHECK(MATCH(question, protected, question) == 1);
    CHECK(MATCH(question, protected, a) == 0);
    CHECK(MATCH(open, protected, open) == 1);
    CHECK(MATCH(close, protected, close) == 1);
    CHECK(MATCH(bang, protected, bang) == 1);
    CHECK(MATCH(dash, protected, dash) == 1);
    CHECK(MATCH(star, raw, a) == 1);
    CHECK(MATCH(question, raw, a) == 1);
    return 0;
}

static int checked_pattern_view_cases(void)
{
    static const unsigned char terminated[] = { '*', 0 };
    static const unsigned char bad_terminal_mask[] = { 0, 1 };
    static const unsigned char bad_protection[] = { 2, 0 };
    static const unsigned char interior_nul[] = { '*', 0, '?', 0 };
    static const unsigned char interior_nul_mask[] = { 0, 0, 0, 0 };
    static const unsigned char text[] = { '*', 0 };

    CHECK(__crabc_test_shell_match(
        terminated, bad_terminal_mask, sizeof(terminated), text, sizeof(text) - 1
    ) == -1);
    CHECK(__crabc_test_shell_match(
        terminated, bad_protection, sizeof(terminated), text, sizeof(text) - 1
    ) == -1);
    CHECK(__crabc_test_shell_match(
        interior_nul, interior_nul_mask, sizeof(interior_nul), text, sizeof(text) - 1
    ) == -1);
    return 0;
}

static int quoted_bracket_cases(void)
{
    static const unsigned char range[] = { '[', 'a', '-', 'z', ']', 0 };
    static const unsigned char range_mask[] = { 0, 0, 1, 0, 0, 0 };
    static const unsigned char protected_close[] = { '[', 'a', ']', 'z', ']', 0 };
    static const unsigned char protected_close_mask[] = { 0, 0, 1, 0, 0, 0 };
    static const unsigned char protected_bang[] = { '[', '!', 'a', ']', 0 };
    static const unsigned char protected_bang_mask[] = { 0, 1, 0, 0, 0 };
    static const unsigned char protected_caret[] = { '[', '^', 'a', ']', 0 };
    static const unsigned char protected_caret_mask[] = { 0, 1, 0, 0, 0 };
    static const unsigned char protected_delimiter[] = {
        '[', '[', ':', 'd', 'i', 'g', 'i', 't', ':', ']', ']', 0
    };
    static const unsigned char protected_delimiter_mask[] = {
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    static const unsigned char protected_class_name[] = {
        '[', '[', ':', 'd', 'i', 'g', 'i', 't', ':', ']', ']', 0
    };
    static const unsigned char protected_class_name_mask[] = {
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
    };
    static const unsigned char raw_backslash_range[] = { '[', 'a', '\\', '-', 'z', ']', 0 };
    static const unsigned char raw[] = { 0, 0, 0, 0, 0, 0, 0 };
    static const unsigned char dash[] = { '-', 0 };
    static const unsigned char a[] = { 'a', 0 };
    static const unsigned char z[] = { 'z', 0 };
    static const unsigned char m[] = { 'm', 0 };
    static const unsigned char close[] = { ']', 0 };
    static const unsigned char bang[] = { '!', 0 };
    static const unsigned char caret[] = { '^', 0 };
    static const unsigned char dclose[] = { 'd', ']', 0 };
    static const unsigned char seven[] = { '7', 0 };
    static const unsigned char backslash[] = { '\\', 0 };

    CHECK(MATCH(range, range_mask, dash) == 1);
    CHECK(MATCH(range, range_mask, a) == 1);
    CHECK(MATCH(range, range_mask, z) == 1);
    CHECK(MATCH(range, range_mask, m) == 0);
    CHECK(MATCH(range, range_mask, backslash) == 0);
    CHECK(MATCH(protected_close, protected_close_mask, a) == 1);
    CHECK(MATCH(protected_close, protected_close_mask, close) == 1);
    CHECK(MATCH(protected_close, protected_close_mask, z) == 1);
    CHECK(MATCH(protected_bang, protected_bang_mask, bang) == 1);
    CHECK(MATCH(protected_bang, protected_bang_mask, a) == 1);
    CHECK(MATCH(protected_bang, protected_bang_mask, m) == 0);
    CHECK(MATCH(protected_caret, protected_caret_mask, caret) == 1);
    CHECK(MATCH(protected_caret, protected_caret_mask, a) == 1);
    CHECK(MATCH(protected_delimiter, protected_delimiter_mask, dclose) == 1);
    CHECK(MATCH(protected_delimiter, protected_delimiter_mask, seven) == 0);
    CHECK(MATCH(protected_class_name, protected_class_name_mask, seven) == 1);
    /* POSIX leaves raw backslash in a bracket unspecified for the shell. */
    CHECK(MATCH(raw_backslash_range, raw, m) == 1);
    CHECK(MATCH(raw_backslash_range, raw, backslash) == 1);
    CHECK(MATCH(raw_backslash_range, raw, dash) == 0);
    return 0;
}

static int escaped_and_malformed_cases(void)
{
    static const unsigned char protected_open_star[] = { '[', '*', 0 };
    static const unsigned char protected_open_star_mask[] = { 1, 0, 0 };
    static const unsigned char protected_backslash_star[] = { '\\', '*', 0 };
    static const unsigned char protected_backslash_star_mask[] = { 1, 0, 0 };
    static const unsigned char raw_backslash_two_stars[] = { '\\', '*', '*', 0 };
    static const unsigned char raw[] = { 0, 0, 0, 0 };
    static const unsigned char malformed[] = { '[', 'a', 'b', 'c', 0 };
    static const unsigned char malformed_mask[] = { 0, 0, 0, 0, 0 };
    static const unsigned char open_name[] = { '[', 'a', 'n', 'y', 0 };
    static const unsigned char backslash_name[] = { '\\', 'a', 'n', 'y', 0 };
    static const unsigned char star_name[] = { '*', 'a', 'n', 'y', 0 };
    static const unsigned char malformed_name[] = { '[', 'a', 'b', 'c', 0 };
    static const unsigned char other[] = { 'o', 't', 'h', 'e', 'r', 0 };

    CHECK(MATCH(protected_open_star, protected_open_star_mask, open_name) == 1);
    CHECK(MATCH(protected_backslash_star, protected_backslash_star_mask, backslash_name) == 1);
    CHECK(MATCH(raw_backslash_two_stars, raw, star_name) == 1);
    CHECK(MATCH(malformed, malformed_mask, malformed_name) == 1);
    CHECK(MATCH(malformed, malformed_mask, other) == 0);
    return 0;
}

static int utf8_and_invalid_cases(void)
{
    static const unsigned char utf8[] = { 0xc3, 0x85, 0 };
    static const unsigned char utf8_mask[] = { 0, 0, 0 };
    static const unsigned char lowercase[] = { 0xc3, 0xa5, 0 };
    static const unsigned char star[] = { '*', 0 };
    static const unsigned char question[] = { '?', 0 };
    static const unsigned char raw[] = { 0, 0 };
    static const unsigned char invalid[] = { 0xff, 0 };

    CHECK(setlocale(LC_CTYPE, "C.UTF-8") != 0);
    CHECK(MATCH(utf8, utf8_mask, utf8) == 1);
    CHECK(MATCH(question, raw, utf8) == 1);
    CHECK(MATCH(utf8, utf8_mask, lowercase) == 0);
    CHECK(MATCH(star, raw, invalid) == 1);
    CHECK(MATCH(question, raw, invalid) == 0);
    CHECK(MATCH(invalid, raw, invalid) == 0);
    return 0;
}

static int glob_cases(const char *fixture)
{
    static const unsigned char protected_star[] = { '*', 0 };
    static const unsigned char protected_star_mask[] = { 1, 0 };
    static const unsigned char raw_backslash_star[] = { '\\', '*', 0 };
    static const unsigned char raw_backslash_star_mask[] = { 0, 0, 0 };
    static const unsigned char protected_open_star[] = { '[', '*', 0 };
    static const unsigned char protected_open_star_mask[] = { 1, 0, 0 };
    static const unsigned char protected_backslash_star[] = { '\\', '*', 0 };
    static const unsigned char protected_backslash_star_mask[] = { 1, 0, 0 };
    static const unsigned char raw_backslash_two_stars[] = { '\\', '*', '*', 0 };
    static const unsigned char raw_backslash_two_stars_mask[] = { 0, 0, 0, 0 };
    static const unsigned char protected_range[] = { '[', 'a', '-', 'z', ']', 0 };
    static const unsigned char protected_range_mask[] = { 0, 0, 1, 0, 0, 0 };
    static const unsigned char protected_close[] = { '[', 'a', ']', 'z', ']', 0 };
    static const unsigned char protected_close_mask[] = { 0, 0, 1, 0, 0, 0 };
    static const unsigned char protected_bang[] = { '[', '!', 'a', ']', 0 };
    static const unsigned char protected_bang_mask[] = { 0, 1, 0, 0, 0 };
    static const unsigned char protected_delimiter[] = {
        '[', '[', ':', 'd', 'i', 'g', 'i', 't', ':', ']', ']', 0
    };
    static const unsigned char protected_delimiter_mask[] = {
        0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };
    static const unsigned char protected_class_name[] = {
        '[', '[', ':', 'd', 'i', 'g', 'i', 't', ':', ']', ']', 0
    };
    static const unsigned char protected_class_name_mask[] = {
        0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0
    };
    static const unsigned char protected_dot[] = { '.', 'h', '*', 0 };
    static const unsigned char protected_dot_mask[] = { 1, 0, 0, 0 };
    static const unsigned char raw_escaped_dot[] = { '\\', '.', 'h', '*', 0 };
    static const unsigned char raw_escaped_dot_mask[] = { 0, 0, 0, 0, 0 };
    static const unsigned char protected_slash[] = { 'd', 'i', 'r', '/', '*', 0 };
    static const unsigned char protected_slash_mask[] = { 0, 0, 0, 1, 0, 0 };
    static const unsigned char raw_escaped_slash[] = { 'd', 'i', 'r', '\\', '/', '*', 0 };
    static const unsigned char raw_escaped_slash_mask[] = { 0, 0, 0, 0, 0, 0, 0 };
    static const unsigned char protected_backslash_slash[] = { 'd', 'i', 'r', '\\', '/', '*', 0 };
    static const unsigned char protected_backslash_slash_mask[] = { 0, 0, 0, 1, 0, 0, 0 };
    static const unsigned char wildcard_before_slash[] = { 'd', '*', '/', 'l', 'e', 'a', 'f', 0 };
    static const unsigned char wildcard_before_slash_mask[] = { 0, 0, 1, 0, 0, 0, 0, 0 };
    static const unsigned char unmatched_star[] = { 'x', '*', 0 };
    static const unsigned char unmatched_star_mask[] = { 0, 0, 0 };
    static const unsigned char malformed[] = { '[', 'a', 'b', 'c', 0 };
    static const unsigned char malformed_mask[] = { 0, 0, 0, 0, 0 };
    static const unsigned char open_file[] = { '[', 'f', 'i', 'l', 'e', 0 };
    static const unsigned char backslash_file[] = { '\\', 'f', 'i', 'l', 'e', 0 };
    static const unsigned char star_file[] = { '*', 'f', 'i', 'l', 'e', 0 };
    static const unsigned char dash_file[] = { '-', 0 };
    static const unsigned char dot_file[] = { '.', 'h', 'i', 'd', 'd', 'e', 'n', 0 };
    static const unsigned char leaf_file[] = { 'd', 'i', 'r', '/', 'l', 'e', 'a', 'f', 0 };
    static const unsigned char backslash_leaf_file[] = {
        'd', 'i', 'r', '\\', '/', 'l', 'e', 'a', 'f', 0
    };
    size_t count = 99;

    CHECK(chdir(fixture) == 0);
    CHECK(GLOB(protected_star, protected_star_mask, count) == SHELL_GLOB_NO_ACTIVE_PATTERN);
    CHECK(count == 0);
    count = 99;
    CHECK(GLOB(raw_backslash_star, raw_backslash_star_mask, count) == SHELL_GLOB_NO_ACTIVE_PATTERN);
    CHECK(count == 0);
    count = 0;
    CHECK(GLOB(protected_open_star, protected_open_star_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    CHECK(GLOB_CONTAINS(protected_open_star, protected_open_star_mask, open_file) == 1);
    count = 0;
    CHECK(GLOB(protected_backslash_star, protected_backslash_star_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    CHECK(GLOB_CONTAINS(protected_backslash_star, protected_backslash_star_mask, backslash_file) == 1);
    count = 0;
    CHECK(GLOB(raw_backslash_two_stars, raw_backslash_two_stars_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 2);
    CHECK(GLOB_CONTAINS(raw_backslash_two_stars, raw_backslash_two_stars_mask, star_file) == 1);
    count = 0;
    CHECK(GLOB(protected_range, protected_range_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 3);
    CHECK(GLOB_CONTAINS(protected_range, protected_range_mask, dash_file) == 1);
    count = 0;
    CHECK(GLOB(protected_close, protected_close_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 3);
    count = 0;
    CHECK(GLOB(protected_bang, protected_bang_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 2);
    count = 0;
    CHECK(GLOB(protected_delimiter, protected_delimiter_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    count = 0;
    CHECK(GLOB(protected_class_name, protected_class_name_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    count = 0;
    CHECK(GLOB(protected_dot, protected_dot_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    CHECK(GLOB_CONTAINS(protected_dot, protected_dot_mask, dot_file) == 1);
    count = 0;
    CHECK(GLOB(raw_escaped_dot, raw_escaped_dot_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    CHECK(GLOB_CONTAINS(raw_escaped_dot, raw_escaped_dot_mask, dot_file) == 1);
    count = 0;
    CHECK(GLOB(protected_slash, protected_slash_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    CHECK(GLOB_CONTAINS(protected_slash, protected_slash_mask, leaf_file) == 1);
    count = 0;
    CHECK(GLOB(raw_escaped_slash, raw_escaped_slash_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    CHECK(GLOB_CONTAINS(raw_escaped_slash, raw_escaped_slash_mask, leaf_file) == 1);
    count = 0;
    CHECK(GLOB(protected_backslash_slash, protected_backslash_slash_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 1);
    CHECK(GLOB_CONTAINS(
        protected_backslash_slash, protected_backslash_slash_mask, backslash_leaf_file
    ) == 1);
    count = 0;
    CHECK(GLOB(wildcard_before_slash, wildcard_before_slash_mask, count) == SHELL_GLOB_MATCHES);
    CHECK(count == 2);
    CHECK(GLOB_CONTAINS(wildcard_before_slash, wildcard_before_slash_mask, leaf_file) == 1);
    CHECK(GLOB_CONTAINS(
        wildcard_before_slash, wildcard_before_slash_mask, backslash_leaf_file
    ) == 1);
    count = 99;
    CHECK(GLOB(unmatched_star, unmatched_star_mask, count) == SHELL_GLOB_NO_MATCH);
    CHECK(count == 0);
    count = 99;
    CHECK(GLOB(malformed, malformed_mask, count) == SHELL_GLOB_NO_ACTIVE_PATTERN);
    CHECK(count == 0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (protected_single_character_cases() != 0
        || checked_pattern_view_cases() != 0
        || quoted_bracket_cases() != 0
        || escaped_and_malformed_cases() != 0
        || utf8_and_invalid_cases() != 0
        || glob_cases(argv[1]) != 0) {
        fprintf(stderr, "owned pattern private witness failed at line %d\\n", failure_line);
        return 1;
    }
    puts("owned-pattern-private: PASS");
    return 0;
}

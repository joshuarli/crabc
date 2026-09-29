/* Bounded static crabc-libc x86-64 POSIX regex fixture.
 *
 * The common cases execute first against pinned musl 1.2.6 and then through
 * the selected freestanding archive. Candidate-only cases pin the deliberate
 * bounded profile: unsupported POSIX grammar is rejected rather than matched
 * with approximate semantics, and fixed capacity failures return REG_ESPACE.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <regex.h>
#include <stddef.h>

static int bytes_equal(const char *left, const char *right, size_t count)
{
    size_t index;
    for (index = 0; index < count; ++index)
        if (left[index] != right[index]) return 0;
    return 1;
}

static int compile_and_match(const char *pattern, int cflags, const char *text,
    int eflags, regoff_t expected_start, regoff_t expected_end)
{
    regex_t compiled;
    regmatch_t matches[3] = {{91, 92}, {93, 94}, {95, 96}};
    int result;

    result = regcomp(&compiled, pattern, cflags);
    if (result != 0 || compiled.re_nsub != 0) return 1;
    result = regexec(&compiled, text, 3, matches, eflags);
    if (result != 0 || matches[0].rm_so != expected_start ||
        matches[0].rm_eo != expected_end || matches[1].rm_so != -1 ||
        matches[1].rm_eo != -1 || matches[2].rm_so != -1 ||
        matches[2].rm_eo != -1) {
        regfree(&compiled);
        return 2;
    }
    regfree(&compiled);
    return 0;
}

static int expect_compile_error(const char *pattern, int cflags, int expected)
{
    regex_t compiled;
    int result = regcomp(&compiled, pattern, cflags);
    if (result == 0) regfree(&compiled);
    return result == expected ? 0 : 1;
}

/* These cases stay inside the selected byte grammar. Match slots after the
 * whole match are observable even though this grammar has no subexpressions.
 * The trace records the actual offsets from each physical C implementation. */
struct differential_case {
    const char *pattern;
    const char *subject;
    int cflags;
    int eflags;
    int result;
    regoff_t start;
    regoff_t end;
};

static const struct differential_case differential_cases[] = {
    {"a+b",  "xa+by",       0, 0, 0, 1, 4},
    {"a+b",  "xaaaby", REG_EXTENDED, 0, 0, 1, 5},
    {"a?b",  "xa?by",       0, 0, 0, 1, 4},
    {"a?b",  "xb", REG_EXTENDED, 0, 0, 1, 2},
    {"[a-c]+", "zzabc", REG_EXTENDED, 0, 0, 2, 5},
    {"[a-c]+", "zzAbC", REG_EXTENDED | REG_ICASE, 0, 0, 2, 5},
    {"a.b", "xa\nb aYb", REG_EXTENDED | REG_NEWLINE, 0, 0, 5, 8},
    {"a[^x]b", "xa\nb aYb", REG_EXTENDED | REG_NEWLINE, 0, 0, 5, 8},
    {"^b", "a\nb", REG_EXTENDED | REG_NEWLINE, REG_NOTBOL, 0, 2, 3},
    {"b$", "b\nc", REG_EXTENDED | REG_NEWLINE, REG_NOTEOL, 0, 0, 1},
    {"^b", "b", REG_EXTENDED, REG_NOTBOL, REG_NOMATCH, -1, -1},
    {"b$", "b", REG_EXTENDED, REG_NOTEOL, REG_NOMATCH, -1, -1},
    {"a.", "xa\303\251", REG_EXTENDED, 0, 0, 1, 3},
    {"b", "a\0b", REG_EXTENDED, 0, REG_NOMATCH, -1, -1},
};

struct differential_error {
    const char *pattern;
    int cflags;
    int error;
};

static const struct differential_error differential_errors[] = {
    {"abc\\", REG_EXTENDED, REG_EESCAPE},
    {"[abc", REG_EXTENDED, REG_EBRACK},
    {"[z-a]", REG_EXTENDED, REG_ERANGE},
    {"*abc", REG_EXTENDED, REG_BADRPT},
};

static void trace_hex(char *output, unsigned value, unsigned digits)
{
    static const char hex[] = "0123456789abcdef";
    while (digits != 0) {
        --digits;
        output[digits] = hex[value & 15];
        value >>= 4;
    }
}

/* Use the same Linux write syscall in both binaries so the freestanding
 * candidate needs no stdio, allocator, or additional C ABI symbol. */
static int trace_result(unsigned case_index, int result,
    const regmatch_t *matches)
{
    char output[30];
    long written;
    unsigned index;

    trace_hex(output, case_index, 2);
    output[2] = ':';
    trace_hex(output + 3, (unsigned)result, 2);
    output[5] = ':';
    for (index = 0; index < 3; ++index) {
        regoff_t start = result == 0 ? matches[index].rm_so : -1;
        regoff_t end = result == 0 ? matches[index].rm_eo : -1;
        trace_hex(output + 6 + index * 8, (unsigned)start, 3);
        output[9 + index * 8] = ',';
        trace_hex(output + 10 + index * 8, (unsigned)end, 3);
        output[13 + index * 8] = ':';
    }
    output[29] = '\n';
    __asm__ volatile("syscall" : "=a"(written) : "a"(1L), "D"(1L),
        "S"(output), "d"(30L) : "rcx", "r11", "memory");
    return written == 30 ? 0 : 1;
}

static int check_differential_cases(void)
{
    size_t index;
    for (index = 0; index < sizeof differential_cases / sizeof differential_cases[0];
        ++index) {
        const struct differential_case *test = &differential_cases[index];
        regex_t compiled;
        regmatch_t matches[3] = {{91, 92}, {93, 94}, {95, 96}};
        int result = regcomp(&compiled, test->pattern, test->cflags);
        if (result != 0 || compiled.re_nsub != 0) return 1 + (int)index;
        result = regexec(&compiled, test->subject, 3, matches, test->eflags);
        regfree(&compiled);
        if (result != test->result) return 32 + (int)index;
        if (result == 0 &&
            (matches[0].rm_so != test->start || matches[0].rm_eo != test->end ||
            matches[1].rm_so != -1 || matches[1].rm_eo != -1 ||
            matches[2].rm_so != -1 || matches[2].rm_eo != -1))
            return 64 + (int)index;
        if (trace_result((unsigned)index, result, matches))
            return 96 + (int)index;
    }
    for (index = 0; index < sizeof differential_errors / sizeof differential_errors[0];
        ++index) {
        const struct differential_error *test = &differential_errors[index];
        regex_t compiled;
        int result = regcomp(&compiled, test->pattern, test->cflags);
        if (result == 0) regfree(&compiled);
        if (result != test->error) return 128 + (int)index;
        if (trace_result(0x80 + (unsigned)index, result, (const regmatch_t *)0))
            return 160 + (int)index;
    }
    return 0;
}

static int check_common_behavior(void)
{
    regex_t compiled;
    regmatch_t untouched = {71, 72};
    char error[8];
    int result;

    if (compile_and_match("", 0, "abc", 0, 0, 0)) return 1;
    if (compile_and_match("^ab*c$", 0, "abbbc", 0, 0, 5)) return 2;
    if (compile_and_match("a.+z", REG_EXTENDED, "xxa12z--az", 0, 2, 10))
        return 3;
    if (compile_and_match("a.*a", REG_EXTENDED, "xxa12a3a", 0, 2, 8))
        return 4;
    if (compile_and_match("^[^0-9][a-c]*$", REG_EXTENDED, "Xabcc", 0, 0, 5))
        return 5;
    if (compile_and_match("^[a-f]+$", REG_EXTENDED | REG_ICASE,
            "aBcDeF", 0, 0, 6))
        return 6;
    if (compile_and_match("^b.$", REG_EXTENDED | REG_NEWLINE,
            "a\nbX\nc", REG_NOTBOL | REG_NOTEOL, 2, 4))
        return 7;
    if (compile_and_match("colou?r", REG_EXTENDED, "colour color", 0, 0, 6))
        return 8;
    if (compile_and_match("a+", 0, "xxa+yy", 0, 2, 4)) return 9;
    if (compile_and_match("a\\+b", REG_EXTENDED, "xxa+b", 0, 2, 5))
        return 10;
    if (compile_and_match("[]a]+", REG_EXTENDED, "x]aa", 0, 1, 4))
        return 11;
    if (compile_and_match("a*", REG_EXTENDED, "baaa", 0, 0, 0))
        return 12;
    if (compile_and_match("^b$", REG_EXTENDED | REG_NEWLINE,
            "a\nb\nc", REG_NOTBOL | REG_NOTEOL, 2, 3))
        return 13;

    result = regcomp(&compiled, "^abc$", REG_NOSUB);
    if (result != 0) return 14;
    result = regexec(&compiled, "abc", 1, &untouched, 0);
    regfree(&compiled);
    if (result != 0 || untouched.rm_so != 71 || untouched.rm_eo != 72)
        return 15;

    result = regcomp(&compiled, "^abc$", 0);
    if (result != 0) return 16;
    if (regexec(&compiled, "abc", 0, (regmatch_t *)0, REG_NOTBOL) != REG_NOMATCH ||
        regexec(&compiled, "abc", 0, (regmatch_t *)0, REG_NOTEOL) != REG_NOMATCH) {
        regfree(&compiled);
        return 17;
    }
    regfree(&compiled);

    if (expect_compile_error("abc\\", REG_EXTENDED, REG_EESCAPE)) return 18;
    if (expect_compile_error("[abc", REG_EXTENDED, REG_EBRACK)) return 19;
    if (expect_compile_error("[z-a]", REG_EXTENDED, REG_ERANGE)) return 20;
    if (expect_compile_error("*abc", REG_EXTENDED, REG_BADRPT)) return 21;

    if (regerror(REG_ERANGE, (const regex_t *)0, error, sizeof(error)) != 24 ||
        !bytes_equal(error, "Invalid", 7) || error[7] != '\0')
        return 22;
    if (regerror(99, (const regex_t *)0, error, 0) != 14) return 23;
    return 0;
}

#ifdef CRABC_REGEX_FREESTANDING
static int check_bounded_profile(void)
{
    static const char too_many_atoms[] =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static char too_long_input[4098];
    regex_t compiled;
    size_t index;

    if (expect_compile_error("(a)", REG_EXTENDED, REG_BADPAT)) return 1;
    if (expect_compile_error("a|b", REG_EXTENDED, REG_BADPAT)) return 2;
    if (expect_compile_error("a{2}", REG_EXTENDED, REG_BADPAT)) return 3;
    if (expect_compile_error("[[:digit:]]", REG_EXTENDED, REG_BADPAT)) return 4;
    if (expect_compile_error("\\(a\\)", 0, REG_BADPAT)) return 5;
    if (expect_compile_error(too_many_atoms, REG_EXTENDED, REG_ESPACE)) return 6;
    if (expect_compile_error("a", 0x10, REG_BADPAT)) return 7;

    if (regcomp(&compiled, "a", REG_EXTENDED) != 0) return 8;
    for (index = 0; index < sizeof(too_long_input) - 1; ++index)
        too_long_input[index] = 'a';
    too_long_input[sizeof(too_long_input) - 1] = '\0';
    if (regexec(&compiled, too_long_input, 0, (regmatch_t *)0, 0) != REG_ESPACE) {
        regfree(&compiled);
        return 9;
    }
    if (regexec(&compiled, "a", 0, (regmatch_t *)0, 0x04) != REG_BADPAT) {
        regfree(&compiled);
        return 10;
    }
    regfree(&compiled);
    return 0;
}
#endif

int crabc_x86_64_regex_probe(void)
{
    int result = check_common_behavior();
    if (result != 0) return result;
    result = check_differential_cases();
    if (result != 0) return 200 + result;
#ifdef CRABC_REGEX_FREESTANDING
    result = check_bounded_profile();
    if (result != 0) return 100 + result;
#endif
    return 0;
}

#ifndef CRABC_REGEX_FREESTANDING
int main(void)
{
    return crabc_x86_64_regex_probe();
}
#endif

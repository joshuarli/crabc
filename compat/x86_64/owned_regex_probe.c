/* One installed-header regex object for musl and the owned x86 runtime. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <locale.h>
#include <regex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef REG_STARTEND
#error "REG_STARTEND is not part of musl's installed regex interface"
#endif

typedef int (*regcomp_signature)(regex_t *__restrict,
    const char *__restrict, int);
typedef int (*regexec_signature)(const regex_t *__restrict,
    const char *__restrict, size_t, regmatch_t *__restrict, int);
typedef void (*regfree_signature)(regex_t *);
typedef size_t (*regerror_signature)(int, const regex_t *__restrict,
    char *__restrict, size_t);

_Static_assert(sizeof(regoff_t) == sizeof(long),
    "installed x86 regoff_t is the signed LP64 long ABI");
_Static_assert(_Alignof(regoff_t) == _Alignof(long),
    "installed x86 regoff_t alignment");
_Static_assert((regoff_t)-1 < (regoff_t)0,
    "installed x86 regoff_t must remain signed");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regcomp),
    regcomp_signature), "installed regcomp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regexec),
    regexec_signature), "installed regexec declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regfree),
    regfree_signature), "installed regfree declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&regerror),
    regerror_signature), "installed regerror declaration");

static regcomp_signature public_regcomp = regcomp;
static regexec_signature public_regexec = regexec;
static regfree_signature public_regfree = regfree;
static regerror_signature public_regerror = regerror;

static void fail(void) { _Exit(127); }
#define CHECK(expression) do { if (!(expression)) fail(); } while (0)

static void expect_match(const char *name, const char *pattern, int cflags,
    const char *text, size_t nmatch, const regmatch_t *expected,
    size_t expected_submatches)
{
    regex_t compiled;
    regmatch_t actual[4];
    size_t index;

    CHECK(nmatch <= sizeof actual / sizeof *actual);
    memset(actual, 0x5a, sizeof actual);
    CHECK(public_regcomp(&compiled, pattern, cflags) == REG_OK);
    CHECK(compiled.re_nsub == expected_submatches);
    CHECK(public_regexec(&compiled, text, nmatch, actual, 0) == REG_OK);
    for (index = 0; index != nmatch; ++index) {
        CHECK(actual[index].rm_so == expected[index].rm_so);
        CHECK(actual[index].rm_eo == expected[index].rm_eo);
    }
    printf("match %s nsub=%zu so=%ld eo=%ld\n", name, compiled.re_nsub,
        (long)actual[0].rm_so, (long)actual[0].rm_eo);
    public_regfree(&compiled);
}

static void expect_no_match(const char *name, const char *pattern, int cflags,
    const char *text, int eflags)
{
    regex_t compiled;

    CHECK(public_regcomp(&compiled, pattern, cflags) == REG_OK);
    CHECK(public_regexec(&compiled, text, 0, 0, eflags) == REG_NOMATCH);
    public_regfree(&compiled);
    printf("nomatch %s\n", name);
}

static void check_nosub(void)
{
    regex_t compiled;
    regmatch_t untouched = {71, 72};

    CHECK(public_regcomp(&compiled, "^abc$", REG_NOSUB) == REG_OK);
    CHECK(public_regexec(&compiled, "abc", 1, &untouched, 0) == REG_OK);
    CHECK(untouched.rm_so == 71 && untouched.rm_eo == 72);
    public_regfree(&compiled);
    puts("nosub-preserves-pmatch");
}

static void check_compile_and_free(void)
{
    regex_t compiled;
    regmatch_t actual[2];

    CHECK(public_regcomp(&compiled, "(ab|a)(b?)", REG_EXTENDED) == REG_OK);
    CHECK(compiled.re_nsub == 2);
    public_regfree(&compiled);

    /* `regfree` releases the completed TNFA graph.  A subsequent `regcomp`
     * overwrites the public output record before a new graph is exposed. */
    CHECK(public_regcomp(&compiled, "(a|b)+", REG_EXTENDED) == REG_OK);
    CHECK(public_regexec(&compiled, "zab", 2, actual, 0) == REG_OK);
    CHECK(actual[0].rm_so == 1 && actual[0].rm_eo == 3);
    CHECK(actual[1].rm_so == 2 && actual[1].rm_eo == 3);
    public_regfree(&compiled);
    puts("compile-regfree-recompile");
}

static void check_errors(void)
{
    regex_t compiled;
    char complete[32];
    char bounded[4];
    char unknown[14];

    CHECK(public_regcomp(&compiled, "[", REG_EXTENDED) == REG_EBRACK);
    CHECK(public_regerror(REG_EBRACK, 0, complete, sizeof complete) == 12);
    CHECK(!memcmp(complete, "Missing ']'", 11) && complete[11] == '\0');
    CHECK(public_regerror(REG_EBRACK, 0, bounded, sizeof bounded) == 12);
    CHECK(!memcmp(bounded, "Mis", 3) && bounded[3] == '\0');
    CHECK(public_regerror(-1, 0, unknown, sizeof unknown) == 14);
    CHECK(!memcmp(unknown, "Unknown error", 13) && unknown[13] == '\0');
    puts("regerror-table-and-truncation");
}

int main(void)
{
    static const regmatch_t longest[] = {{1, 3}};
    static const regmatch_t captures[] = {{1, 3}, {2, 3}};
    static const regmatch_t backreference[] = {{1, 3}, {1, 2}};
    static const regmatch_t empty_backreference[] = {{0, 0}, {0, 0}};
    static const regmatch_t newline_anchor[] = {{0, 1}};
    static const regmatch_t class_match[] = {{2, 4}};
    static const regmatch_t icase_match[] = {{0, 1}};
    static const char utf8_text[] = {
        'z', (char)0xc3, (char)0xa9, (char)0xc3, (char)0xa9, 'x', '\0',
    };
    static const char utf8_pattern[] = {(char)0xc3, (char)0xa9, '+', '\0'};
    static const regmatch_t utf8_match[] = {{1, 5}};

    CHECK(setlocale(LC_ALL, "C.UTF-8") != NULL);
    expect_match("ere-leftmost-longest", "a|ab", REG_EXTENDED, "zab", 1,
        longest, 0);
    expect_match("ere-captures", "(a|b)+", REG_EXTENDED, "zab", 2,
        captures, 1);
    expect_match("bre-backreference", "\\(a\\)\\1", 0, "zaa", 2,
        backreference, 1);
    expect_match("bre-empty-backreference", "\\(a*\\)\\1", 0, "", 2,
        empty_backreference, 1);
    expect_match("newline-anchor", "^a$", REG_EXTENDED | REG_NEWLINE,
        "a\nx", 1, newline_anchor, 0);
    expect_match("negated-class", "[^[:digit:]]+", REG_EXTENDED, "10xy2", 1,
        class_match, 0);
    expect_match("icase", "[a]", REG_EXTENDED | REG_ICASE, "A", 1,
        icase_match, 0);
    expect_match("utf8-byte-offsets", utf8_pattern, REG_EXTENDED, utf8_text, 1,
        utf8_match, 0);
    expect_no_match("notbol", "^a", REG_EXTENDED, "a", REG_NOTBOL);
    expect_no_match("noteol", "a$", REG_EXTENDED, "a", REG_NOTEOL);
    check_nosub();
    check_compile_and_free();
    check_errors();
    puts("owned-regex-installed-header-ok");
    return 0;
}

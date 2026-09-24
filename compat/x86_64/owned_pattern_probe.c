/*
 * Source-bound C witness for musl 1.2.6 `src/regex/{fnmatch,glob}.c`.
 *
 * The runner supplies `/fixture` and `/etc/passwd` inside a disposable
 * chroot.  This consumes the installed public fnmatch.h/glob.h records and
 * runs one identical workload object under pinned musl and every owned
 * product.  In particular, tilde expansion reaches the standard passwd ABI;
 * it does not admit a test-local parser or host account database.
 *
 * Word-expansion preflight belongs to owned_wordexp_probe.c's nocmd-source
 * selector, whose reader checks the candidate and fixed-musl classifications
 * separately. This filename-pattern witness compares fnmatch/glob behavior.
 */
#include <dirent.h>
#include <errno.h>
#include <fnmatch.h>
#include <glob.h>
#include <locale.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int failure_line;

#define CHECK(condition) do { \
    if (!(condition)) { \
        failure_line = __LINE__; \
        return -1; \
    } \
} while (0)

static int vector_is(const glob_t *result, const char *const expected[], size_t count)
{
    size_t index;

    CHECK(result->gl_pathc == count);
    CHECK(result->gl_pathv != 0);
    for (index = 0; index < count; index++) {
        CHECK(result->gl_pathv[result->gl_offs + index] != 0);
        CHECK(!strcmp(result->gl_pathv[result->gl_offs + index], expected[index]));
    }
    CHECK(result->gl_pathv[result->gl_offs + count] == 0);
    return 0;
}

static int vector_contains(const glob_t *result, const char *expected)
{
    size_t index;

    for (index = 0; index < result->gl_pathc; index++) {
        if (!strcmp(result->gl_pathv[result->gl_offs + index], expected)) return 1;
    }
    return 0;
}

/* These narrow selector cases run in separate chroot children. They retain
 * the regression boundary when one source-control-flow error would otherwise
 * prevent a later matcher case from executing. */
static int matcher_escaped_wildcard_cases(void)
{
    CHECK(setlocale(LC_CTYPE, "C") != 0);
    CHECK(fnmatch("a\\*", "a*", 0) == 0);
    CHECK(fnmatch("a\\*", "ax", 0) == FNM_NOMATCH);
    CHECK(fnmatch("a\\?", "a?", 0) == 0);
    CHECK(fnmatch("a\\?", "ax", 0) == FNM_NOMATCH);
    return 0;
}

static int matcher_range_case(void)
{
    CHECK(setlocale(LC_CTYPE, "C") != 0);
    CHECK(fnmatch("[a-z]", "0", 0) == FNM_NOMATCH);
    return 0;
}

static int matcher_nested_class_case(void)
{
    CHECK(setlocale(LC_CTYPE, "C") != 0);
    CHECK(fnmatch("[[:digit:]a]", "a", 0) == 0);
    return 0;
}

static int matcher_c_and_posix_cases(void)
{
    CHECK(setlocale(LC_CTYPE, "C") != 0);
    CHECK(fnmatch("a?c", "abc", 0) == 0);
    CHECK(fnmatch("a?c", "ac", 0) == FNM_NOMATCH);
    CHECK(fnmatch("*.c", "dir/a.c", FNM_PATHNAME) == FNM_NOMATCH);
    CHECK(fnmatch("*", "dir/a.c", 0) == 0);
    CHECK(fnmatch("a/*", "a/b", FNM_PATHNAME) == 0);
    CHECK(fnmatch("a/*", "a/b/c", FNM_PATHNAME) == FNM_NOMATCH);
    CHECK(fnmatch("a/*", "a/.hidden", FNM_PATHNAME | FNM_PERIOD) == FNM_NOMATCH);
    CHECK(fnmatch("a/.*", "a/.hidden", FNM_PATHNAME | FNM_PERIOD) == 0);
    CHECK(fnmatch("*", ".dot", FNM_PERIOD) == FNM_NOMATCH);
    CHECK(fnmatch(".*", ".dot", FNM_PERIOD) == 0);
    CHECK(matcher_escaped_wildcard_cases() == 0);
    CHECK(fnmatch("a\\*", "a*", FNM_NOESCAPE) == FNM_NOMATCH);
    CHECK(fnmatch("tail\\", "tail\\", 0) == 0);
    CHECK(fnmatch("[!a]", "b", 0) == 0);
    CHECK(fnmatch("[!a]", "a", 0) == FNM_NOMATCH);
    CHECK(fnmatch("[]a]", "]", 0) == 0);
    CHECK(fnmatch("[-a]", "-", 0) == 0);
    CHECK(fnmatch("[[:digit:]]", "7", 0) == 0);
    CHECK(fnmatch("[[:digit:]]", "z", 0) == FNM_NOMATCH);
    CHECK(matcher_range_case() == 0);
    CHECK(matcher_nested_class_case() == 0);
    CHECK(fnmatch("abc", "abc/rest", FNM_LEADING_DIR) == 0);
    CHECK(fnmatch("abc", "abc/rest", FNM_PATHNAME | FNM_LEADING_DIR) == 0);
    CHECK(fnmatch("AbC", "aBc", FNM_CASEFOLD) == 0);
    CHECK(fnmatch("[A-Z]", "a", FNM_CASEFOLD) == 0);
    CHECK(setlocale(LC_CTYPE, "POSIX") != 0);
    CHECK(fnmatch("[[:alpha:]]", "z", 0) == 0);
    CHECK(fnmatch("[[:alpha:]]", "7", 0) == FNM_NOMATCH);
    return 0;
}

static int matcher_utf8_and_invalid_cases(void)
{
    CHECK(setlocale(LC_CTYPE, "C.UTF-8") != 0);
    CHECK(fnmatch("\303\205", "\303\245", FNM_CASEFOLD) == 0);
    CHECK(fnmatch("[[:alpha:]]", "\303\251", 0) == 0);
    CHECK(fnmatch("[[:alpha:]]", "\303\227", 0) == FNM_NOMATCH);
    CHECK(fnmatch("[\303\200-\303\205]", "\303\204", 0) == 0);
    CHECK(fnmatch("*", "\377", 0) == 0);
    CHECK(fnmatch("?", "\377", 0) == FNM_NOMATCH);
    CHECK(fnmatch("\377", "x", 0) == FNM_NOMATCH);
    CHECK(fnmatch("\303", "\303", 0) == FNM_NOMATCH);
    CHECK(fnmatch("*x", "\303x", 0) == 0);
    return 0;
}

static int direct_directory_order(char entries[][32], size_t *count)
{
    DIR *directory;
    struct dirent *entry;

    directory = opendir("/fixture");
    CHECK(directory != 0);
    *count = 0;
    while ((entry = readdir(directory)) != 0) {
        if (!strcmp(entry->d_name, "a.txt") || !strcmp(entry->d_name, "b.txt")
            || !strcmp(entry->d_name, "z.txt")) {
            CHECK(*count < 3);
            strcpy(entries[*count], entry->d_name);
            (*count)++;
        }
    }
    CHECK(closedir(directory) == 0);
    CHECK(*count == 3);
    return 0;
}

static int glob_literal_path_case(void)
{
    static const char *const literal[] = { "/fixture/a.txt" };
    glob_t result = { 0 };

    /* The literal-prefix loop writes each source byte at buf[pos + j]. */
    CHECK(glob("/fixture/a.txt", 0, 0, &result) == 0);
    CHECK(vector_is(&result, literal, 1) == 0);
    globfree(&result);
    return 0;
}

static int glob_nested_path_case(void)
{
    static const char *const nested[] = {
        "/fixture/dir/child.txt",
        "/fixture/link-dir/child.txt",
    };
    glob_t result = { 0 };

    /* A recursive component retains the separator so the next do_glob call
     * consumes it into the pathname before matching the next component. */
    CHECK(glob("/fixture/*dir*/*.txt", 0, 0, &result) == 0);
    CHECK(vector_is(&result, nested, 2) == 0);
    globfree(&result);
    return 0;
}

static int glob_basic_sort_and_memory_cases(void)
{
    static const char *const sorted[] = {
        "/fixture/a.txt", "/fixture/b.txt", "/fixture/z.txt",
    };
    char ordered_names[3][32];
    size_t ordered_count;
    size_t index;
    glob_t result = { 0 };

    CHECK(direct_directory_order(ordered_names, &ordered_count) == 0);
    errno = E2BIG;
    CHECK(glob("/fixture/*.txt", 0, 0, &result) == 0);
    CHECK(errno == E2BIG);
    CHECK(vector_is(&result, sorted, 3) == 0);
    globfree(&result);
    CHECK(result.gl_pathc == 0 && result.gl_pathv == 0 && result.gl_offs == 0);

    CHECK(glob("/fixture/*.txt", GLOB_NOSORT, 0, &result) == 0);
    CHECK(result.gl_pathc == ordered_count && result.gl_pathv != 0);
    for (index = 0; index < ordered_count; index++) {
        char expected[64];
        snprintf(expected, sizeof expected, "/fixture/%s", ordered_names[index]);
        CHECK(!strcmp(result.gl_pathv[index], expected));
    }
    globfree(&result);

    /* Repeated allocation and release proves the source's flexible Match
     * ownership recovery rather than merely observing one result vector. */
    for (index = 0; index < 32; index++) {
        void *allocation;
        CHECK(glob("/fixture/[ab].txt", 0, 0, &result) == 0);
        CHECK(result.gl_pathc == 2);
        globfree(&result);
        CHECK(result.gl_pathc == 0 && result.gl_pathv == 0);
        allocation = malloc(97);
        CHECK(allocation != 0);
        memset(allocation, (int)index, 97);
        free(allocation);
    }
    return 0;
}

static int glob_offset_append_and_nocheck_cases(void)
{
    static const char *const initial[] = { "/fixture/a.txt" };
    static const char *const appended[] = { "/fixture/a.txt", "/fixture/b.txt" };
    glob_t result = { 0 };

    result.gl_offs = 2;
    CHECK(glob("/fixture/a.txt", GLOB_DOOFFS, 0, &result) == 0);
    CHECK(result.gl_pathv[0] == 0 && result.gl_pathv[1] == 0);
    CHECK(vector_is(&result, initial, 1) == 0);
    CHECK(glob("/fixture/b.txt", GLOB_DOOFFS | GLOB_APPEND, 0, &result) == 0);
    CHECK(result.gl_pathv[0] == 0 && result.gl_pathv[1] == 0);
    CHECK(vector_is(&result, appended, 2) == 0);
    globfree(&result);
    CHECK(result.gl_pathc == 0 && result.gl_pathv == 0 && result.gl_offs == 2);

    CHECK(glob("/fixture/missing", GLOB_NOCHECK, 0, &result) == 0);
    CHECK(result.gl_pathc == 1 && !strcmp(result.gl_pathv[0], "/fixture/missing"));
    globfree(&result);
    CHECK(glob("", GLOB_NOCHECK, 0, &result) == 0);
    CHECK(result.gl_pathc == 1 && !strcmp(result.gl_pathv[0], ""));
    globfree(&result);
    CHECK(glob("", 0, 0, &result) == GLOB_NOMATCH);
    globfree(&result);
    return 0;
}

static int glob_period_escape_mark_and_trailing_cases(void)
{
    static const char *const directory[] = { "/fixture/dir/" };
    glob_t result = { 0 };

    CHECK(glob("/fixture/*", 0, 0, &result) == 0);
    CHECK(!vector_contains(&result, "/fixture/.hidden"));
    globfree(&result);
    CHECK(glob("/fixture/*", GLOB_PERIOD, 0, &result) == 0);
    CHECK(vector_contains(&result, "/fixture/.hidden"));
    CHECK(vector_contains(&result, "/fixture/.") && vector_contains(&result, "/fixture/.."));
    globfree(&result);

    CHECK(glob("/fixture/star\\*", 0, 0, &result) == 0);
    CHECK(result.gl_pathc == 1 && !strcmp(result.gl_pathv[0], "/fixture/star*"));
    globfree(&result);
    CHECK(glob("/fixture/star\\*", GLOB_NOESCAPE, 0, &result) == GLOB_NOMATCH);
    globfree(&result);

    CHECK(glob("/fixture/dir", GLOB_MARK, 0, &result) == 0);
    CHECK(vector_is(&result, directory, 1) == 0);
    globfree(&result);
    CHECK(glob("/fixture/link-dir", GLOB_MARK, 0, &result) == 0);
    CHECK(vector_is(&result, (const char *const[]){ "/fixture/link-dir/" }, 1) == 0);
    globfree(&result);
    CHECK(glob("/fixture/dir/", 0, 0, &result) == 0);
    CHECK(vector_is(&result, directory, 1) == 0);
    globfree(&result);
    CHECK(glob("/fixture/a.txt/", 0, 0, &result) == GLOB_NOMATCH);
    globfree(&result);
    return 0;
}

static int glob_dangling_mark_case(void)
{
    static const char *const dangling[] = { "/fixture/dangling" };
    glob_t result = { 0 };

    /* musl's failed stat of a dangling link publishes ENOENT even though the
     * following lstat verifies the link and returns it unmarked. */
    errno = E2BIG;
    CHECK(glob("/fixture/dangling", GLOB_MARK, 0, &result) == 0);
    CHECK(errno == ENOENT);
    CHECK(vector_is(&result, dangling, 1) == 0);
    globfree(&result);
    return 0;
}

static int glob_tilde_cases(void)
{
    glob_t result = { 0 };

    CHECK(glob("~/home.txt", GLOB_TILDE, 0, &result) == 0);
    CHECK(result.gl_pathc == 1 && !strcmp(result.gl_pathv[0], "/fixture/home/home.txt"));
    globfree(&result);
    CHECK(glob("~tester/user.txt", GLOB_TILDE, 0, &result) == 0);
    CHECK(result.gl_pathc == 1 && !strcmp(result.gl_pathv[0], "/fixture/userhome/user.txt"));
    globfree(&result);
    CHECK(glob("~/home.txt", 0, 0, &result) == GLOB_NOMATCH);
    globfree(&result);
    CHECK(glob("~missing/nope", GLOB_TILDE, 0, &result) == GLOB_NOMATCH);
    globfree(&result);
    CHECK(glob("~missing/nope", GLOB_TILDE_CHECK, 0, &result) == GLOB_NOMATCH);
    globfree(&result);
    return 0;
}

static int error_calls;
static int error_code;
static int error_return;
static char error_path[128];

static int capture_error(const char *path, int code)
{
    error_calls++;
    error_code = code;
    if (path) {
        strncpy(error_path, path, sizeof error_path - 1);
        error_path[sizeof error_path - 1] = 0;
    }
    return error_return;
}

static int glob_unreadable_error_cases(void)
{
    glob_t result = { 0 };

    CHECK(setgid(65534) == 0);
    CHECK(setuid(65534) == 0);
    error_calls = 0;
    error_code = 0;
    error_return = 0;
    error_path[0] = 0;
    CHECK(glob("/fixture/blocked/*", 0, capture_error, &result) == GLOB_NOMATCH);
    CHECK(error_calls == 1 && error_code == EACCES);
    CHECK(!strcmp(error_path, "/fixture/blocked/"));
    CHECK(result.gl_pathc == 0 && result.gl_pathv == 0);
    globfree(&result);

    error_calls = 0;
    error_return = 0;
    CHECK(glob("/fixture/blocked/*", GLOB_ERR, capture_error, &result) == GLOB_ABORTED);
    CHECK(error_calls == 1 && error_code == EACCES);
    CHECK(result.gl_pathc == 0 && result.gl_pathv != 0);
    globfree(&result);

    error_calls = 0;
    error_return = 1;
    CHECK(glob("/fixture/blocked/*", 0, capture_error, &result) == GLOB_ABORTED);
    CHECK(error_calls == 1 && error_code == EACCES);
    globfree(&result);
    return 0;
}

/*
 * Deterministic differential corpus.
 *
 * The directed cases above name individual contracts; this corpus checks that
 * the owned translation reproduces pinned musl across the selected grammar.
 * `fnmatch-corpus` runs fixed and fixed-seed generated patterns built from
 * literals, `?`, `*`, escapes, brackets (negation, ranges, reversed ranges,
 * leading `]`/`-`, classes, collating and equivalence spellings, unterminated
 * forms), slashes, periods, UTF-8, and invalid bytes against fixed and
 * generated subjects under all 32 combinations of FNM_PATHNAME, FNM_NOESCAPE,
 * FNM_PERIOD, FNM_LEADING_DIR, and FNM_CASEFOLD in both C and C.UTF-8.
 * `glob-corpus` expands fixed and generated patterns over the runner's
 * `/corpus/outer/inner/tree`, absolute and relative to it, under combinations of
 * GLOB_MARK, GLOB_NOCHECK, GLOB_NOESCAPE, GLOB_PERIOD, GLOB_ERR, GLOB_NOSORT,
 * GLOB_DOOFFS, GLOB_TILDE, and GLOB_TILDE_CHECK in both C and C.UTF-8, with an
 * error callback that continues or aborts.  GLOB_NOSORT results are folded
 * in sorted order because directory order belongs to the filesystem, not to
 * the implementation.
 *
 * Every result folds into a 64-bit FNV-1a digest printed once per block; the
 * runner compares the complete transcript with pinned musl.  The `-trace`
 * selector spellings print each observation to localize a divergence.
 */
#ifndef CORPUS_SEED
#define CORPUS_SEED 0x9e3779b97f4a7c15ULL
#endif

enum { CORPUS_BLOCK = 1000 };

struct corpus_state {
    unsigned long long random;
    unsigned long long digest;
    int trace;
    unsigned long calls;
    unsigned long matches;
};

static unsigned corpus_next(struct corpus_state *state)
{
    unsigned long long x = state->random;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    state->random = x;
    return (unsigned)((x * 0x2545f4914f6cdd1dULL) >> 32);
}

static void corpus_fold_bytes(struct corpus_state *state, const void *bytes, size_t size)
{
    const unsigned char *cursor = bytes;

    while (size--) {
        state->digest ^= *cursor++;
        state->digest *= 0x100000001b3ULL;
    }
}

static void corpus_fold(struct corpus_state *state, long value)
{
    corpus_fold_bytes(state, &value, sizeof value);
}

static void corpus_fold_string(struct corpus_state *state, const char *text)
{
    corpus_fold_bytes(state, text, strlen(text) + 1);
}

static int corpus_append(char *buffer, size_t capacity, size_t *length, const char *piece)
{
    size_t size = strlen(piece);

    CHECK(*length + size < capacity);
    memcpy(buffer + *length, piece, size);
    *length += size;
    buffer[*length] = 0;
    return 0;
}

static void corpus_trace_bytes(const char *label, const char *bytes)
{
    const unsigned char *cursor = (const unsigned char *)bytes;

    printf(" %s=", label);
    if (!*cursor) printf("-");
    for (; *cursor; ++cursor) printf("%02x", *cursor);
}

static void corpus_block(struct corpus_state *state, const char *name, const char *locale, size_t block)
{
    printf("corpus %s locale=%s block=%zu digest=%016llx\n", name, locale, block, state->digest);
    state->digest = 0xcbf29ce484222325ULL;
}

static const char *const fnmatch_fixed_patterns[] = {
    "", "*", "?", "a", "a*", "*a", "a*b", "*a*", "a?b", "??", "***", "a**b",
    "\\", "\\\\", "\\*", "\\?", "\\[", "a\\", "[", "[]", "[]]", "[]a]", "[!]a]",
    "[^]a]", "[!a]", "[^a]", "[a-c]", "[c-a]", "[a-]", "[-a]", "[!-]", "[a-c-e]",
    "[]-a]", "[\\]]", "[\\a]", "[a\\]", "[[]", "[[:alpha:]]", "[[:digit:]a]",
    "[![:alpha:]]", "[[:upper:][:digit:]]", "[[:foo:]]", "[[:alpha:]",
    "[[:alpha", "[[.a.]]", "[[=a=]]", "[[.a", "[[:xdigit:]]*", "[a/b]", "a/b",
    "a/*", "*/b", "*/*", "a/", "/a", ".*", "*.c", ".", "..", "a/.*", "a/[.]b",
    "[.]a", "\\.a", "a/\\.b", "[A-Z]", "[a-z]*", "*[[:space:]]*", "*[!a-z]",
    "\303\251", "\303\211", "[\303\251]", "[\303\200-\303\277]", "[!\303\251]",
    "*\303\251*", "?\303\251", "\377", "*\377", "[\377]", "\303", "[\303]",
    "a[", "a[b", "*[", "[[:alpha:][:punct:]]", "[[:lower:]]*[[:upper:]]",
    "abc/*/d", "*/[!.]*",
};

/* Each pattern token carries a subject spelling it usually matches, so the
 * generated corpus exercises successful as well as failing matches. */
static const char *const fnmatch_pattern_tokens[][2] = {
    {"a", "a"}, {"b", "b"}, {"A", "a"}, {"B", "B"}, {"c", "c"}, {".", "."},
    {"/", "/"}, {"-", "-"}, {"*", ""}, {"*", "ab"}, {"*", "a/."}, {"?", "x"},
    {"?", "/"}, {"\\", "\\"}, {"\\*", "*"}, {"\\?", "?"}, {"\\[", "["},
    {"\\a", "a"}, {"\\/", "/"}, {"[", "["}, {"]", "]"}, {"[ab]", "b"},
    {"[!a]", "c"}, {"[^a]", "a"}, {"[]a]", "]"}, {"[a-c]", "B"}, {"[A-Z]", "q"},
    {"[z-a]", "m"}, {"[-a]", "-"}, {"[a-]", "-"}, {"[[:alpha:]]", "Z"},
    {"[[:digit:]]", "7"}, {"[[:upper:]]", "a"}, {"[[:lower:]]", "A"},
    {"[[:space:]]", " "}, {"[[:punct:]]", "."}, {"[[:foo:]]", "f"},
    {"[[.a.]]", "a"}, {"[[=a=]]", "="}, {"[[:alpha:]", "["}, {"[\\]]", "]"},
    {"[a/b]", "/"}, {"[.]", "."}, {"[!/]", "/"}, {"\303\251", "\303\211"},
    {"\303\211", "\303\211"}, {"[\303\251-\303\277]", "\303\266"},
    {"\377", "\377"}, {"\303", "\303"}, {"[\377]", "\377"},
};

static const char *const fnmatch_subject_atoms[] = {
    "a", "b", "A", "B", "c", ".", "/", "\\", "*", "?", "[", "]", "-", " ",
    "7", "\303\251", "\303\211", "\377", "\303", "x", "ab",
};

static const char *const fnmatch_fixed_subjects[] = {
    "", "a", "ab", "abc", "a/b", "a/b/c", ".a", "a/.b", "..", "A", "aB/c",
    "[", "]", "\\", "*", "a*b", "\303\251", "\303\211x", "\377", "\303",
    "x\303", " \t", "abc/x/d", "-",
};

static void fnmatch_observe(struct corpus_state *state, const char *pattern,
    const char *subject)
{
    /* musl never returns from FNM_PATHNAME when its component scan reaches an
     * invalid multibyte pattern character (`fnmatch-pathname-unmatchable`),
     * so FNM_PATHNAME skips any pattern that is not valid in this locale. */
    int pathname = mbstowcs(0, pattern, 0) != (size_t)-1;
    int flags;

    for (flags = 0; flags != 32; ++flags) {
        int selected = ((flags & 1) ? FNM_PATHNAME : 0) | ((flags & 2) ? FNM_NOESCAPE : 0)
            | ((flags & 4) ? FNM_PERIOD : 0) | ((flags & 8) ? FNM_LEADING_DIR : 0)
            | ((flags & 16) ? FNM_CASEFOLD : 0);
        int result;

        if ((selected & FNM_PATHNAME) && !pathname) continue;
        result = fnmatch(pattern, subject, selected);

        ++state->calls;
        if (!result) ++state->matches;
        corpus_fold(state, result);
        if (state->trace) {
            printf("fnmatch-trace");
            corpus_trace_bytes("pattern", pattern);
            corpus_trace_bytes("subject", subject);
            printf(" flags=%d result=%d\n", selected, result);
        }
    }
}

static int fnmatch_generated_subject(struct corpus_state *state, char *buffer, size_t capacity)
{
    size_t length = 0;
    unsigned count = corpus_next(state) % 7;

    buffer[0] = 0;
    while (count--)
        CHECK(corpus_append(buffer, capacity, &length, fnmatch_subject_atoms[corpus_next(state)
            % (sizeof fnmatch_subject_atoms / sizeof *fnmatch_subject_atoms)]) == 0);
    return 0;
}

static int fnmatch_corpus_locale(const char *locale, int trace)
{
    struct corpus_state state;
    size_t pattern;
    size_t subject;

    CHECK(setlocale(LC_CTYPE, locale) != 0);
    memset(&state, 0, sizeof state);
    state.random = CORPUS_SEED;
    state.digest = 0xcbf29ce484222325ULL;
    state.trace = trace;
    for (pattern = 0; pattern != sizeof fnmatch_fixed_patterns / sizeof *fnmatch_fixed_patterns; ++pattern)
        for (subject = 0; subject != sizeof fnmatch_fixed_subjects / sizeof *fnmatch_fixed_subjects; ++subject)
            fnmatch_observe(&state, fnmatch_fixed_patterns[pattern], fnmatch_fixed_subjects[subject]);
    corpus_block(&state, "fnmatch-fixed", locale, 0);
    for (pattern = 0; pattern != 16 * CORPUS_BLOCK; ++pattern) {
        char text[128];
        char generated[64];
        size_t length = 0;
        unsigned tokens = 1 + corpus_next(&state) % 6;

        char sample[128];
        size_t sample_length = 0;

        text[0] = 0;
        sample[0] = 0;
        while (tokens--) {
            const char *const *token = fnmatch_pattern_tokens[corpus_next(&state)
                % (sizeof fnmatch_pattern_tokens / sizeof *fnmatch_pattern_tokens)];

            CHECK(corpus_append(text, sizeof text, &length, token[0]) == 0);
            CHECK(corpus_append(sample, sizeof sample, &sample_length, token[1]) == 0);
        }
        fnmatch_observe(&state, text, sample);
        for (subject = 0; subject != 4; ++subject) {
            CHECK(fnmatch_generated_subject(&state, generated, sizeof generated) == 0);
            fnmatch_observe(&state, text, generated);
        }
        fnmatch_observe(&state, text, fnmatch_fixed_subjects[corpus_next(&state)
            % (sizeof fnmatch_fixed_subjects / sizeof *fnmatch_fixed_subjects)]);
        if ((pattern + 1) % CORPUS_BLOCK == 0)
            corpus_block(&state, "fnmatch-random", locale, pattern / CORPUS_BLOCK);
    }
    printf("corpus fnmatch locale=%s calls=%lu matches=%lu\n", locale, state.calls, state.matches);
    return 0;
}

static int fnmatch_corpus(int trace)
{
    CHECK(fnmatch_corpus_locale("C", trace) == 0);
    CHECK(fnmatch_corpus_locale("C.UTF-8", trace) == 0);
    return 0;
}

/*
 * `fnmatch-pathname-unmatchable`: FNM_PATHNAME over an invalid pattern byte.
 *
 * musl's FNM_PATHNAME component scan advances by `pat_next`'s step, which is
 * zero for an invalid multibyte pattern character (UNMATCHABLE), so it never
 * returns once the scan reaches one.  Without FNM_PATHNAME the same character
 * makes fnmatch_internal return FNM_NOMATCH, and a component containing it can
 * never match; the owned translation returns that FNM_NOMATCH instead (the
 * intentional difference in owned-pattern.md).  Each call runs in a child with
 * an alarm: the runner requires every pinned musl child to die of SIGALRM and
 * every owned child to report FNM_NOMATCH, so this selector's transcript is
 * checked against those fixed outcomes rather than compared across runtimes.
 */
static int fnmatch_pathname_unmatchable_case(void)
{
    static const char *const cases[][2] = {
        {"\377", ""}, {"\377", "\377"}, {"a/\377", "a/b"}, {"\\\377/b", "x/b"},
        {"*\303", "\303"},
    };
    size_t index;

    CHECK(setlocale(LC_CTYPE, "C.UTF-8") != 0);
    for (index = 0; index != sizeof cases / sizeof *cases; ++index) {
        pid_t child;
        int status;

        CHECK(fflush(stdout) == 0);
        child = fork();
        CHECK(child >= 0);
        if (child == 0) {
            alarm(1);
            printf("pathname-unmatchable case=%zu result=%d\n", index,
                fnmatch(cases[index][0], cases[index][1], FNM_PATHNAME));
            _exit(fflush(stdout) == 0 ? 0 : 127);
        }
        CHECK(waitpid(child, &status, 0) == child);
        if (WIFSIGNALED(status))
            printf("pathname-unmatchable case=%zu source-nontermination signal=%d\n",
                index, WTERMSIG(status));
        else
            CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    return 0;
}

#define GLOB_CORPUS "/corpus/outer/inner/tree"

static struct corpus_state *glob_error_state;
/* The final flag set's error callback requests an abort. */
static int glob_error_abort;

static int glob_corpus_error(const char *path, int code)
{
    struct corpus_state *state = glob_error_state;

    corpus_fold_string(state, path);
    corpus_fold(state, code);
    if (state->trace) {
        printf(" errfunc");
        corpus_trace_bytes("path", path);
        printf(" errno=%d", code);
    }
    return glob_error_abort;
}

static int glob_compare_paths(const void *left, const void *right)
{
    return strcmp(*(char *const *)left, *(char *const *)right);
}

static const char *const glob_fixed_patterns[] = {
    "*", ".*", "?", "??", "a", "a*", "*b", "[ab]", "[!a]*", "d*", "d*/", "d*/*",
    "*/*", "*/.*", "*/*/*", "d1/sub/*", "d1/*/z", "*/", ".", "..", "./a",
    "../tree/a", "d1//x", "d1/./x", "missing", "missing/*", "*/missing",
    "star\\*", "star*", "q\\?", "q?", "br[[]a]", "br\\[a]", "back\\\\slash",
    "back\\slash", "\303\251*", "[\303\251]", "*\377*", "file.txt/",
    "file.txt/*", "d2", "d2/", "d2/*", "dangling", "dangling/", "loop/*",
    "blocked/*", "blocked", "[", "[a", "a[", "\\", "*\\", "d1/[.]y", "d1/.y",
    "", "/", "//", "/corpus", "/corpus/", "/corpus/*/", "/corpus/*/*/tree//d1/x",
    "~", "~/", "~/*", "~/../*", "~root", "~root/*", "~tester/*", "~missing",
    "~missing/*", "\\~/*", "~\\root/*", "~ro*/*", "~/home.txt",
};

/* A component such as `.*` also matches `..`.  The tree sits three
 * single-entry directories below `/corpus`, deeper than any generated pattern
 * can climb, so no expansion lists the chroot root, which differs between the
 * musl and dynamic-product roots. */
static const char *const glob_component_tokens[] = {
    "*", "*", "?", ".*", "a", "b", "d1", "d2", "d*", "[ab]", "[!a]*", "[d]?",
    "sub", "x", ".y", "z", "star\\*", "q\\?", "br[[]a]", "\\a", "missing",
    "file.txt", "dangling", "loop", "blocked", "\303\251", "*\377", ".", "..",
    "[", "\\",
};

static const int glob_flag_sets[] = {
    0, GLOB_MARK, GLOB_NOCHECK, GLOB_NOESCAPE, GLOB_PERIOD, GLOB_ERR,
    GLOB_NOSORT, GLOB_MARK | GLOB_PERIOD, GLOB_NOCHECK | GLOB_NOESCAPE,
    GLOB_MARK | GLOB_NOSORT | GLOB_DOOFFS, GLOB_ERR | GLOB_MARK | GLOB_NOCHECK,
    GLOB_TILDE, GLOB_TILDE_CHECK, GLOB_TILDE | GLOB_NOCHECK | GLOB_MARK,
    GLOB_NOCHECK,
};

static int glob_observe(struct corpus_state *state, const char *pattern)
{
    size_t flag;

    for (flag = 0; flag != sizeof glob_flag_sets / sizeof *glob_flag_sets; ++flag) {
        glob_t result;
        size_t index;
        int status;

        memset(&result, 0, sizeof result);
        result.gl_offs = 3;
        glob_error_state = state;
        glob_error_abort = flag + 1 == sizeof glob_flag_sets / sizeof *glob_flag_sets;
        if (state->trace) {
            printf("glob-trace");
            corpus_trace_bytes("pattern", pattern);
            printf(" flags=%d", glob_flag_sets[flag]);
        }
        status = glob(pattern, glob_flag_sets[flag], glob_corpus_error, &result);
        ++state->calls;
        corpus_fold(state, status);
        corpus_fold(state, (long)result.gl_pathc);
        if (state->trace) printf(" status=%d count=%zu", status, result.gl_pathc);
        if (result.gl_pathv) {
            size_t offset = (glob_flag_sets[flag] & GLOB_DOOFFS) ? result.gl_offs : 0;

            for (index = 0; index != offset; ++index) CHECK(result.gl_pathv[index] == 0);
            CHECK(result.gl_pathv[offset + result.gl_pathc] == 0);
            if (glob_flag_sets[flag] & GLOB_NOSORT)
                qsort(result.gl_pathv + offset, result.gl_pathc, sizeof *result.gl_pathv,
                    glob_compare_paths);
            for (index = 0; index != result.gl_pathc; ++index) {
                corpus_fold_string(state, result.gl_pathv[offset + index]);
                if (state->trace) corpus_trace_bytes("path", result.gl_pathv[offset + index]);
            }
            if (result.gl_pathc) ++state->matches;
        }
        if (state->trace) putchar('\n');
        globfree(&result);
    }
    return 0;
}

static int glob_corpus_pass(struct corpus_state *state, const char *prefix,
    const char *locale)
{
    size_t pattern;

    for (pattern = 0; pattern != sizeof glob_fixed_patterns / sizeof *glob_fixed_patterns; ++pattern) {
        char text[256];
        size_t length = 0;

        text[0] = 0;
        CHECK(corpus_append(text, sizeof text, &length, prefix) == 0);
        CHECK(corpus_append(text, sizeof text, &length, glob_fixed_patterns[pattern]) == 0);
        CHECK(glob_observe(state, text) == 0);
    }
    corpus_block(state, prefix[0] ? "glob-fixed-absolute" : "glob-fixed-relative", locale, 0);
    for (pattern = 0; pattern != CORPUS_BLOCK; ++pattern) {
        char text[256];
        size_t length = 0;
        unsigned components = 1 + corpus_next(state) % 3;

        text[0] = 0;
        CHECK(corpus_append(text, sizeof text, &length, prefix) == 0);
        while (components--) {
            CHECK(corpus_append(text, sizeof text, &length, glob_component_tokens[corpus_next(state)
                % (sizeof glob_component_tokens / sizeof *glob_component_tokens)]) == 0);
            if (corpus_next(state) % 4 == 0)
                CHECK(corpus_append(text, sizeof text, &length, glob_component_tokens[corpus_next(state)
                    % (sizeof glob_component_tokens / sizeof *glob_component_tokens)]) == 0);
            if (components || corpus_next(state) % 5 == 0)
                CHECK(corpus_append(text, sizeof text, &length, corpus_next(state) % 7 ? "/" : "//") == 0);
        }
        CHECK(glob_observe(state, text) == 0);
    }
    corpus_block(state, prefix[0] ? "glob-random-absolute" : "glob-random-relative", locale, 0);
    return 0;
}

static int glob_corpus(int trace)
{
    struct corpus_state state;

    memset(&state, 0, sizeof state);
    state.random = CORPUS_SEED;
    state.digest = 0xcbf29ce484222325ULL;
    state.trace = trace;
    CHECK(setlocale(LC_CTYPE, "C") != 0);
    CHECK(glob_corpus_pass(&state, GLOB_CORPUS "/", "C") == 0);
    CHECK(setlocale(LC_CTYPE, "C.UTF-8") != 0);
    CHECK(glob_corpus_pass(&state, GLOB_CORPUS "/", "C.UTF-8") == 0);
    CHECK(chdir(GLOB_CORPUS) == 0);
    CHECK(glob_corpus_pass(&state, "", "C.UTF-8") == 0);
    CHECK(setlocale(LC_CTYPE, "C") != 0);
    CHECK(glob_corpus_pass(&state, "", "C") == 0);
    printf("corpus glob calls=%lu nonempty=%lu\n", state.calls, state.matches);
    return 0;
}

static int run_selected_case(const char *selector)
{
    if (!strcmp(selector, "fnmatch-pathname-unmatchable")) return fnmatch_pathname_unmatchable_case();
    if (!strcmp(selector, "fnmatch-corpus")) return fnmatch_corpus(0);
    if (!strcmp(selector, "fnmatch-corpus-trace")) return fnmatch_corpus(1);
    if (!strcmp(selector, "glob-corpus")) return glob_corpus(0);
    if (!strcmp(selector, "glob-corpus-trace")) return glob_corpus(1);
    if (!strcmp(selector, "fnmatch-escaped")) return matcher_escaped_wildcard_cases();
    if (!strcmp(selector, "fnmatch-range")) return matcher_range_case();
    if (!strcmp(selector, "fnmatch-nested-class")) return matcher_nested_class_case();
    if (!strcmp(selector, "glob-literal")) return glob_literal_path_case();
    if (!strcmp(selector, "glob-nested")) return glob_nested_path_case();
    if (!strcmp(selector, "glob-dangling-mark")) return glob_dangling_mark_case();
    if (strcmp(selector, "all")) {
        failure_line = __LINE__;
        return -1;
    }
    if (matcher_c_and_posix_cases()
        || matcher_utf8_and_invalid_cases()
        || glob_literal_path_case()
        || glob_nested_path_case()
        || glob_basic_sort_and_memory_cases()
        || glob_offset_append_and_nocheck_cases()
        || glob_period_escape_mark_and_trailing_cases()
        || glob_dangling_mark_case()
        || glob_tilde_cases()
        || glob_unreadable_error_cases()) {
        return 1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *selector;

    if (argc == 1) selector = "all";
    else if (argc == 2) selector = argv[1];
    else {
        failure_line = __LINE__;
        selector = "invalid-selector";
    }
    if (run_selected_case(selector)) {
        fprintf(stderr, "owned-pattern %s failure at line %d errno %d\n",
            selector, failure_line, errno);
        return 1;
    }
    printf("owned-pattern-%s-ok\n", selector);
    return 0;
}

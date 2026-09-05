/*
 * Source-bound C witness for musl 1.2.6 `src/regex/{fnmatch,glob}.c`.
 *
 * The runner supplies `/fixture` and `/etc/passwd` inside a disposable
 * chroot.  This consumes the installed public fnmatch.h/glob.h records and
 * runs one identical workload object under pinned musl and every owned
 * product.  In particular, tilde expansion reaches the standard passwd ABI;
 * it does not admit a test-local parser or host account database.
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

static int run_selected_case(const char *selector)
{
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

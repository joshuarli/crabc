/* Private adapter fixture: linked only with the explicit probe cfg archive. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern int __crabc_test_wordexp_paths(const char *, const char *const *,
    const char *const *, size_t, const unsigned char *, size_t, size_t);

static int failures;

static void check(const char *name, const char *source,
    const char *const *names, const char *const *values, size_t variables,
    const char *expected, size_t bytes, size_t count)
{
    int status = __crabc_test_wordexp_paths(source, names, values, variables,
        (const unsigned char *)expected, bytes, count);
    if (status) {
        fprintf(stderr, "%s: status %d: %s\n", name, status, source);
        failures++;
    }
}

#define CHECK(name, source, value, expected, count) do { \
    const char *names[] = {"A"}; \
    const char *values[] = {value}; \
    check(name, source, names, values, 1, expected, sizeof(expected)-1, count); \
} while (0)

static int path_join(char *buffer, size_t size, const char *root, const char *name)
{
    int n = snprintf(buffer, size, "%s/%s", root, name);
    return n >= 0 && (size_t)n < size;
}

int main(void)
{
    if (!setlocale(LC_ALL, "C")) return 1;
    CHECK("four removal lengths",
        "\"${A#a*c}\" \"${A##a*c}\" \"${A%a*c}\" \"${A%%a*c}\"",
        "abcabc", "abc\0\0abc\0\0", 4);
    CHECK("quoted wildcards", "\"${A#'*'}\" \"${A#\\*}\" \"${A#'?'}\"",
        "*abc", "abc\0abc\0*abc\0", 3);
    CHECK("protected range member", "\"${A#[a\"-\"z]}\"", "-tail", "tail\0", 1);
    CHECK("protected range has no interior", "\"${A#[a\"-\"z]}\"", "mtail", "mtail\0", 1);
    CHECK("protected bracket end", "\"${A#[a\"]\"z]}\"", "]tail", "tail\0", 1);
    CHECK("protected negation", "\"${A#[\"!\"a]}\"", "!tail", "tail\0", 1);
    CHECK("quoted class name letter", "\"${A#[[:di\"g\"it:]]}\"", "4tail", "tail\0", 1);
    CHECK("removal result splitting", "${A#prefix:} \"${A#prefix:}\"",
        "prefix:a b", "a\0b\0a b\0", 3);
    CHECK("empty removal quote state", "${A#a} \"${A#a}\"", "a", "\0", 1);

    const char *home_names[] = {"HOME"};
    const char *home_values[] = {"space * ? [home]"};
    check("HOME bytes remain literal", "~", home_names, home_values, 1,
        "space * ? [home]\0", sizeof("space * ? [home]\0")-1, 1);
    home_values[0] = "";
    check("empty HOME", "~ ~/tail", home_names, home_values, 1,
        "\0/tail\0", sizeof("\0/tail\0")-1, 2);

    if (!setlocale(LC_ALL, "C.UTF-8")) return 2;
    CHECK("UTF-8 prefix character", "\"${A#?}\"", "\303\251tail", "tail\0", 1);
    CHECK("UTF-8 suffix character", "\"${A%?}\"", "tail\303\251", "tail\0", 1);
    CHECK("invalid UTF-8 progress", "\"${A#?}\"", "\377tail", "\377tail\0", 1);
    if (!setlocale(LC_ALL, "C")) return 3;
    CHECK("C byte prefix", "\"${A#?}\"", "\303\251tail", "\251tail\0", 1);

    /* The fixture's native /etc/passwd owner supplies the named/fallback
       reference. No shared getpwnam/getpwuid result is retained. */
    struct passwd record, *found = NULL;
    size_t pw_capacity = 1024;
    char *pw_storage = NULL;
    int pw_status;
    do {
        free(pw_storage);
        pw_storage = malloc(pw_capacity);
        if (!pw_storage) return 4;
        pw_status = getpwuid_r(getuid(), &record, pw_storage, pw_capacity, &found);
        if (pw_status == ERANGE) pw_capacity *= 2;
    } while (pw_status == ERANGE);
    if (pw_status || !found) return 5;
    char named[1024];
    if (snprintf(named, sizeof named, "~%s", found->pw_name) >= (int)sizeof named) return 6;
    check("reentrant named tilde", named, NULL, NULL, 0,
        found->pw_dir, strlen(found->pw_dir)+1, 1);
    home_values[0] = NULL;
    check("unset HOME uid fallback", "~", home_names, home_values, 1,
        found->pw_dir, strlen(found->pw_dir)+1, 1);
    free(pw_storage);

    const char *temporary = getenv("TMPDIR");
    if (!temporary || temporary[0] != '/') return 7;
    char directory[4096];
    if (!path_join(directory, sizeof directory, temporary, "wordexp-paths.XXXXXX")) return 8;
    if (!mkdtemp(directory)) return 9;
    const char *entries[] = {"z", "a", "-", "m", ".hidden", "*"};
    char pathname[4096], source[8192], expected[16384];
    for (size_t i=0; i<sizeof entries/sizeof entries[0]; i++) {
        if (!path_join(pathname, sizeof pathname, directory, entries[i])) return 10;
        int fd = open(pathname, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0600);
        if (fd < 0 || close(fd)) return 11;
    }
    /* Fixed contained test roots cannot carry shell syntax into these quotes. */
    if (strpbrk(directory, "\"\\$`")) return 12;
    snprintf(source, sizeof source, "\"%s\"/[a\"-\"z]", directory);
    size_t used=0;
    const char *ordered[] = {"-", "a", "z"};
    for (size_t i=0; i<3; i++) {
        if (!path_join(expected+used, sizeof expected-used, directory, ordered[i])) return 13;
        used += strlen(expected+used)+1;
    }
    check("glob protected range and sorting", source, NULL, NULL, 0, expected, used, 3);

    const char *patterns[] = {"\".\"h*", "\\*", "$A", "no-match-*"};
    const char *results[] = {".hidden", "*", "\\*", "no-match-*"};
    const char *names[] = {"A"};
    const char *values[] = {"\\*"};
    for (size_t i=0; i<4; i++) {
        snprintf(source, sizeof source, "\"%s\"/%s", directory, patterns[i]);
        if (!path_join(expected, sizeof expected, directory, results[i])) return 14;
        check("glob quote and no-match boundary", source, names, values, 1,
            expected, strlen(expected)+1, 1);
    }
    for (size_t i=0; i<sizeof entries/sizeof entries[0]; i++) {
        if (!path_join(pathname, sizeof pathname, directory, entries[i])) return 15;
        if (unlink(pathname)) return 16;
    }
    if (rmdir(directory)) return 17;
    if (failures) return 1;
    puts("PASS private wordexp pathname adapter");
    return 0;
}

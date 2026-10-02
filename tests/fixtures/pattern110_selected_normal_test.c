#define _GNU_SOURCE
#include <regex.h>
#include <fnmatch.h>
#include <glob.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct regex_case { const char *name, *pattern, *subject; int flags; };
static const struct regex_case regex_cases[] = {
    { "bre-backref", "^\\(ab\\)\\1$", "abab", 0 },
    { "nosub-backref", "^\\(ab\\)\\1$", "abab", REG_NOSUB },
    { "longest-groups", "(a|ab)(b?)", "ab", REG_EXTENDED },
    { "optional-group", "(ab)?(cd)", "cd", REG_EXTENDED },
    { "newline-anchor", "^[[:alpha:]]+$", "first\nsecond", REG_EXTENDED|REG_NEWLINE },
    { "ascii-fold", "[a-z]+", "ABC", REG_EXTENDED|REG_ICASE },
    { "utf8-fold", "\303\251+", "\303\211\303\211", REG_EXTENDED|REG_ICASE },
    { "empty-match", "b*", "abc", REG_EXTENDED },
};

struct match_case { const char *name, *pattern, *subject; int flags; };
static const struct match_case match_cases[] = {
    { "path-components", "src/*.[ch]", "src/main.c", FNM_PATHNAME },
    { "component-period", "src/*", "src/.hidden", FNM_PATHNAME|FNM_PERIOD },
    { "literal-period", "src/.*", "src/.hidden", FNM_PATHNAME|FNM_PERIOD },
    { "leading-directory", "src", "src/main.c", FNM_LEADING_DIR },
    { "escaped-star", "report\\*.txt", "report*.txt", 0 },
    { "class-fold", "[[:lower:]]*", "Alpha", FNM_CASEFOLD },
    { "utf8-character", "?", "\303\251", 0 },
};

static int observe_glob(const char *locale)
{
    glob_t result = {0};
    result.gl_offs = 2;
    if (glob(".work/pattern110/fs/*.txt", GLOB_DOOFFS, NULL, &result)) return 10;
    if (result.gl_pathc != 2 || result.gl_pathv[0] || result.gl_pathv[1]) return 11;
    char *first = result.gl_pathv[2];
    if (glob(".work/pattern110/fs/nested/*.txt", GLOB_DOOFFS|GLOB_APPEND,
             NULL, &result)) return 12;
    if (result.gl_pathc != 4 || result.gl_pathv[2] != first) return 13;
    if (glob(".work/pattern110/fs/link", GLOB_DOOFFS|GLOB_APPEND|GLOB_MARK,
             NULL, &result)) return 14;
    if (result.gl_pathc != 5 || result.gl_pathv[2] != first
        || result.gl_pathv[7]) return 15;
    for (size_t i = 0; i < result.gl_pathc; i++)
        printf("glob %s %zu %s\n", locale, i, result.gl_pathv[2+i]);
    globfree(&result);
    return 0;
}

static int observe_thread_locale(void)
{
    if (!setlocale(LC_ALL, "C")) return 20;
    locale_t locale = newlocale(LC_CTYPE_MASK, "C.UTF-8", NULL);
    if (!locale) return 21;
    locale_t previous = uselocale(locale);
    if (!previous) return 22;
    regex_t compiled;
    regmatch_t matches[3];
    if (regcomp(&compiled, "^(.)(.)$", REG_EXTENDED)) return 23;
    if (regexec(&compiled, "\303\251\303\237", 3, matches, 0)) return 24;
    printf("thread-locale %ld:%ld %ld:%ld %ld:%ld match=%d\n",
           (long)matches[0].rm_so, (long)matches[0].rm_eo,
           (long)matches[1].rm_so, (long)matches[1].rm_eo,
           (long)matches[2].rm_so, (long)matches[2].rm_eo,
           fnmatch("?", "\303\251", 0));
    regfree(&compiled);
    if (uselocale(previous) != locale) return 25;
    freelocale(locale);
    if (fnmatch("?", "\303\251", 0) != FNM_NOMATCH) return 26;
    return 0;
}

int crabc_pattern110_selected_normal(void)
{
    const char *locales[] = { "C", "POSIX", "C.UTF-8" };
    for (size_t locale = 0; locale < 3; locale++) {
        if (!setlocale(LC_ALL, locales[locale])) return 1;
        for (size_t i = 0; i < sizeof regex_cases/sizeof *regex_cases; i++) {
            const struct regex_case *sample = &regex_cases[i];
            regex_t compiled;
            regmatch_t matches[4] = {{-7,-7},{-7,-7},{-7,-7},{-7,-7}};
            if (regcomp(&compiled, sample->pattern, sample->flags)) return 2;
            int result = regexec(&compiled, sample->subject, 4, matches, 0);
            if (result != 0 && result != REG_NOMATCH) return 3;
            if (regexec(&compiled, sample->subject, 0, NULL, 0) != result) return 4;
            printf("regex %s %s %d %zu", locales[locale], sample->name,
                   result, compiled.re_nsub);
            for (size_t j = 0; j < 4; j++)
                printf(" %ld:%ld", (long)matches[j].rm_so, (long)matches[j].rm_eo);
            putchar('\n');
            regfree(&compiled);
        }
        for (size_t i = 0; i < sizeof match_cases/sizeof *match_cases; i++) {
            const struct match_case *sample = &match_cases[i];
            printf("fnmatch %s %s %d\n", locales[locale], sample->name,
                   fnmatch(sample->pattern, sample->subject, sample->flags));
        }
        int result = observe_glob(locales[locale]);
        if (result) return result;
    }
    int result = observe_thread_locale();
    if (result) return result;
    return fflush(NULL);
}

#ifndef CRABC_NATIVE_ENTRY
int main(void) { return crabc_pattern110_selected_normal(); }
#endif

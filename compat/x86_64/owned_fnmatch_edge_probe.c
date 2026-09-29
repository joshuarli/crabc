/* Directed C fnmatch differential for component boundaries and brackets. */
#include <fnmatch.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>

struct fnmatch_edge_case {
    const char *name;
    const char *pattern;
    const char *subject;
};

static const struct fnmatch_edge_case fnmatch_edge_cases[] = {
    {"empty", "", ""},
    {"leading-dir-empty", "", "/child"},
    {"leading-dir-prefix", "a", "a/child"},
    {"leading-dir-trailing-slash", "a/", "a/child"},
    {"double-separator", "a//b", "a//b"},
    {"star-separator", "a/*/b", "a/x/b"},
    {"star-empty-component", "a/*/b", "a//b"},
    {"escaped-separator", "a\\/b", "a/b"},
    {"escaped-leading-period", "\\.x", ".x"},
    {"escaped-component-period", "a/\\.x", "a/.x"},
    {"bracket-leading-period", "[.]x", ".x"},
    {"bracket-component-period", "a/[.]x", "a/.x"},
    {"star-leading-period", "*", ".x"},
    {"star-component-period", "a/*", "a/.x"},
    {"question-separator", "a?b", "a/b"},
    {"bracket-separator", "a[/]b", "a/b"},
    {"negative-bracket-separator", "a[!/]b", "a/b"},
    {"range-forward", "[a-c]", "b"},
    {"range-reversed", "[c-a]", "b"},
    {"range-leading-dash", "[-c]", "-"},
    {"range-trailing-dash", "[c-]", "-"},
    {"range-double-dash", "[a--c]", "b"},
    {"range-casefold", "[A-C]", "b"},
    {"bracket-escaped-dash", "[a\\-c]", "b"},
    {"bracket-escaped-close", "[a\\]]", "]"},
    {"bracket-leading-close", "[]a]", "]"},
    {"bracket-negated-close", "[!]]", "a"},
    {"bracket-class", "[[:alpha:]]", "b"},
    {"bracket-class-negated", "[![:alpha:]]", "5"},
    {"bracket-class-range", "[[:alpha:]b-d]", "c"},
    {"bracket-equivalence", "[[=a=]]", "a"},
    {"bracket-collating", "[[.a.]]", "a"},
    {"bracket-incomplete", "[[:alpha:]", "[[:alpha:]"},
    {"utf8-literal", "\303\251", "\303\251"},
    {"utf8-question", "?", "\303\251"},
    {"utf8-range", "[\303\251-\303\277]", "\303\266"},
    {"utf8-range-casefold", "[\303\200-\303\226]", "\303\245"},
    {"utf8-invalid-subject", "*x", "\377x"},
    {"utf8-invalid-bracket", "[\377]", "x"},
    {"utf8-invalid-literal", "\377", "x"},
};

static int matcher_edge_matrix_case(void)
{
    static const char *const locales[] = {"C", "POSIX", "C.UTF-8"};
    unsigned locale_index;
    unsigned case_index;
    int flags;

    for (locale_index = 0; locale_index < sizeof locales / sizeof *locales; locale_index++) {
        if (!setlocale(LC_CTYPE, locales[locale_index])) return -1;
        for (case_index = 0;
            case_index < sizeof fnmatch_edge_cases / sizeof *fnmatch_edge_cases;
            case_index++) {
            const struct fnmatch_edge_case *sample = &fnmatch_edge_cases[case_index];
            int pathname_pattern_is_valid = mbstowcs(0, sample->pattern, 0) != (size_t)-1;
            for (flags = 0; flags < 32; flags++) {
                int selected = ((flags & 1) ? FNM_PATHNAME : 0)
                    | ((flags & 2) ? FNM_NOESCAPE : 0)
                    | ((flags & 4) ? FNM_PERIOD : 0)
                    | ((flags & 8) ? FNM_LEADING_DIR : 0)
                    | ((flags & 16) ? FNM_CASEFOLD : 0);
                /* musl's pathname scanner never advances past malformed
                 * multibyte pattern bytes. Other flag cells remain useful. */
                if ((selected & FNM_PATHNAME) && !pathname_pattern_is_valid) continue;
                printf("%s %s flags=%d result=%d\n", locales[locale_index],
                    sample->name, selected,
                    fnmatch(sample->pattern, sample->subject, selected));
            }
        }
    }
    return 0;
}

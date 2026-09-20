#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <locale.h>
#include <stdlib.h>
#include <string.h>

static int environment_precedence(void)
{
    static const char *categories[] = {
        "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE",
        "LC_MONETARY", "LC_MESSAGES",
    };
    if (unsetenv("LC_ALL") || unsetenv("LANG")) return 30;
    for (unsigned i = 0; i < sizeof categories / sizeof categories[0]; ++i)
        if (unsetenv(categories[i])) return 31;
    if (!setlocale(LC_ALL, "") || MB_CUR_MAX != 4) return 32;
    if (setenv("LANG", "POSIX", 1) || !setlocale(LC_ALL, "") || MB_CUR_MAX != 1) return 33;
    if (setenv("LC_CTYPE", "C.UTF-8", 1) || !setlocale(LC_CTYPE, "") || MB_CUR_MAX != 4) return 34;
    if (setenv("LC_ALL", "C", 1) || !setlocale(LC_ALL, "") || MB_CUR_MAX != 1) return 35;
    if (setenv("LC_ALL", "", 1) || !setlocale(LC_ALL, "") || MB_CUR_MAX != 4) return 36;
    if (setenv("LC_CTYPE", "", 1) || !setlocale(LC_ALL, "") || MB_CUR_MAX != 1) return 37;

    if (setenv("LC_CTYPE", "C.UTF-8", 1)) return 40;
    locale_t base = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    if (!base) return 41;
    locale_t inherited = newlocale(LC_NUMERIC_MASK, "", base);
    if (!inherited) return 42;
    locale_t old = uselocale(inherited);
    if (!old || MB_CUR_MAX != 1) return 43;
    /* Global changes do not replace an installed per-thread locale. */
    if (!setlocale(LC_ALL, "") || MB_CUR_MAX != 1) return 44;
    if (uselocale(old) != inherited || MB_CUR_MAX != 4) return 45;
    freelocale(inherited);

    /* Pinned musl resolves unselected null-base categories from the
     * environment, including LC_CTYPE when only LC_NUMERIC is selected. */
    locale_t defaults = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    if (!defaults) return 46;
    old = uselocale(defaults);
    if (!old || MB_CUR_MAX != 4) return 47;
    if (uselocale(old) != defaults) return 48;
    freelocale(defaults);
    defaults = newlocale(0, (const char *)0, (locale_t)0);
    if (!defaults) return 49;
    old = uselocale(defaults);
    if (!old || MB_CUR_MAX != 4) return 50;
    if (uselocale(old) != defaults) return 51;
    freelocale(defaults);
    return 0;
}

/* Project profile assertion, kept separate from musl's arbitrary-name
 * locale maps: rejection must not partially publish earlier categories. */
static int unsupported_environment(void)
{
    if (!setlocale(LC_ALL, "C.UTF-8")) return 60;
    locale_t base = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
    if (!base || setenv("LC_CTYPE", "C", 1) ||
        setenv("LC_TIME", "crabc-unsupported-locale", 1)) return 61;
    if (setlocale(LC_ALL, "") || MB_CUR_MAX != 4) return 62;
    errno = 0;
    if (newlocale(LC_ALL_MASK, "", base) || errno != ENOENT) return 63;
    locale_t old = uselocale(base);
    if (!old || MB_CUR_MAX != 4) return 64;
    if (uselocale(old) != base) return 65;
    freelocale(base);
    if (!setlocale(LC_CTYPE, "") || MB_CUR_MAX != 1) return 66;
    if (setenv("LC_ALL", "C", 1) || !setlocale(LC_ALL, "")) return 67;
    return 0;
}

/* Run in an empty environment with LC_ALL=C. An empty name selects that
 * supported locale; it is not an unsupported locale-database request. */
int crabc_x86_64_locale_environment_probe(int argc, char **argv)
{
    int object_only = argc == 2 && !strcmp(argv[1], "object");
    if (!getenv("LC_ALL") || strcmp(getenv("LC_ALL"), "C")) return 1;
    if (!setlocale(LC_ALL, "C.UTF-8")) return 2;
    errno = 73;
    if (!object_only) {
        const char *selected = setlocale(LC_ALL, "");
        if (!selected) return 10;
        if (strcmp(selected, "C") || MB_CUR_MAX != 1) return 11;
        if (errno != 73) return 12;
    }
    locale_t object = newlocale(LC_ALL_MASK, "", (locale_t)0);
    if (!object) return 20;
    locale_t previous = uselocale(object);
    if (!previous || MB_CUR_MAX != 1) return 21;
    if (uselocale(previous) != object) return 22;
    freelocale(object);
    int result = environment_precedence();
    if (result) return result;
    return argc == 2 && !strcmp(argv[1], "profile") ? unsupported_environment() : 0;
}

#ifndef CRABC_LOCALE_ENVIRONMENT_NO_MAIN
int main(int argc, char **argv)
{
    return crabc_x86_64_locale_environment_probe(argc, argv);
}
#endif

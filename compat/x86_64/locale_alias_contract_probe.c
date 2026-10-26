/*
 * One installed-header application object proves musl's locale/time weak-alias
 * rule: executable public replacements are admitted, while libc's own
 * source-selected internal calls retain the private implementation.
 */
#define _GNU_SOURCE 1
#define _XOPEN_SOURCE 700

#include <ctype.h>
#include <langinfo.h>
#include <locale.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <wctype.h>

static int override_token;
static int tzset_calls;
static int wcsftime_l_calls;
static char override_text[] = "application-override";

extern size_t __wcsftime_l(wchar_t *restrict, size_t,
    const wchar_t *restrict, const struct tm *restrict, locale_t);

typedef size_t (*wcsftime_l_signature)(wchar_t *restrict, size_t,
    const wchar_t *restrict, const struct tm *restrict, locale_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&wcsftime_l),
    wcsftime_l_signature), "installed wcsftime_l declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&__wcsftime_l),
    wcsftime_l_signature), "musl internal wcsftime_l declaration");

struct guarded_wide_output {
    uint64_t before;
    wchar_t output[128];
    uint64_t after;
};

static int equal(const char *left, const char *right)
{
    while (*left == *right) {
        if (*left == '\0')
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

static int wide_equal(const wchar_t *left, const wchar_t *right)
{
    while (*left == *right) {
        if (*left == L'\0')
            return 1;
        ++left;
        ++right;
    }
    return 0;
}

static size_t format_wide(int internal, wchar_t *output, size_t capacity,
    const wchar_t *format, const struct tm *value, locale_t locale)
{
    if (internal)
        return __wcsftime_l(output, capacity, format, value, locale);
    return wcsftime(output, capacity, format, value);
}

static int retained_wcsftime(locale_t locale)
{
    const struct tm calendar = {
        .tm_sec = 5,
        .tm_min = 4,
        .tm_hour = 13,
        .tm_mday = 29,
        .tm_mon = 1,
        .tm_year = 124,
        .tm_wday = 4,
        .tm_yday = 59,
        .tm_isdst = 0,
    };
    const struct tm extended_year = {
        .tm_year = 8100,
        .tm_isdst = 0,
    };
    const uint64_t before = UINT64_C(0x0123456789abcdef);
    const uint64_t after = UINT64_C(0xfedcba9876543210);
    const wchar_t untouched = (wchar_t)0x55555555u;

    if (wcsftime_l(NULL, 0, L"%Y", &calendar, locale) != 79 ||
        wcsftime_l_calls != 1)
        return 1;

    for (int internal = 0; internal != 2; ++internal) {
        struct guarded_wide_output guarded;
        memset(&guarded, 0x55, sizeof(guarded));
        guarded.before = before;
        guarded.after = after;
        if (format_wide(internal, NULL, 0, L"%Y", &calendar, locale) != 0 ||
            guarded.before != before || guarded.after != after)
            return 2;

        memset(&guarded, 0x55, sizeof(guarded));
        guarded.before = before;
        guarded.after = after;
        if (format_wide(internal, guarded.output, 64,
                L"%Y-%m-%d %H:%M:%S", &calendar, locale) != 19 ||
            !wide_equal(guarded.output, L"2024-02-29 13:04:05") ||
            guarded.before != before || guarded.after != after)
            return 3;
        for (size_t index = 20; index != 128; ++index)
            if (guarded.output[index] != untouched)
                return 4;

        memset(&guarded, 0x55, sizeof(guarded));
        guarded.before = before;
        guarded.after = after;
        if (format_wide(internal, guarded.output, 4, L"%Y", &calendar, locale) != 0 ||
            !wide_equal(guarded.output, L"202") || guarded.output[3] != L'\0' ||
            guarded.before != before || guarded.after != after)
            return 5;
        for (size_t index = 4; index != 128; ++index)
            if (guarded.output[index] != untouched)
                return 6;

        memset(&guarded, 0x55, sizeof(guarded));
        guarded.before = before;
        guarded.after = after;
        if (format_wide(internal, guarded.output, 16, L"pre%Qpost", &calendar, locale) != 0 ||
            !wide_equal(guarded.output, L"pre") || guarded.output[3] != L'\0' ||
            guarded.before != before || guarded.after != after)
            return 7;
        for (size_t index = 4; index != 128; ++index)
            if (guarded.output[index] != untouched)
                return 8;

        memset(&guarded, 0x55, sizeof(guarded));
        guarded.before = before;
        guarded.after = after;
        if (format_wide(internal, guarded.output, 16, L"%+5Y", &extended_year, locale) != 6 ||
            !wide_equal(guarded.output, L"+10000") ||
            guarded.before != before || guarded.after != after)
            return 9;
        for (size_t index = 7; index != 128; ++index)
            if (guarded.output[index] != untouched)
                return 10;
        if (wcsftime_l_calls != 1)
            return 11;
    }
    return 0;
}

/*
 * These are artifact-observation declarations only. They deliberately name
 * musl's internal locale spellings, including the reverse weak
 * `__freelocale` alias, so the same executable can replace every selected
 * public weak entry while higher-level libc code still reaches its retained
 * provider. Installed public headers remain the sole source of the
 * application object's ordinary API declarations.
 */
extern locale_t __newlocale(int, const char *, locale_t);
extern locale_t __duplocale(locale_t);
extern void __freelocale(locale_t);
extern locale_t __uselocale(locale_t);
extern char *__nl_langinfo(nl_item);
extern char *__nl_langinfo_l(nl_item, locale_t);
extern int __isalpha_l(int, locale_t);
extern int __iswalpha_l(wint_t, locale_t);
extern int __strcoll_l(const char *, const char *, locale_t);
extern int __wcscoll_l(const wchar_t *, const wchar_t *, locale_t);

static int retained_locale_objects(void)
{
    locale_t c_locale = __newlocale(LC_ALL_MASK, "C", NULL);
    locale_t posix = __newlocale(LC_ALL_MASK, "POSIX", NULL);
    locale_t utf8 = __newlocale(LC_ALL_MASK, "C.UTF-8", NULL);
    locale_t duplicate;
    locale_t previous;

    if (c_locale == NULL || posix == NULL || utf8 == NULL ||
        !equal(__nl_langinfo_l(CODESET, c_locale), "ASCII") ||
        !equal(__nl_langinfo_l(CODESET, posix), "ASCII") ||
        !equal(__nl_langinfo_l(CODESET, utf8), "UTF-8"))
        return 1;

    duplicate = __duplocale(utf8);
    if (duplicate == NULL || !equal(__nl_langinfo_l(CODESET, duplicate), "UTF-8"))
        return 2;

    previous = __uselocale(utf8);
    if (!equal(__nl_langinfo(CODESET), "UTF-8") ||
        __isalpha_l('A', utf8) == 0 || __iswalpha_l(L'A', utf8) == 0 ||
        __strcoll_l("a", "b", utf8) >= 0 || __wcscoll_l(L"a", L"b", utf8) >= 0)
        return 3;
    (void)__uselocale(previous);
    __freelocale(duplicate);
    __freelocale(utf8);
    __freelocale(posix);
    __freelocale(c_locale);
    return 0;
}

locale_t newlocale(int mask, const char *name, locale_t base)
{
    (void)mask;
    (void)name;
    (void)base;
    return (locale_t)&override_token;
}

locale_t duplocale(locale_t locale)
{
    (void)locale;
    return (locale_t)&override_token;
}

locale_t uselocale(locale_t locale)
{
    (void)locale;
    return (locale_t)&override_token;
}

char *nl_langinfo(nl_item item)
{
    (void)item;
    return override_text;
}

char *nl_langinfo_l(nl_item item, locale_t locale)
{
    (void)item;
    (void)locale;
    return override_text;
}

int isalpha_l(int character, locale_t locale)
{
    (void)character;
    (void)locale;
    return 71;
}

int iswalpha_l(wint_t character, locale_t locale)
{
    (void)character;
    (void)locale;
    return 72;
}

int strcasecmp_l(const char *left, const char *right, locale_t locale)
{
    (void)left;
    (void)right;
    (void)locale;
    return 73;
}

int strcoll_l(const char *left, const char *right, locale_t locale)
{
    (void)left;
    (void)right;
    (void)locale;
    return 74;
}

size_t strxfrm_l(char *destination, const char *source, size_t count,
    locale_t locale)
{
    (void)destination;
    (void)source;
    (void)count;
    (void)locale;
    return 75;
}

int wcscoll_l(const wchar_t *left, const wchar_t *right, locale_t locale)
{
    (void)left;
    (void)right;
    (void)locale;
    return 76;
}

size_t wcsxfrm_l(wchar_t *destination, const wchar_t *source, size_t count,
    locale_t locale)
{
    (void)destination;
    (void)source;
    (void)count;
    (void)locale;
    return 77;
}

size_t strftime_l(char *output, size_t capacity, const char *format,
    const struct tm *value, locale_t locale)
{
    (void)output;
    (void)capacity;
    (void)format;
    (void)value;
    (void)locale;
    return 78;
}

size_t wcsftime_l(wchar_t *restrict output, size_t capacity,
    const wchar_t *restrict format, const struct tm *restrict value, locale_t locale)
{
    (void)output;
    (void)capacity;
    (void)format;
    (void)value;
    (void)locale;
    ++wcsftime_l_calls;
    return 79;
}

struct tm *gmtime_r(const time_t *input, struct tm *output)
{
    (void)input;
    (void)output;
    return NULL;
}

struct tm *localtime_r(const time_t *input, struct tm *output)
{
    (void)input;
    (void)output;
    return NULL;
}

char *asctime_r(const struct tm *value, char *output)
{
    (void)value;
    (void)output;
    return NULL;
}

void tzset(void)
{
    ++tzset_calls;
}

int main(void)
{
    const time_t epoch = 0;
    struct tm value = {
        .tm_sec = 0,
        .tm_min = 0,
        .tm_hour = 0,
        .tm_mday = 1,
        .tm_mon = 0,
        .tm_year = 70,
        .tm_wday = 4,
        .tm_yday = 0,
        .tm_isdst = 0,
    };
    char text[64];
    char transformed[8];
    wchar_t wide_transformed[8];
    char *calendar;
    struct tm *broken_down;
    locale_t override_locale = __newlocale(LC_ALL_MASK, "C.UTF-8", NULL);
    locale_t release_locale = __newlocale(LC_ALL_MASK, "C", NULL);

    if (override_locale == NULL || release_locale == NULL)
        return 1;
    if (newlocale(LC_ALL_MASK, "C", NULL) != (locale_t)&override_token ||
        duplocale(override_locale) != (locale_t)&override_token ||
        uselocale(NULL) != (locale_t)&override_token)
        return 2;
    if (!equal(nl_langinfo(CODESET), override_text) ||
        !equal(nl_langinfo_l(CODESET, override_locale), override_text))
        return 3;
    if (isalpha_l('A', override_locale) != 71 ||
        iswalpha_l(L'A', override_locale) != 72 ||
        strcasecmp_l("A", "a", override_locale) != 73 ||
        strcoll_l("a", "b", override_locale) != 74 ||
        strxfrm_l(transformed, "a", sizeof(transformed), override_locale) != 75 ||
        wcscoll_l(L"a", L"b", override_locale) != 76 ||
        wcsxfrm_l(wide_transformed, L"a", sizeof(wide_transformed) / sizeof(wide_transformed[0]),
            override_locale) != 77 ||
        strftime_l(text, sizeof(text), "%a", &value, override_locale) != 78)
        return 4;
    if (gmtime_r(&epoch, &value) != NULL ||
        localtime_r(&epoch, &value) != NULL ||
        asctime_r(&value, text) != NULL)
        return 5;
    tzset();
    if (tzset_calls != 1)
        return 6;

    /* The direct internal calls keep C/POSIX/C.UTF-8 state out of overrides. */
    if (retained_locale_objects() != 0)
        return 7;

    /* asctime uses hidden asctime_r and fixed C langinfo. */
    calendar = asctime(&value);
    if (calendar == NULL || !equal(calendar, "Thu Jan  1 00:00:00 1970\n"))
        return 8;

    /* gmtime and localtime retain hidden reentrant providers. */
    broken_down = gmtime(&epoch);
    if (broken_down == NULL || broken_down->tm_year != 70 ||
        broken_down->tm_mon != 0 || broken_down->tm_mday != 1)
        return 9;
    broken_down = localtime(&epoch);
    if (broken_down == NULL || broken_down->tm_year != 70 ||
        broken_down->tm_mon != 0 || broken_down->tm_mday != 1)
        return 10;

    /* strftime and collation call the retained private locale bodies. */
    if (strftime(text, sizeof(text), "%a", &value) != 3 ||
        !equal(text, "Thu") || strcoll("a", "b") >= 0 ||
        wcscoll(L"a", L"b") >= 0)
        return 11;
    if (retained_wcsftime(override_locale) != 0)
        return 12;

    __freelocale(override_locale);
    freelocale(release_locale);
    return 0;
}

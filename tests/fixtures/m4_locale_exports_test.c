#define _GNU_SOURCE 1

#include <ctype.h>
#include <langinfo.h>
#include <locale.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <wchar.h>
#include <wctype.h>

extern int __isalpha_l(int, locale_t);
extern int __iswalpha_l(wint_t, locale_t);
extern int __wcscoll_l(const wchar_t *, const wchar_t *, locale_t);
extern size_t __wcsxfrm_l(wchar_t *, const wchar_t *, size_t, locale_t);
extern locale_t __newlocale(int, const char *, locale_t);
extern void __freelocale(locale_t);
extern double strtod_l(const char *, char **, locale_t);
extern double __strtod_l(const char *, char **, locale_t);

int main(void) {
    locale_t loc = __newlocale(LC_ALL_MASK, "C", NULL);
    if (!loc) return 1;

    if (!isalpha_l('a', loc) || isalpha_l('1', loc) || !__isalpha_l('A', loc)) return 2;
    if (!iswalpha_l(L'a', loc) || !__iswalpha_l(L'A', loc)) return 3;
    if (!iswctype_l(L'7', wctype_l("digit", loc), loc)) return 4;
    if (towupper_l(L'a', loc) != L'A' || towlower_l(L'A', loc) != L'a') return 5;
    if (towctrans_l(L'a', wctrans_l("toupper", loc), loc) != L'A') return 6;

    if (strcasecmp("AbC", "aBc") != 0 || strncasecmp("AbD", "aBc", 2) != 0) return 7;
    if (strcasecmp_l("AbC", "aBc", loc) != 0 || strncasecmp_l("AbD", "aBc", 3, loc) <= 0) return 8;
    if (strcoll("a", "b") >= 0 || strcoll_l("b", "a", loc) <= 0) return 9;
    {
        char transformed[3];
        if (strxfrm(transformed, "abcd", sizeof transformed) != 4 || strcmp(transformed, "ab")) return 10;
        if (strxfrm_l(transformed, "xy", sizeof transformed, loc) != 2 || strcmp(transformed, "xy")) return 11;
    }

    {
        wchar_t left[] = L"Alpha";
        wchar_t right[] = L"aLPHA";
        wchar_t transformed[3];
        if (wcscasecmp(left, right) != 0 || wcsncasecmp(left, right, 5) != 0) return 12;
        if (wcscoll_l(left, right, loc) == 0 || __wcscoll_l(left, right, loc) == 0) return 13;
        if (wcsxfrm_l(transformed, left, 3, loc) != 5 || __wcsxfrm_l(transformed, left, 3, loc) != 5) return 14;
    }

    {
        struct tm time = {0};
        wchar_t rendered[32];
        time.tm_year = 70;
        time.tm_mon = 0;
        time.tm_mday = 1;
        if (wcsftime(rendered, 32, L"%Y", &time) != 4 || wcscmp(rendered, L"1970")) return 15;
        if (wcsftime_l(rendered, 32, L"%Y", &time, loc) != 4 || wcscmp(rendered, L"1970")) return 16;
    }

    if (!nl_langinfo_l(CODESET, loc)) return 17;
    {
        char *end;
        if (strtod_l("12.5", &end, loc) != 12.5 || *end) return 18;
        if (__strtod_l("7.25", &end, loc) != 7.25 || *end) return 19;
    }
    if (strerror_l(2, loc) != strerror(2)) return 20;

    __freelocale(loc);
    puts("m4 locale exports ok");
    return 0;
}

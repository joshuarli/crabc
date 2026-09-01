/* Native Linux/x86-64 built-in locale-object and localized-wide ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <langinfo.h>
#include <locale.h>
#include <stddef.h>
#include <wchar.h>
#include <wctype.h>

#if defined(CRABC_REQUIRE_STRICT_LANGINFO_LOCALE)
typedef char *(*strict_langinfo_l_signature)(nl_item, locale_t);

_Static_assert(sizeof(locale_t) == sizeof(void *) &&
    _Alignof(locale_t) == _Alignof(void *), "strict locale_t pointer ABI");
_Static_assert(sizeof(nl_item) == sizeof(int), "strict nl_item int ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&nl_langinfo_l),
    strict_langinfo_l_signature), "strict nl_langinfo_l declaration");

int crabc_x86_64_locale_object_wide_header_abi_probe(void)
{
    return 0;
}
#else
typedef locale_t (*newlocale_signature)(int, const char *, locale_t);
typedef void (*freelocale_signature)(locale_t);
typedef locale_t (*locale_unary_signature)(locale_t);
typedef char *(*langinfo_signature)(nl_item);
typedef char *(*langinfo_l_signature)(nl_item, locale_t);
typedef int (*isw_l_signature)(wint_t, locale_t);
typedef int (*iswctype_l_signature)(wint_t, wctype_t, locale_t);
typedef wctype_t (*wctype_l_signature)(const char *, locale_t);
typedef wint_t (*tow_l_signature)(wint_t, locale_t);
typedef wint_t (*towctrans_l_signature)(wint_t, wctrans_t, locale_t);
typedef wctrans_t (*wctrans_l_signature)(const char *, locale_t);
typedef int (*wide_compare_l_signature)(const wchar_t *, const wchar_t *, locale_t);
typedef int (*wide_ncompare_l_signature)(const wchar_t *, const wchar_t *, size_t, locale_t);
typedef size_t (*wide_xfrm_l_signature)(wchar_t *, const wchar_t *, size_t, locale_t);

_Static_assert(sizeof(locale_t) == sizeof(void *) &&
    _Alignof(locale_t) == _Alignof(void *), "locale_t pointer ABI");
_Static_assert((locale_t)LC_GLOBAL_LOCALE == (locale_t)-1,
    "LC_GLOBAL_LOCALE pointer sentinel");
_Static_assert(LC_CTYPE_MASK == 1 && LC_NUMERIC_MASK == 2 &&
    LC_TIME_MASK == 4 && LC_COLLATE_MASK == 8 && LC_MONETARY_MASK == 16 &&
    LC_MESSAGES_MASK == 32 && LC_ALL_MASK == 0x7fffffff,
    "locale category mask ABI");
_Static_assert(sizeof(nl_item) == sizeof(int), "nl_item int ABI");
_Static_assert(CODESET == 14 && RADIXCHAR == 0x10000 &&
    ABDAY_1 == 0x20000 && ERA_T_FMT == 0x20031 &&
    YESEXPR == 0x50000 && NOEXPR == 0x50001,
    "langinfo item ABI");

#define CHECK(name, signature) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(name)), signature), \
        #name " declaration")

CHECK(newlocale, newlocale_signature);
CHECK(freelocale, freelocale_signature);
CHECK(uselocale, locale_unary_signature);
CHECK(duplocale, locale_unary_signature);
CHECK(nl_langinfo, langinfo_signature);
CHECK(nl_langinfo_l, langinfo_l_signature);
CHECK(iswalnum_l, isw_l_signature);
CHECK(iswalpha_l, isw_l_signature);
CHECK(iswblank_l, isw_l_signature);
CHECK(iswcntrl_l, isw_l_signature);
CHECK(iswdigit_l, isw_l_signature);
CHECK(iswgraph_l, isw_l_signature);
CHECK(iswlower_l, isw_l_signature);
CHECK(iswprint_l, isw_l_signature);
CHECK(iswpunct_l, isw_l_signature);
CHECK(iswspace_l, isw_l_signature);
CHECK(iswupper_l, isw_l_signature);
CHECK(iswxdigit_l, isw_l_signature);
CHECK(iswctype_l, iswctype_l_signature);
CHECK(wctype_l, wctype_l_signature);
CHECK(towlower_l, tow_l_signature);
CHECK(towupper_l, tow_l_signature);
CHECK(towctrans_l, towctrans_l_signature);
CHECK(wctrans_l, wctrans_l_signature);
CHECK(wcscasecmp_l, wide_compare_l_signature);
CHECK(wcsncasecmp_l, wide_ncompare_l_signature);
CHECK(wcscoll_l, wide_compare_l_signature);
CHECK(wcsxfrm_l, wide_xfrm_l_signature);

int crabc_x86_64_locale_object_wide_header_abi_probe(void)
{
    return 0;
}
#endif

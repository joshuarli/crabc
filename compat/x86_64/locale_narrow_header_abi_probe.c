/* Native Linux/x86-64 fixed-locale narrow text ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <ctype.h>
#include <locale.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

#if defined(CRABC_REQUIRE_STRICT_STRING_LOCALE)
typedef int (*strict_compare_l_signature)(const char *, const char *, locale_t);
typedef int (*strict_ncompare_l_signature)(const char *, const char *, size_t, locale_t);

_Static_assert(sizeof(locale_t) == sizeof(void *) &&
    _Alignof(locale_t) == _Alignof(void *), "strict locale_t pointer ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strcasecmp_l),
    strict_compare_l_signature), "strict strcasecmp_l declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strncasecmp_l),
    strict_ncompare_l_signature), "strict strncasecmp_l declaration");

int crabc_x86_64_locale_narrow_header_abi_probe(void)
{
    return 0;
}
#else
typedef int (*ctype_l_signature)(int, locale_t);
typedef int (*compare_signature)(const char *, const char *);
typedef int (*compare_l_signature)(const char *, const char *, locale_t);
typedef int (*ncompare_signature)(const char *, const char *, size_t);
typedef int (*ncompare_l_signature)(const char *, const char *, size_t, locale_t);
typedef size_t (*xfrm_signature)(char *, const char *, size_t);
typedef size_t (*xfrm_l_signature)(char *, const char *, size_t, locale_t);

_Static_assert(sizeof(locale_t) == sizeof(void *) &&
    _Alignof(locale_t) == _Alignof(void *), "locale_t pointer ABI");
_Static_assert((locale_t)LC_GLOBAL_LOCALE == (locale_t)-1,
    "LC_GLOBAL_LOCALE pointer sentinel");
_Static_assert(LC_CTYPE_MASK == 1 && LC_COLLATE_MASK == 8 &&
    LC_ALL_MASK == 0x7fffffff, "selected locale mask ABI");

#define CHECK(name, signature) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(name)), signature), \
        #name " declaration")

CHECK(isalnum_l, ctype_l_signature);
CHECK(isalpha_l, ctype_l_signature);
CHECK(isblank_l, ctype_l_signature);
CHECK(iscntrl_l, ctype_l_signature);
CHECK(isdigit_l, ctype_l_signature);
CHECK(isgraph_l, ctype_l_signature);
CHECK(islower_l, ctype_l_signature);
CHECK(isprint_l, ctype_l_signature);
CHECK(ispunct_l, ctype_l_signature);
CHECK(isspace_l, ctype_l_signature);
CHECK(isupper_l, ctype_l_signature);
CHECK(isxdigit_l, ctype_l_signature);
CHECK(tolower_l, ctype_l_signature);
CHECK(toupper_l, ctype_l_signature);
CHECK(strcasecmp, compare_signature);
CHECK(strcasecmp_l, compare_l_signature);
CHECK(strncasecmp, ncompare_signature);
CHECK(strncasecmp_l, ncompare_l_signature);
CHECK(strcoll, compare_signature);
CHECK(strcoll_l, compare_l_signature);
CHECK(strxfrm, xfrm_signature);
CHECK(strxfrm_l, xfrm_l_signature);

int crabc_x86_64_locale_narrow_header_abi_probe(void)
{
    return 0;
}
#endif

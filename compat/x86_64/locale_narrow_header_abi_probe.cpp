/* Native Linux/x86-64 C++17 fixed-locale narrow text C-linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <ctype.h>
#include <locale.h>
#include <string.h>
#include <strings.h>

#if defined(CRABC_REQUIRE_STRICT_STRING_LOCALE)
using strict_compare_l_signature = int (*)(const char *, const char *, locale_t);
using strict_ncompare_l_signature = int (*)(const char *, const char *, size_t, locale_t);

static_assert(sizeof(locale_t) == sizeof(void *));
static_assert(__is_same(decltype(&strcasecmp_l), strict_compare_l_signature));
static_assert(__is_same(decltype(&strncasecmp_l), strict_ncompare_l_signature));

auto *crabc_strict_strcasecmp_l = &strcasecmp_l;
auto *crabc_strict_strncasecmp_l = &strncasecmp_l;
#else
static_assert(sizeof(locale_t) == sizeof(void *));
static_assert(LC_CTYPE_MASK == 1 && LC_COLLATE_MASK == 8 &&
    LC_ALL_MASK == 0x7fffffff);

#define REFERENCE(name) auto *crabc_locale_narrow_##name = &(name)
REFERENCE(isalnum_l);
REFERENCE(isalpha_l);
REFERENCE(isblank_l);
REFERENCE(iscntrl_l);
REFERENCE(isdigit_l);
REFERENCE(isgraph_l);
REFERENCE(islower_l);
REFERENCE(isprint_l);
REFERENCE(ispunct_l);
REFERENCE(isspace_l);
REFERENCE(isupper_l);
REFERENCE(isxdigit_l);
REFERENCE(tolower_l);
REFERENCE(toupper_l);
REFERENCE(strcasecmp);
REFERENCE(strcasecmp_l);
REFERENCE(strncasecmp);
REFERENCE(strncasecmp_l);
REFERENCE(strcoll);
REFERENCE(strcoll_l);
REFERENCE(strxfrm);
REFERENCE(strxfrm_l);
#endif

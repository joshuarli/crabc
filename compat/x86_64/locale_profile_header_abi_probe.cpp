/*
 * Native Linux/x86-64 C++17 fixed-locale-profile header ABI/linkage probe.
 *
 * The used references intentionally retain the two unmangled C spellings for
 * inspection. This probe establishes no locale-object, conversion, collation,
 * iconv, gettext, time, stdio, or general locale-database boundary.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE) || \
    defined(_LARGEFILE64_SOURCE)
#error "this probe intentionally uses the strict base header surface"
#endif

#include <limits.h>
#include <locale.h>
#include <stddef.h>

static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8,
    "x86 LP64 pointer and size_t widths");
static_assert(CHAR_MAX == 127 && CHAR_MIN == -128,
    "x86 signed plain char");
static_assert(LC_CTYPE == 0 && LC_NUMERIC == 1 && LC_TIME == 2 &&
    LC_COLLATE == 3 && LC_MONETARY == 4 && LC_MESSAGES == 5 && LC_ALL == 6,
    "musl locale category values");
static_assert(sizeof(struct lconv) == 96 && alignof(struct lconv) == 8,
    "x86 struct lconv ABI");
static_assert(__builtin_offsetof(struct lconv, decimal_point) == 0 &&
    __builtin_offsetof(struct lconv, thousands_sep) == 8 &&
    __builtin_offsetof(struct lconv, grouping) == 16 &&
    __builtin_offsetof(struct lconv, int_curr_symbol) == 24 &&
    __builtin_offsetof(struct lconv, currency_symbol) == 32 &&
    __builtin_offsetof(struct lconv, mon_decimal_point) == 40 &&
    __builtin_offsetof(struct lconv, mon_thousands_sep) == 48 &&
    __builtin_offsetof(struct lconv, mon_grouping) == 56 &&
    __builtin_offsetof(struct lconv, positive_sign) == 64 &&
    __builtin_offsetof(struct lconv, negative_sign) == 72 &&
    __builtin_offsetof(struct lconv, int_frac_digits) == 80 &&
    __builtin_offsetof(struct lconv, frac_digits) == 81 &&
    __builtin_offsetof(struct lconv, p_cs_precedes) == 82 &&
    __builtin_offsetof(struct lconv, p_sep_by_space) == 83 &&
    __builtin_offsetof(struct lconv, n_cs_precedes) == 84 &&
    __builtin_offsetof(struct lconv, n_sep_by_space) == 85 &&
    __builtin_offsetof(struct lconv, p_sign_posn) == 86 &&
    __builtin_offsetof(struct lconv, n_sign_posn) == 87 &&
    __builtin_offsetof(struct lconv, int_p_cs_precedes) == 88 &&
    __builtin_offsetof(struct lconv, int_p_sep_by_space) == 89 &&
    __builtin_offsetof(struct lconv, int_n_cs_precedes) == 90 &&
    __builtin_offsetof(struct lconv, int_n_sep_by_space) == 91 &&
    __builtin_offsetof(struct lconv, int_p_sign_posn) == 92 &&
    __builtin_offsetof(struct lconv, int_n_sign_posn) == 93,
    "x86 struct lconv field layout");
static_assert(__is_same(decltype(((struct lconv *)0)->decimal_point), char *) &&
    __is_same(decltype(((struct lconv *)0)->int_frac_digits), char),
    "struct lconv pointer and char field types");

using crabc_setlocale_signature = char *(*)(int, const char *);
using crabc_localeconv_signature = struct lconv *(*)(void);

static_assert(__is_same(decltype(&setlocale), crabc_setlocale_signature),
    "setlocale C++ declaration");
static_assert(__is_same(decltype(&localeconv), crabc_localeconv_signature),
    "localeconv C++ declaration");

__attribute__((used)) static crabc_setlocale_signature
    crabc_locale_profile_setlocale = &setlocale;
__attribute__((used)) static crabc_localeconv_signature
    crabc_locale_profile_localeconv = &localeconv;

int crabc_x86_64_locale_profile_header_abi_probe_cpp()
{
    return 0;
}

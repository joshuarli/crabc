/*
 * Native Linux/x86-64 C11 fixed-locale-profile header ABI probe.
 *
 * This deliberately covers only the unconditional `<locale.h>` profile
 * boundary: six category constants, `struct lconv`, `setlocale`, and
 * `localeconv`. It does not select locale objects, `_l` APIs, multibyte
 * conversion, collation, iconv, gettext, time conversion, or stdio.
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

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8,
    "x86 LP64 pointer and size_t widths");
_Static_assert(CHAR_MAX == 127 && CHAR_MIN == -128,
    "x86 signed plain char");
_Static_assert(LC_CTYPE == 0 && LC_NUMERIC == 1 && LC_TIME == 2 &&
    LC_COLLATE == 3 && LC_MONETARY == 4 && LC_MESSAGES == 5 && LC_ALL == 6,
    "musl locale category values");
_Static_assert(sizeof(struct lconv) == 96 && _Alignof(struct lconv) == 8,
    "x86 struct lconv ABI");
_Static_assert(__builtin_offsetof(struct lconv, decimal_point) == 0 &&
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
_Static_assert(CRABC_TYPE_IS(__typeof__(((struct lconv *)0)->decimal_point),
    char *) && CRABC_TYPE_IS(__typeof__(((struct lconv *)0)->int_frac_digits),
    char), "struct lconv pointer and char field types");

typedef char *(*crabc_setlocale_signature)(int, const char *);
typedef struct lconv *(*crabc_localeconv_signature)(void);

_Static_assert(CRABC_TYPE_IS(__typeof__(&setlocale),
    crabc_setlocale_signature), "setlocale declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&localeconv),
    crabc_localeconv_signature), "localeconv declaration");

int crabc_x86_64_locale_profile_header_abi_probe_c(void)
{
    return 0;
}

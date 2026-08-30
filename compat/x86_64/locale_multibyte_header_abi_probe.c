/*
 * Native Linux/x86-64 C11 locale/multibyte header ABI probe.
 *
 * Pinned musl 1.2.6 defines this narrow declaration/layout contract.  It
 * deliberately covers only the selected C/POSIX/C.UTF-8 locale-selection and
 * multibyte conversion boundary: `setlocale`, `localeconv`, MB_CUR_MAX, and
 * the named stateless/state-record conversions.  It does not select
 * `locale_t`, locale-object APIs, `_l` APIs, collation, iconv, or wide stdio.
 * The runner compiles this source against both header trees; it does not link
 * or claim a callable C runtime.
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

#include <locale.h>
#include <limits.h>
#include <stdlib.h>
#include <wchar.h>

#define CRABC_TYPE_IS(actual, expected) __builtin_types_compatible_p(actual, expected)

_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8,
    "x86 LP64 pointer and size_t widths");
_Static_assert(CHAR_MAX == 127 && CHAR_MIN == -128,
    "x86 signed plain char");
_Static_assert(sizeof(wchar_t) == 4 && (wchar_t)-1 < 0,
    "x86 wchar_t is signed 32-bit");
_Static_assert(sizeof(wint_t) == 4 && (wint_t)-1 > 0,
    "x86 wint_t is unsigned 32-bit");
_Static_assert(sizeof(mbstate_t) == 8 && _Alignof(mbstate_t) == 4,
    "x86 mbstate_t ABI");
_Static_assert(__builtin_offsetof(mbstate_t, __opaque1) == 0 &&
    __builtin_offsetof(mbstate_t, __opaque2) == 4 &&
    sizeof(((mbstate_t *)0)->__opaque1) == sizeof(unsigned) &&
    sizeof(((mbstate_t *)0)->__opaque2) == sizeof(unsigned),
    "x86 mbstate_t opaque-word layout");

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
typedef size_t (*crabc_mb_cur_max_signature)(void);
typedef int (*crabc_mblen_signature)(const char *, size_t);
typedef int (*crabc_mbtowc_signature)(wchar_t *restrict,
    const char *restrict, size_t);
typedef int (*crabc_wctomb_signature)(char *, wchar_t);
typedef size_t (*crabc_mbstowcs_signature)(wchar_t *restrict,
    const char *restrict, size_t);
typedef size_t (*crabc_wcstombs_signature)(char *restrict,
    const wchar_t *restrict, size_t);
typedef wint_t (*crabc_btowc_signature)(int);
typedef int (*crabc_wctob_signature)(wint_t);
typedef int (*crabc_mbsinit_signature)(const mbstate_t *);
typedef size_t (*crabc_mbrtowc_signature)(wchar_t *restrict,
    const char *restrict, size_t, mbstate_t *restrict);
typedef size_t (*crabc_wcrtomb_signature)(char *restrict, wchar_t,
    mbstate_t *restrict);
typedef size_t (*crabc_mbrlen_signature)(const char *restrict, size_t,
    mbstate_t *restrict);
typedef size_t (*crabc_mbsrtowcs_signature)(wchar_t *restrict,
    const char **restrict, size_t, mbstate_t *restrict);
typedef size_t (*crabc_wcsrtombs_signature)(char *restrict,
    const wchar_t **restrict, size_t, mbstate_t *restrict);

_Static_assert(CRABC_TYPE_IS(__typeof__(&setlocale),
    crabc_setlocale_signature), "setlocale declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&localeconv),
    crabc_localeconv_signature), "localeconv declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&__ctype_get_mb_cur_max),
    crabc_mb_cur_max_signature), "__ctype_get_mb_cur_max declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(MB_CUR_MAX), size_t),
    "MB_CUR_MAX expression type");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mblen), crabc_mblen_signature),
    "mblen declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mbtowc), crabc_mbtowc_signature),
    "mbtowc declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wctomb), crabc_wctomb_signature),
    "wctomb declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mbstowcs),
    crabc_mbstowcs_signature), "mbstowcs declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcstombs),
    crabc_wcstombs_signature), "wcstombs declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&btowc), crabc_btowc_signature),
    "btowc declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wctob), crabc_wctob_signature),
    "wctob declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mbsinit), crabc_mbsinit_signature),
    "mbsinit declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mbrtowc),
    crabc_mbrtowc_signature), "mbrtowc declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcrtomb), crabc_wcrtomb_signature),
    "wcrtomb declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mbrlen), crabc_mbrlen_signature),
    "mbrlen declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&mbsrtowcs),
    crabc_mbsrtowcs_signature), "mbsrtowcs declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&wcsrtombs),
    crabc_wcsrtombs_signature), "wcsrtombs declaration");

/*
 * Native Linux/x86-64 C++17 locale/multibyte header ABI and linkage probe.
 *
 * The `used` references intentionally leave undefined names in this object.
 * The runner verifies that all of them are unmangled C spellings requested by
 * the project headers.  It does not link a candidate archive or select
 * locale-object APIs, `_l` APIs, collation, iconv, or wide stdio.
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

static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8,
    "x86 LP64 pointer and size_t widths");
static_assert(CHAR_MAX == 127 && CHAR_MIN == -128,
    "x86 signed plain char");
static_assert(sizeof(wchar_t) == 4 && static_cast<wchar_t>(-1) < 0,
    "x86 wchar_t is signed 32-bit");
static_assert(sizeof(wint_t) == 4 && static_cast<wint_t>(-1) > 0,
    "x86 wint_t is unsigned 32-bit");
static_assert(sizeof(mbstate_t) == 8 && alignof(mbstate_t) == 4,
    "x86 mbstate_t ABI");
static_assert(__builtin_offsetof(mbstate_t, __opaque1) == 0 &&
    __builtin_offsetof(mbstate_t, __opaque2) == 4 &&
    sizeof(((mbstate_t *)0)->__opaque1) == sizeof(unsigned) &&
    sizeof(((mbstate_t *)0)->__opaque2) == sizeof(unsigned),
    "x86 mbstate_t opaque-word layout");

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
using crabc_mb_cur_max_signature = size_t (*)(void);
using crabc_mblen_signature = int (*)(const char *, size_t);
using crabc_mbtowc_signature = int (*)(wchar_t *__restrict,
    const char *__restrict, size_t);
using crabc_wctomb_signature = int (*)(char *, wchar_t);
using crabc_mbstowcs_signature = size_t (*)(wchar_t *__restrict,
    const char *__restrict, size_t);
using crabc_wcstombs_signature = size_t (*)(char *__restrict,
    const wchar_t *__restrict, size_t);
using crabc_btowc_signature = wint_t (*)(int);
using crabc_wctob_signature = int (*)(wint_t);
using crabc_mbsinit_signature = int (*)(const mbstate_t *);
using crabc_mbrtowc_signature = size_t (*)(wchar_t *__restrict,
    const char *__restrict, size_t, mbstate_t *__restrict);
using crabc_wcrtomb_signature = size_t (*)(char *__restrict, wchar_t,
    mbstate_t *__restrict);
using crabc_mbrlen_signature = size_t (*)(const char *__restrict, size_t,
    mbstate_t *__restrict);
using crabc_mbsrtowcs_signature = size_t (*)(wchar_t *__restrict,
    const char **__restrict, size_t, mbstate_t *__restrict);
using crabc_wcsrtombs_signature = size_t (*)(char *__restrict,
    const wchar_t **__restrict, size_t, mbstate_t *__restrict);

static_assert(__is_same(decltype(&setlocale), crabc_setlocale_signature),
    "setlocale C++ declaration");
static_assert(__is_same(decltype(&localeconv), crabc_localeconv_signature),
    "localeconv C++ declaration");
static_assert(__is_same(decltype(&__ctype_get_mb_cur_max),
    crabc_mb_cur_max_signature), "__ctype_get_mb_cur_max C++ declaration");
static_assert(__is_same(decltype(MB_CUR_MAX), size_t),
    "MB_CUR_MAX C++ expression type");
static_assert(__is_same(decltype(&mblen), crabc_mblen_signature),
    "mblen C++ declaration");
static_assert(__is_same(decltype(&mbtowc), crabc_mbtowc_signature),
    "mbtowc C++ declaration");
static_assert(__is_same(decltype(&wctomb), crabc_wctomb_signature),
    "wctomb C++ declaration");
static_assert(__is_same(decltype(&mbstowcs), crabc_mbstowcs_signature),
    "mbstowcs C++ declaration");
static_assert(__is_same(decltype(&wcstombs), crabc_wcstombs_signature),
    "wcstombs C++ declaration");
static_assert(__is_same(decltype(&btowc), crabc_btowc_signature),
    "btowc C++ declaration");
static_assert(__is_same(decltype(&wctob), crabc_wctob_signature),
    "wctob C++ declaration");
static_assert(__is_same(decltype(&mbsinit), crabc_mbsinit_signature),
    "mbsinit C++ declaration");
static_assert(__is_same(decltype(&mbrtowc), crabc_mbrtowc_signature),
    "mbrtowc C++ declaration");
static_assert(__is_same(decltype(&wcrtomb), crabc_wcrtomb_signature),
    "wcrtomb C++ declaration");
static_assert(__is_same(decltype(&mbrlen), crabc_mbrlen_signature),
    "mbrlen C++ declaration");
static_assert(__is_same(decltype(&mbsrtowcs), crabc_mbsrtowcs_signature),
    "mbsrtowcs C++ declaration");
static_assert(__is_same(decltype(&wcsrtombs), crabc_wcsrtombs_signature),
    "wcsrtombs C++ declaration");

/* `used` retains header-requested undefined references for nm inspection. */
__attribute__((used)) static crabc_setlocale_signature
    crabc_locale_multibyte_setlocale = &setlocale;
__attribute__((used)) static crabc_localeconv_signature
    crabc_locale_multibyte_localeconv = &localeconv;
__attribute__((used)) static crabc_mb_cur_max_signature
    crabc_locale_multibyte_mb_cur_max = &__ctype_get_mb_cur_max;
__attribute__((used)) static crabc_mblen_signature
    crabc_locale_multibyte_mblen = &mblen;
__attribute__((used)) static crabc_mbtowc_signature
    crabc_locale_multibyte_mbtowc = &mbtowc;
__attribute__((used)) static crabc_wctomb_signature
    crabc_locale_multibyte_wctomb = &wctomb;
__attribute__((used)) static crabc_mbstowcs_signature
    crabc_locale_multibyte_mbstowcs = &mbstowcs;
__attribute__((used)) static crabc_wcstombs_signature
    crabc_locale_multibyte_wcstombs = &wcstombs;
__attribute__((used)) static crabc_btowc_signature
    crabc_locale_multibyte_btowc = &btowc;
__attribute__((used)) static crabc_wctob_signature
    crabc_locale_multibyte_wctob = &wctob;
__attribute__((used)) static crabc_mbsinit_signature
    crabc_locale_multibyte_mbsinit = &mbsinit;
__attribute__((used)) static crabc_mbrtowc_signature
    crabc_locale_multibyte_mbrtowc = &mbrtowc;
__attribute__((used)) static crabc_wcrtomb_signature
    crabc_locale_multibyte_wcrtomb = &wcrtomb;
__attribute__((used)) static crabc_mbrlen_signature
    crabc_locale_multibyte_mbrlen = &mbrlen;
__attribute__((used)) static crabc_mbsrtowcs_signature
    crabc_locale_multibyte_mbsrtowcs = &mbsrtowcs;
__attribute__((used)) static crabc_wcsrtombs_signature
    crabc_locale_multibyte_wcsrtombs = &wcsrtombs;

int crabc_x86_64_locale_multibyte_header_abi_probe_cpp()
{
    return 0;
}

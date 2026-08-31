/* Native Linux/x86-64 selected <wchar.h>/<wctype.h> ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <wchar.h>
#include <wctype.h>

typedef size_t (*wcslen_signature)(const wchar_t *);
typedef size_t (*wcsnlen_signature)(const wchar_t *, size_t);
typedef wchar_t *(*wcscpy_signature)(wchar_t *, const wchar_t *);
typedef wchar_t *(*wcsncpy_signature)(wchar_t *, const wchar_t *, size_t);
typedef wchar_t *(*wcpcpy_signature)(wchar_t *, const wchar_t *);
typedef wchar_t *(*wcpncpy_signature)(wchar_t *, const wchar_t *, size_t);
typedef wchar_t *(*wcscat_signature)(wchar_t *, const wchar_t *);
typedef wchar_t *(*wcsncat_signature)(wchar_t *, const wchar_t *, size_t);
typedef int (*wcscmp_signature)(const wchar_t *, const wchar_t *);
typedef int (*wcsncmp_signature)(const wchar_t *, const wchar_t *, size_t);
typedef wchar_t *(*wcschr_signature)(const wchar_t *, wchar_t);
typedef wchar_t *(*wcsstr_signature)(const wchar_t *, const wchar_t *);
typedef size_t (*wcsspan_signature)(const wchar_t *, const wchar_t *);
typedef size_t (*wcsxfrm_signature)(wchar_t *, const wchar_t *, size_t);
typedef int (*wcstokcmp_signature)(const wchar_t *, const wchar_t *);
typedef wchar_t *(*wcstok_signature)(wchar_t *, const wchar_t *, wchar_t **);
typedef wchar_t *(*wmemchr_signature)(const wchar_t *, wchar_t, size_t);
typedef int (*wmemcmp_signature)(const wchar_t *, const wchar_t *, size_t);
typedef wchar_t *(*wmemcpy_signature)(wchar_t *, const wchar_t *, size_t);
typedef wchar_t *(*wmemmove_signature)(wchar_t *, const wchar_t *, size_t);
typedef wchar_t *(*wmemset_signature)(wchar_t *, wchar_t, size_t);
typedef int (*wcwidth_signature)(wchar_t);
typedef int (*wcswidth_signature)(const wchar_t *, size_t);
typedef int (*isw_signature)(wint_t);
typedef int (*iswctype_signature)(wint_t, wctype_t);
typedef wctype_t (*wctype_signature)(const char *);
typedef wint_t (*tow_signature)(wint_t);
typedef wint_t (*towctrans_signature)(wint_t, wctrans_t);
typedef wctrans_t (*wctrans_signature)(const char *);

_Static_assert(sizeof(wchar_t) == 4 && _Alignof(wchar_t) == 4,
    "x86 signed wchar_t ABI");
_Static_assert(WCHAR_MIN == INT32_MIN && WCHAR_MAX == INT32_MAX,
    "x86 wchar_t range");
_Static_assert(sizeof(wint_t) == 4 && _Alignof(wint_t) == 4 &&
    WEOF == UINT32_MAX, "x86 wint_t/WEOF ABI");
_Static_assert(sizeof(wctype_t) == 8 && _Alignof(wctype_t) == 8,
    "x86 wctype_t ABI");
_Static_assert(sizeof(wctrans_t) == sizeof(void *) &&
    _Alignof(wctrans_t) == _Alignof(void *), "x86 wctrans_t ABI");

#define CHECK(name, signature) \
    _Static_assert(__builtin_types_compatible_p(__typeof__(&(name)), signature), \
        #name " declaration")

CHECK(wcslen, wcslen_signature);
CHECK(wcsnlen, wcsnlen_signature);
CHECK(wcscpy, wcscpy_signature);
CHECK(wcsncpy, wcsncpy_signature);
CHECK(wcpcpy, wcpcpy_signature);
CHECK(wcpncpy, wcpncpy_signature);
CHECK(wcscat, wcscat_signature);
CHECK(wcsncat, wcsncat_signature);
CHECK(wcscmp, wcscmp_signature);
CHECK(wcsncmp, wcsncmp_signature);
CHECK(wcschr, wcschr_signature);
CHECK(wcsrchr, wcschr_signature);
CHECK(wcsstr, wcsstr_signature);
CHECK(wcscspn, wcsspan_signature);
CHECK(wcsspn, wcsspan_signature);
CHECK(wcspbrk, wcsstr_signature);
CHECK(wcsxfrm, wcsxfrm_signature);
CHECK(wcscoll, wcstokcmp_signature);
CHECK(wcstok, wcstok_signature);
CHECK(wcscasecmp, wcstokcmp_signature);
CHECK(wcsncasecmp, wcsncmp_signature);
CHECK(wmemchr, wmemchr_signature);
CHECK(wmemcmp, wmemcmp_signature);
CHECK(wmemcpy, wmemcpy_signature);
CHECK(wmemmove, wmemmove_signature);
CHECK(wmemset, wmemset_signature);
CHECK(wcwidth, wcwidth_signature);
CHECK(wcswidth, wcswidth_signature);
CHECK(iswalnum, isw_signature);
CHECK(iswalpha, isw_signature);
CHECK(iswblank, isw_signature);
CHECK(iswcntrl, isw_signature);
CHECK(iswdigit, isw_signature);
CHECK(iswgraph, isw_signature);
CHECK(iswlower, isw_signature);
CHECK(iswprint, isw_signature);
CHECK(iswpunct, isw_signature);
CHECK(iswspace, isw_signature);
CHECK(iswupper, isw_signature);
CHECK(iswxdigit, isw_signature);
CHECK(iswctype, iswctype_signature);
CHECK(wctype, wctype_signature);
CHECK(towlower, tow_signature);
CHECK(towupper, tow_signature);
CHECK(towctrans, towctrans_signature);
CHECK(wctrans, wctrans_signature);

int crabc_x86_64_wide_character_header_abi_probe(void)
{
    return 0;
}

/* Installed-header C witness for the selected native monetary ABI. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <monetary.h>

#include <stdint.h>

typedef ssize_t (*strfmon_signature)(char *restrict, size_t,
    const char *restrict, ...);
typedef ssize_t (*strfmon_l_signature)(char *restrict, size_t, locale_t,
    const char *restrict, ...);

_Static_assert(sizeof(ssize_t) == sizeof(long), "LP64 ssize_t");
_Static_assert(_Alignof(ssize_t) == _Alignof(long), "LP64 ssize_t alignment");
_Static_assert(sizeof(locale_t) == sizeof(void *), "opaque locale token width");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strfmon),
    strfmon_signature), "strfmon declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strfmon_l),
    strfmon_l_signature), "strfmon_l declaration");

/* These return values retain direct external C references in an object. */
strfmon_signature crabc_x86_64_strfmon_header_c(void) { return strfmon; }
strfmon_l_signature crabc_x86_64_strfmon_l_header_c(void) { return strfmon_l; }

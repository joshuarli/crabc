/* Source-only Linux/x86-64 wchar.h wcswcs declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <wchar.h>

typedef wchar_t *(*wcswcs_signature)(const wchar_t *, const wchar_t *);

_Static_assert(sizeof(wchar_t) == 4 && _Alignof(wchar_t) == 4,
    "x86 wchar_t ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wcswcs),
    wcswcs_signature), "wcswcs declaration");

static wcswcs_signature wcswcs_function __attribute__((used)) = wcswcs;

int crabc_x86_64_wcswcs_header_abi_probe(void)
{
    return wcswcs_function != (wcswcs_signature)0 ? 0 : 1;
}

/* Pinned-musl/project Linux/x86-64 fpathconf declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef long (*fpathconf_signature)(int, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&fpathconf),
    fpathconf_signature), "fpathconf declaration");
static fpathconf_signature fpathconf_signature_value __attribute__((used)) = fpathconf;

int crabc_x86_64_fpathconf_header_abi_probe(void)
{
    return fpathconf_signature_value != (fpathconf_signature)0 ? 0 : 1;
}

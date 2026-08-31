/* Pinned-musl/project Linux/x86-64 sysconf declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef long (*sysconf_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&sysconf),
    sysconf_signature), "sysconf declaration");
static sysconf_signature sysconf_signature_value __attribute__((used)) = sysconf;

int crabc_x86_64_sysconf_header_abi_probe(void)
{
    return sysconf_signature_value != (sysconf_signature)0 ? 0 : 1;
}

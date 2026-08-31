/* Pinned-musl/project Linux/x86-64 pathconf declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef long (*pathconf_signature)(const char *, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&pathconf),
    pathconf_signature), "pathconf declaration");
static pathconf_signature pathconf_signature_value __attribute__((used)) = pathconf;

int crabc_x86_64_pathconf_header_abi_probe(void)
{
    return pathconf_signature_value != (pathconf_signature)0 ? 0 : 1;
}

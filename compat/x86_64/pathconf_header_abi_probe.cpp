/* C++17 companion for the Linux/x86-64 pathconf declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using pathconf_signature = long (*)(const char *, int);

static_assert(__is_same(decltype(&pathconf), pathconf_signature),
              "C++ pathconf declaration");
static pathconf_signature pathconf_signature_value __attribute__((used)) = pathconf;

int crabc_x86_64_pathconf_header_abi_probe_cpp()
{
    return pathconf_signature_value != nullptr ? 0 : 1;
}

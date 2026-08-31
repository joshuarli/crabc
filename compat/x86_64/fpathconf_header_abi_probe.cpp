/* C++17 companion for the Linux/x86-64 fpathconf declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using fpathconf_signature = long (*)(int, int);

static_assert(__is_same(decltype(&fpathconf), fpathconf_signature),
              "C++ fpathconf declaration");
static fpathconf_signature fpathconf_signature_value __attribute__((used)) = fpathconf;

int crabc_x86_64_fpathconf_header_abi_probe_cpp()
{
    return fpathconf_signature_value != nullptr ? 0 : 1;
}

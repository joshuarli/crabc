/* C++17 companion for the Linux/x86-64 ttyname_r declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using ttyname_r_signature = int (*)(int, char *, size_t);

static_assert(__is_same(decltype(&ttyname_r), ttyname_r_signature),
    "C++ ttyname_r declaration");

static ttyname_r_signature ttyname_r_function = ttyname_r;

int crabc_x86_64_ttyname_r_header_abi_probe_cpp()
{
    return ttyname_r_function != nullptr ? 0 : 1;
}

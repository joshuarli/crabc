/* C++17 companion for the Linux/x86-64 isatty declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using isatty_signature = int (*)(int);

static_assert(__is_same(decltype(&isatty), isatty_signature),
    "C++ isatty declaration");

static isatty_signature isatty_function = isatty;

int crabc_x86_64_isatty_header_abi_probe_cpp()
{
    return isatty_function != nullptr ? 0 : 1;
}

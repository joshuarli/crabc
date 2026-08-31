/* C++17 companion for the pinned-musl/project posix_close declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using posix_close_signature = int (*)(int, int);

static_assert(sizeof(int) == 4 && alignof(int) == 4,
              "C++ x86 posix_close int ABI");
static_assert(__is_same(decltype(&posix_close), posix_close_signature),
              "C++ posix_close declaration");

static posix_close_signature posix_close_function __attribute__((used)) =
    posix_close;

int crabc_x86_64_posix_close_header_abi_probe_cpp()
{
    return posix_close_function != nullptr ? 0 : 1;
}

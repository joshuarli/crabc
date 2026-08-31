/* C++17 companion for selected Linux/x86-64 readlinkat headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using readlinkat_signature = ssize_t (*)(int, const char *, char *, size_t);

static_assert(sizeof(int) == 4 && alignof(int) == 4, "C++ x86 readlinkat int ABI");
static_assert(sizeof(size_t) == 8 && alignof(size_t) == 8,
              "C++ x86 readlinkat size_t ABI");
static_assert(sizeof(ssize_t) == 8 && alignof(ssize_t) == 8,
              "C++ x86 readlinkat ssize_t ABI");
static_assert(__is_same(decltype(&readlinkat), readlinkat_signature),
              "C++ readlinkat declaration");

__attribute__((used)) static readlinkat_signature crabc_readlinkat = readlinkat;

int crabc_x86_64_readlinkat_header_abi_probe_cpp()
{
    return static_cast<int>(readlinkat(-100, "fixture", nullptr, 0));
}

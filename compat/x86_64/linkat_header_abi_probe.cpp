/* C++17 companion for selected Linux/x86-64 linkat headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using linkat_signature = int (*)(int, const char *, int, const char *, int);

static_assert(sizeof(int) == 4 && alignof(int) == 4,
              "C++ x86 linkat int ABI");
static_assert(sizeof(char *) == 8 && alignof(char *) == 8,
              "C++ x86 linkat pointer ABI");
static_assert(__is_same(decltype(&linkat), linkat_signature),
              "C++ linkat declaration");

__attribute__((used)) static linkat_signature crabc_linkat = linkat;

int crabc_x86_64_linkat_header_abi_probe_cpp()
{
    return linkat(-100, "existing", -100, "new", 0);
}

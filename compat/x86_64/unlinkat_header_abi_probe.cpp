/* C++17 companion for selected Linux/x86-64 unlinkat headers. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

using unlinkat_signature = int (*)(int, const char *, int);

static_assert(AT_FDCWD == -100 && AT_REMOVEDIR == 0x200 &&
                  AT_SYMLINK_NOFOLLOW == 0x100,
              "C++ x86 unlinkat constants");
static_assert(SYS_unlinkat == 263, "C++ Linux x86 unlinkat syscall number");
static_assert(__is_same(decltype(&unlinkat), unlinkat_signature),
              "C++ unlinkat declaration");

__attribute__((used)) static unlinkat_signature crabc_unlinkat = unlinkat;

int crabc_x86_64_unlinkat_header_abi_probe_cpp()
{
    return unlinkat(AT_FDCWD, "unlinkat-header", 0);
}

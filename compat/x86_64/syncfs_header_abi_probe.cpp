/* Linux/x86-64 GNU C++17 <unistd.h> syncfs declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/syscall.h>
#include <unistd.h>

using syncfs_signature = int (*)(int);

static_assert(SYS_syncfs == 306, "x86 syncfs syscall number");

#if defined(CRABC_SYNCFS_REQUIRE_GNU) || \
    defined(CRABC_SYNCFS_REQUIRE_GNU_HIDDEN)
static_assert(__is_same(decltype(&syncfs), syncfs_signature),
    "GNU C++ syncfs declaration");
__attribute__((used)) static syncfs_signature crabc_syncfs_c_linkage = syncfs;
#endif

/* This opt-in reference must fail outside GNU feature selection. */
#if defined(CRABC_SYNCFS_REQUIRE_GNU_HIDDEN)
__attribute__((used)) static syncfs_signature crabc_syncfs_must_be_hidden =
    syncfs;
#endif

int crabc_x86_64_syncfs_header_abi_probe_cpp()
{
    return SYS_syncfs;
}

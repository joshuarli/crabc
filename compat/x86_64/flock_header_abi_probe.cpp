/* C++ source-only Linux/x86-64 <sys/file.h> ABI probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#include <sys/file.h>
#include <sys/syscall.h>

static_assert(LOCK_SH == 1 && LOCK_EX == 2 && LOCK_NB == 4 && LOCK_UN == 8,
    "x86 C++ flock operation bits");
static_assert(L_SET == 0 && L_INCR == 1 && L_XTND == 2,
    "x86 C++ lockf command values");
static_assert(SYS_flock == 73, "x86 C++ flock syscall number");

using flock_function = int (*)(int, int);
static_assert(__is_same(decltype(&flock), flock_function),
    "x86 C++ flock declaration and unmangled linkage");

int crabc_x86_64_file_header_abi_probe_cpp()
{
    return LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN;
}

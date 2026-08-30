/* Source-only Linux/x86-64 C++ <sys/sendfile.h> declaration/value probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#define _LARGEFILE64_SOURCE 1
#include <stdint.h>
#include <sys/sendfile.h>
#include <sys/syscall.h>

static_assert(sizeof(off_t) == sizeof(int64_t), "x86 sendfile off_t width");
static_assert(static_cast<off_t>(-1) < static_cast<off_t>(0),
              "x86 sendfile off_t signed");
static_assert(SYS_sendfile == 40, "x86 sendfile syscall number");
using sendfile_function = ssize_t (*)(int, int, off_t *, size_t);
using sendfile64_function = ssize_t (*)(int, int, off64_t *, size_t);
static_assert(__is_same(decltype(&sendfile), sendfile_function),
              "x86 sendfile declaration");
static_assert(__is_same(decltype(&sendfile64), sendfile64_function),
              "x86 sendfile64 declaration");

int crabc_x86_64_sendfile_header_abi_probe()
{
    return SYS_sendfile;
}

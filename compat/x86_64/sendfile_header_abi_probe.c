/* Source-only Linux/x86-64 <sys/sendfile.h> declaration/value probe. */

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

_Static_assert(sizeof(off_t) == sizeof(int64_t), "x86 sendfile off_t width");
_Static_assert((off_t)-1 < (off_t)0, "x86 sendfile off_t signed");
_Static_assert(SYS_sendfile == 40, "x86 sendfile syscall number");

static ssize_t (*sendfile_signature)(int, int, off_t *, size_t) = sendfile;
static ssize_t (*sendfile64_signature)(int, int, off64_t *, size_t) = sendfile64;

int crabc_x86_64_sendfile_header_abi_probe(void)
{
    (void)sendfile_signature;
    (void)sendfile64_signature;
    return SYS_sendfile;
}

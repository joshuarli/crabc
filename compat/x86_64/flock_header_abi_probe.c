/* Source-only Linux/x86-64 <sys/file.h> declaration/value probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#define _GNU_SOURCE 1
#include <sys/file.h>
#include <sys/syscall.h>

_Static_assert(LOCK_SH == 1 && LOCK_EX == 2 && LOCK_NB == 4 && LOCK_UN == 8,
    "x86 flock operation bits");
_Static_assert(L_SET == 0 && L_INCR == 1 && L_XTND == 2,
    "x86 lockf command values");
_Static_assert(SYS_flock == 73, "x86 flock syscall number");

static int (*flock_signature)(int, int) = flock;

int crabc_x86_64_file_header_abi_probe(void)
{
    (void)flock_signature;
    return LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN;
}

/* Linux/x86-64 selected <sys/mman.h> munlockall declaration probe.
 *
 * This declaration-only C profile matrix establishes the zero-argument C ABI.
 * It does not select mlockall, per-range locking, whole-process lock policy,
 * or a C runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

typedef int (*crabc_munlockall_type)(void);

_Static_assert(__builtin_types_compatible_p(__typeof__(&munlockall),
    crabc_munlockall_type), "munlockall declaration");

__attribute__((used)) static crabc_munlockall_type crabc_munlockall_c_linkage =
    munlockall;

int crabc_x86_64_munlockall_header_abi_probe(void)
{
    return 0;
}

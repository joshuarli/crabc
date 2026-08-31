/* Linux/x86-64 selected <sys/mman.h> mlockall declaration probe.
 *
 * This is deliberately a declaration-only C profile matrix. It establishes
 * the one-argument C ABI and the portable MCL_CURRENT/MCL_FUTURE vocabulary;
 * it does not select mlock, munlockall, mapping policy, or a C runtime.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

typedef int (*crabc_mlockall_type)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&mlockall),
    crabc_mlockall_type), "mlockall declaration");
_Static_assert(MCL_CURRENT == 1, "MCL_CURRENT ABI value");
_Static_assert(MCL_FUTURE == 2, "MCL_FUTURE ABI value");

__attribute__((used)) static crabc_mlockall_type crabc_mlockall_c_linkage =
    mlockall;

int crabc_x86_64_mlockall_header_abi_probe(void)
{
    return 0;
}

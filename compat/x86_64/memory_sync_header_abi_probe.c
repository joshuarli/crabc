/* Linux/x86-64 selected <sys/mman.h> mapping-synchronization profile probe.
 *
 * Pinned musl 1.2.6 owns the declaration, constant, feature-visibility, and
 * C-linkage contract. `msync` is visible in every selected C profile; this
 * source proves only that narrow header fact, not runtime behavior, pthread
 * cancellation, a complete mapping header, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

typedef int (*crabc_memory_sync_type)(void *, size_t, int);

_Static_assert(MS_ASYNC == 0x1, "MS_ASYNC value");
_Static_assert(MS_INVALIDATE == 0x2, "MS_INVALIDATE value");
_Static_assert(MS_SYNC == 0x4, "MS_SYNC value");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msync),
    crabc_memory_sync_type), "msync declaration");

static crabc_memory_sync_type crabc_memory_sync_c_linkage = msync;

int crabc_x86_64_memory_sync_header_abi_probe(void)
{
    return crabc_memory_sync_c_linkage == msync ? 0 : 1;
}

/* Linux/x86-64 selected <sys/mman.h> mapping-synchronization C++17 probe.
 *
 * `msync` remains visible in every selected C/C++ profile. This is only a
 * declaration/linkage check, not a cancellation or runtime claim.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

using memory_sync_type = int (*)(void *, size_t, int);

static_assert(__is_same(decltype(&msync), memory_sync_type),
    "C++ msync declaration");
static_assert(MS_ASYNC == 0x1 && MS_INVALIDATE == 0x2 && MS_SYNC == 0x4,
    "C++ msync values");

__attribute__((used)) static memory_sync_type crabc_memory_sync_cxx_linkage =
    msync;

int crabc_x86_64_memory_sync_header_abi_probe_cpp()
{
    return crabc_memory_sync_cxx_linkage == msync ? 0 : 1;
}

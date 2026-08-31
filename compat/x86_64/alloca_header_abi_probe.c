/* Source-only Linux/x86-64 <alloca.h> compiler-builtin declaration probe.
 *
 * `alloca` is intentionally exercised only through musl's public macro.
 * This probe does not select a callable alloca symbol or any allocator ABI.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <alloca.h>

#ifndef alloca
#error "musl-compatible alloca must be a compiler-builtin macro"
#endif

_Static_assert(sizeof(size_t) == 8, "x86-64 size_t width");
_Static_assert(__builtin_types_compatible_p(
    __typeof__(alloca((size_t)1)), void *),
    "alloca builtin result type");

int crabc_x86_64_alloca_header_abi_probe(void)
{
    void *storage = alloca((size_t)1);

    return storage == 0;
}

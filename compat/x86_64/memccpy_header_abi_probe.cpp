/* C++ companion for the native x86-64 <string.h> memccpy declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

using memccpy_signature = void *(*)(void *, const void *, int, size_t);

#if defined(CRABC_EXPECT_MEMCCPY)
static_assert(__is_same(decltype(&memccpy), memccpy_signature),
              "memccpy declaration");
#endif

int crabc_x86_64_memccpy_header_abi_probe_cpp()
{
    return 0;
}

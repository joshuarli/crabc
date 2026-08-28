/* C++ companion for the native x86-64 <string.h> memory-search probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>

using byte_search_signature = void *(*)(const void *, int, size_t);
using memory_search_signature = void *(*)(const void *, size_t, const void *, size_t);

static_assert(__is_same(decltype(&memchr), byte_search_signature),
              "memchr declaration");
static_assert(__is_same(decltype(&memmem), memory_search_signature),
              "memmem POSIX/GNU declaration");
static_assert(__is_same(decltype(&memrchr), byte_search_signature),
              "memrchr GNU declaration");

int crabc_x86_64_memory_search_header_abi_probe_cpp()
{
    return 0;
}

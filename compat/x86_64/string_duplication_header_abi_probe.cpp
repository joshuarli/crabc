/* C++ companion for the native x86-64 <string.h> duplication probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>

using duplicate_signature = char *(*)(const char *);
using bounded_duplicate_signature = char *(*)(const char *, size_t);

static_assert(__is_same(decltype(&strdup), duplicate_signature),
              "strdup declaration");
static_assert(__is_same(decltype(&strndup), bounded_duplicate_signature),
              "strndup declaration");

int crabc_x86_64_string_duplication_header_abi_probe_cpp()
{
    return 0;
}

/* C++ companion for the native x86-64 <string.h> C-string copy probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>

using copy_signature = char *(*)(char *, const char *);
using bounded_copy_signature = char *(*)(char *, const char *, size_t);
using sized_copy_signature = size_t (*)(char *, const char *, size_t);

static_assert(__is_same(decltype(&strcpy), copy_signature),
              "strcpy declaration");
static_assert(__is_same(decltype(&strncpy), bounded_copy_signature),
              "strncpy declaration");
static_assert(__is_same(decltype(&strcat), copy_signature),
              "strcat declaration");
static_assert(__is_same(decltype(&strncat), bounded_copy_signature),
              "strncat declaration");
static_assert(__is_same(decltype(&stpcpy), copy_signature),
              "stpcpy declaration");
static_assert(__is_same(decltype(&stpncpy), bounded_copy_signature),
              "stpncpy declaration");
static_assert(__is_same(decltype(&strlcpy), sized_copy_signature),
              "strlcpy declaration");
static_assert(__is_same(decltype(&strlcat), sized_copy_signature),
              "strlcat declaration");

int crabc_x86_64_string_copy_header_abi_probe_cpp()
{
    return 0;
}

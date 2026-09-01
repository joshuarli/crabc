/* C++ companion for the native x86-64 <string.h> C-string copy probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>
/* Match the consumer-provided builtin spelling needed by the C macro use. */
#include <alloca.h>

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

#if defined(CRABC_EXPECT_STRDUPA)
#ifndef strdupa
#error "GNU/compiler-native C++ <string.h> must expose strdupa"
#endif
#endif

#if defined(CRABC_REQUIRE_STRDUPA_HIDDEN)
#ifdef strdupa
#error "non-GNU C <string.h> must hide strdupa"
#endif
#endif

/*
 * Exact musl syntax stays visible to C++ but cannot expand: alloca returns
 * void *, while C++ strcpy requires char *. The runner requires this failure.
 */
#if defined(CRABC_REQUIRE_STRDUPA_CPP_EXPANSION_REJECTED)
static char *strdupa_cpp_expansion_must_be_rejected()
{
    return strdupa("stack copy");
}
#endif

int crabc_x86_64_string_copy_header_abi_probe_cpp()
{
    return 0;
}

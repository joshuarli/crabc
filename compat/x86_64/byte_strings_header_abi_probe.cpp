/* C++ companion for the native x86-64 <string.h> byte-string probe. */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>
#include <strings.h>

using char_search_signature = char *(*)(const char *, int);
using compare_signature = int (*)(const char *, const char *);
using bounded_compare_signature = int (*)(const char *, const char *, size_t);
using span_signature = size_t (*)(const char *, const char *);
using length_signature = size_t (*)(const char *);
using bounded_length_signature = size_t (*)(const char *, size_t);

static_assert(__is_same(decltype(&strchr), char_search_signature), "strchr declaration");
static_assert(__is_same(decltype(&strrchr), char_search_signature), "strrchr declaration");
static_assert(__is_same(decltype(&strcmp), compare_signature), "strcmp declaration");
static_assert(__is_same(decltype(&strncmp), bounded_compare_signature), "strncmp declaration");
static_assert(__is_same(decltype(&strcspn), span_signature), "strcspn declaration");
static_assert(__is_same(decltype(&strspn), span_signature), "strspn declaration");
static_assert(__is_same(decltype(&strlen), length_signature), "strlen declaration");
static_assert(__is_same(decltype(&strnlen), bounded_length_signature), "strnlen declaration");
static_assert(__is_same(decltype(&strpbrk), char *(*)(const char *, const char *)),
              "strpbrk declaration");
static_assert(__is_same(decltype(&strstr), char *(*)(const char *, const char *)),
              "strstr declaration");

#if defined(CRABC_EXPECT_GNU)
static_assert(__is_same(decltype(&strverscmp), compare_signature),
              "strverscmp GNU declaration");
static_assert(__is_same(decltype(&strchrnul), char_search_signature),
              "strchrnul GNU declaration");
#endif

#if defined(CRABC_EXPECT_ALIASES)
static_assert(__is_same(decltype(&index), char_search_signature), "index declaration");
static_assert(__is_same(decltype(&rindex), char_search_signature), "rindex declaration");
#endif

#if defined(CRABC_REQUIRE_STRCHRNUL)
static char_search_signature required_strchrnul_signature = strchrnul;
#endif

#if defined(CRABC_REQUIRE_STRVERSCMP)
static compare_signature required_strverscmp_signature = strverscmp;
#endif

int crabc_x86_64_byte_strings_header_abi_probe_cpp()
{
    return 0;
}

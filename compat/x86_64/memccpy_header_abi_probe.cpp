/* C++ companion for the Linux/x86-64 <string.h> memccpy declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

#if defined(CRABC_EXPECT_MEMCCPY)
using memccpy_signature = void *(*)(void *, const void *, int, size_t);

static_assert(__is_same(decltype(&memccpy), memccpy_signature),
    "memccpy C++ declaration");

static memccpy_signature memccpy_function = memccpy;
#endif

/* An opt-in reference that must fail outside X/Open/GNU/BSD selection. */
#if defined(CRABC_REQUIRE_MEMCCPY_HIDDEN)
using hidden_memccpy_signature = void *(*)(void *, const void *, int, size_t);
static hidden_memccpy_signature memccpy_must_be_hidden = memccpy;
#endif

int crabc_x86_64_memccpy_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_MEMCCPY)
    return memccpy_function != nullptr ? 0 : 1;
#else
    return 0;
#endif
}

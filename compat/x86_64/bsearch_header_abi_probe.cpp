/* C++17 companion for the Linux/x86-64 stdlib bsearch declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

using bsearch_compare_signature = int (*)(const void *, const void *);
using bsearch_signature = void *(*)(
    const void *, const void *, size_t, size_t, bsearch_compare_signature);

static_assert(__is_same(decltype(&bsearch), bsearch_signature),
    "C++ bsearch declaration");

static bsearch_signature bsearch_function __attribute__((used)) = bsearch;

int crabc_x86_64_bsearch_header_abi_probe_cpp()
{
    return bsearch_function != nullptr ? 0 : 1;
}

/* C++17 companion for the Linux/x86-64 search.h linear-search declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <search.h>

using linear_search_compare_signature = int (*)(const void *, const void *);
using lfind_signature = void *(*) (
    const void *, const void *, size_t *, size_t, linear_search_compare_signature);
using lsearch_signature = void *(*) (
    const void *, void *, size_t *, size_t, linear_search_compare_signature);

static_assert(__is_same(decltype(&lfind), lfind_signature),
    "C++ lfind declaration");
static_assert(__is_same(decltype(&lsearch), lsearch_signature),
    "C++ lsearch declaration");

static lfind_signature lfind_function __attribute__((used)) = lfind;
static lsearch_signature lsearch_function __attribute__((used)) = lsearch;

int crabc_x86_64_linear_search_header_abi_probe_cpp()
{
    return lfind_function != nullptr && lsearch_function != nullptr ? 0 : 1;
}

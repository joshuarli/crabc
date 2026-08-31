/* Source-only Linux/x86-64 search.h lfind/lsearch declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <search.h>

typedef int (*linear_search_compare_signature)(const void *, const void *);
typedef void *(*lfind_signature)(
    const void *, const void *, size_t *, size_t, linear_search_compare_signature);
typedef void *(*lsearch_signature)(
    const void *, void *, size_t *, size_t, linear_search_compare_signature);

_Static_assert(__builtin_types_compatible_p(__typeof__(&lfind),
    lfind_signature), "lfind declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&lsearch),
    lsearch_signature), "lsearch declaration");

static lfind_signature lfind_function __attribute__((used)) = lfind;
static lsearch_signature lsearch_function __attribute__((used)) = lsearch;

int crabc_x86_64_linear_search_header_abi_probe(void)
{
    return lfind_function != (lfind_signature)0 &&
            lsearch_function != (lsearch_signature)0 ? 0 : 1;
}

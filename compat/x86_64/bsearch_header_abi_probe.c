/* Source-only Linux/x86-64 stdlib bsearch declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

typedef int (*bsearch_compare_signature)(const void *, const void *);
typedef void *(*bsearch_signature)(
    const void *, const void *, size_t, size_t, bsearch_compare_signature);

_Static_assert(__builtin_types_compatible_p(__typeof__(&bsearch),
    bsearch_signature), "bsearch declaration");

static bsearch_signature bsearch_function __attribute__((used)) = bsearch;

int crabc_x86_64_bsearch_header_abi_probe(void)
{
    return bsearch_function != (bsearch_signature)0 ? 0 : 1;
}

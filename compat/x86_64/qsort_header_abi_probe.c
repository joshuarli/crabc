/* Source-only Linux/x86-64 stdlib qsort declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

typedef int (*qsort_compare_signature)(const void *, const void *);
typedef void (*qsort_signature)(void *, size_t, size_t,
                                qsort_compare_signature);

_Static_assert(__builtin_types_compatible_p(__typeof__(&qsort),
    qsort_signature), "qsort declaration");

static qsort_signature qsort_function __attribute__((used)) = qsort;

int crabc_x86_64_qsort_header_abi_probe(void)
{
    return qsort_function != 0 ? 0 : 1;
}

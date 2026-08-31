/* C++ companion for the Linux/x86-64 stdlib qsort declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

using qsort_compare_signature = int (*)(const void *, const void *);
using qsort_signature = void (*)(void *, size_t, size_t,
                                 qsort_compare_signature);

static qsort_signature qsort_function __attribute__((used)) = qsort;

int crabc_x86_64_qsort_header_abi_probe_cpp()
{
    return qsort_function != nullptr ? 0 : 1;
}

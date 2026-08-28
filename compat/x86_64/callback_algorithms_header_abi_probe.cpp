/* C++ companion for the Linux/x86-64 stdlib callback-algorithms probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdlib.h>

using compare_signature = int (*)(const void *, const void *);
using compare_context_signature = int (*)(const void *, const void *, void *);
using bsearch_signature = void *(*)
    (const void *, const void *, size_t, size_t, compare_signature);
using qsort_signature = void (*)(void *, size_t, size_t,
                                 compare_signature);
using qsort_r_signature = void (*)(void *, size_t, size_t,
                                   compare_context_signature, void *);

static bsearch_signature bsearch_function __attribute__((used)) = bsearch;
static qsort_signature qsort_function __attribute__((used)) = qsort;

#if defined(CRABC_EXPECT_QSORT_R) || defined(CRABC_REQUIRE_QSORT_R)
static qsort_r_signature qsort_r_function __attribute__((used)) = qsort_r;
#endif

/* __qsort_r is musl-private and must never leak through installed headers. */
#if defined(CRABC_REQUIRE_INTERNAL_QSORT_R)
static qsort_r_signature internal_qsort_r_function __attribute__((used)) =
    __qsort_r;
#endif

int crabc_x86_64_callback_algorithms_header_abi_probe_cpp()
{
    return bsearch_function != nullptr && qsort_function != nullptr ? 0 : 1;
}

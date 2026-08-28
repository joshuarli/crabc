/* Source-only Linux/x86-64 <string.h> memory-search declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <string.h>

typedef void *(*byte_search_signature)(const void *, int, size_t);
typedef void *(*memory_search_signature)(const void *, size_t, const void *, size_t);

static byte_search_signature memchr_signature = memchr;

#if defined(CRABC_EXPECT_MEMMEM)
static memory_search_signature memmem_signature = memmem;
#endif

#if defined(CRABC_EXPECT_MEMRCHR)
static byte_search_signature memrchr_signature = memrchr;
#endif

/* These branches are compiled only as expected-failure checks. */
#if defined(CRABC_EXPECT_MEMMEM_HIDDEN)
static memory_search_signature required_memmem_signature = memmem;
#endif

#if defined(CRABC_EXPECT_MEMRCHR_HIDDEN)
static byte_search_signature required_memrchr_signature = memrchr;
#endif

int crabc_x86_64_memory_search_header_abi_probe(void)
{
    (void)memchr_signature;
#if defined(CRABC_EXPECT_MEMMEM)
    (void)memmem_signature;
#endif
#if defined(CRABC_EXPECT_MEMRCHR)
    (void)memrchr_signature;
#endif
#if defined(CRABC_EXPECT_MEMMEM_HIDDEN)
    (void)required_memmem_signature;
#endif
#if defined(CRABC_EXPECT_MEMRCHR_HIDDEN)
    (void)required_memrchr_signature;
#endif
    return 0;
}

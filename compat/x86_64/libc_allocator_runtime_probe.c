/*
 * Native Linux/x86-64 C allocator boundary probe.
 *
 * The same body executes against pinned musl and against the opt-in static
 * crabc-libc allocator backend. The mixed-runtime candidate supplies the
 * target-owned wrapper, errno slot, and bundled backend; pinned musl supplies
 * the still-missing static startup and process primitives, but never an
 * allocator entry point.
 *
 * This checks return/error/data/alignment/liveness results, not allocation
 * addresses after free: reuse topology is allocator-private rather than a
 * musl C ABI guarantee. Live zero-size results remain separately checked
 * for musl's distinct-object behavior.
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#ifdef CRABC_ALLOCATOR_RUNTIME_CANDIDATE
extern size_t __crabc_x86_allocator_runtime_v1(void);
#endif

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index) {
        if (left[index] != right[index])
            return 0;
    }
    return 1;
}

int crabc_x86_64_allocator_runtime_probe(void)
{
    static const size_t sizes[] = { 1, 15, 16, 17, 4096, 262144 };
    /* musl 1.2.6 mallocng uses UNIT == 16 on this LP64 target. */
    static const size_t musl_mallocng_max_alignment = ((size_t)1 << 31) * 16;
    static const unsigned char prefix[] = { 1, 2, 3, 4 };
    unsigned char *zero_a;
    unsigned char *zero_b;
    unsigned char *block;
    unsigned char *resized;
    void *aligned;
    void *page_aligned;
    size_t index;

#ifdef CRABC_ALLOCATOR_RUNTIME_CANDIDATE
    if (__crabc_x86_allocator_runtime_v1() != 1)
        return 100;
#endif

    /* malloc(0) is implementation-defined; this records the pinned-musl
     * non-null, distinct, naturally aligned result. */
    errno = E2BIG;
    zero_a = malloc(0);
    zero_b = malloc(0);
    if (zero_a == NULL || zero_b == NULL || zero_a == zero_b ||
        (uintptr_t)zero_a % 16 != 0 || (uintptr_t)zero_b % 16 != 0 ||
        errno != E2BIG)
        return 1;
    free(zero_a);
    free(zero_b);
    if (errno != E2BIG)
        return 2;
    free(NULL);
    if (errno != E2BIG)
        return 26;

    for (index = 0; index < sizeof(sizes) / sizeof(sizes[0]); ++index) {
        block = malloc(sizes[index]);
        if (block == NULL || (uintptr_t)block % 16 != 0)
            return 3;
        block[0] = (unsigned char)index;
        block[sizes[index] - 1] = (unsigned char)(index + 17);
        free(block);
    }
    block = malloc(262144);
    if (block == NULL)
        return 27;
    errno = ECHILD;
    free(block);
    if (errno != ECHILD)
        return 40;

    /* A freed allocation must leave the same allocation route live, but
     * address reuse itself is intentionally not an assertion. */
    block = malloc(4096);
    if (block == NULL)
        return 28;
    block[0] = 0x43;
    block[4095] = 0x8e;
    free(block);
    block = malloc(4096);
    if (block == NULL || (uintptr_t)block % 16 != 0)
        return 29;
    block[0] = 0xa6;
    block[4095] = 0x19;
    if (block[0] != 0xa6 || block[4095] != 0x19)
        return 30;
    free(block);

    errno = 0;
    if (malloc((size_t)-1) != NULL || errno != ENOMEM)
        return 31;

    block = malloc(sizeof(prefix));
    if (block == NULL)
        return 4;
    for (index = 0; index < sizeof(prefix); ++index)
        block[index] = prefix[index];
    block = realloc(block, 8192);
    if (block == NULL || (uintptr_t)block % 16 != 0 ||
        !bytes_equal(block, prefix, sizeof(prefix)))
        return 5;
    block = realloc(block, 2);
    if (block == NULL)
        return 6;
    if ((uintptr_t)block % 16 != 0)
        return 38;
    if (!bytes_equal(block, prefix, 2))
        return 39;
    errno = 0;
    if (realloc(block, (size_t)-1) != NULL || errno != ENOMEM ||
        !bytes_equal(block, prefix, 2))
        return 7;
    free(block);

    block = realloc(NULL, 17);
    if (block == NULL || (uintptr_t)block % 16 != 0)
        return 32;
    block[0] = 0x58;
    block[16] = 0xb7;
    if (block[0] != 0x58 || block[16] != 0xb7)
        return 33;
    free(block);

    block = calloc(17, sizeof(unsigned long));
    if (block == NULL || (uintptr_t)block % 16 != 0)
        return 8;
    for (index = 0; index < 17 * sizeof(unsigned long); ++index) {
        if (block[index] != 0)
            return 9;
    }
    errno = EAGAIN;
    free(block);
    if (errno != EAGAIN)
        return 10;

    errno = 0;
    if (calloc((size_t)-1, 2) != NULL || errno != ENOMEM)
        return 11;

    /* Standard-valid C11 aligned allocation: 128 is a 64-byte multiple. */
    aligned = aligned_alloc(64, 128);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0)
        return 34;
    free(aligned);

    /* The remaining aligned_alloc probes record musl's historical
     * extensions for non-multiple or zero alignment inputs. */
    errno = EINTR;
    aligned = aligned_alloc(64, 65);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0 || errno != EINTR)
        return 12;
    free(aligned);
    errno = 0;
    if (aligned_alloc(3, 64) != NULL || errno != EINVAL)
        return 13;
    errno = EINTR;
    aligned = aligned_alloc(0, 7);
    if (aligned == NULL || (uintptr_t)aligned % 16 != 0 || errno != EINTR)
        return 102;
    free(aligned);
    /* This is also a C11-valid 64-byte multiple, but musl rejects the
     * overflowing request before asking the backend to allocate it. */
    errno = 0;
    if (aligned_alloc(64, (size_t)-64) != NULL || errno != ENOMEM)
        return 36;
    errno = 0;
    if (aligned_alloc(musl_mallocng_max_alignment, 1) != NULL ||
        errno != ENOMEM)
        return 41;

    aligned = (void *)(uintptr_t)1;
    errno = EDOM;
    if (posix_memalign(&aligned, sizeof(void *) / 2, 64) != EINVAL ||
        aligned != (void *)(uintptr_t)1 || errno != EDOM)
        return 101;

    aligned = (void *)(uintptr_t)1;
    errno = EDOM;
    if (posix_memalign(&aligned, 24, 64) != EINVAL ||
        aligned != (void *)(uintptr_t)1 || errno != EINVAL)
        return 14;
    errno = EDOM;
    if (posix_memalign(&aligned, 64, 1) != 0 ||
        (uintptr_t)aligned % 64 != 0 || errno != EDOM)
        return 15;
    free(aligned);
    if (errno != EDOM)
        return 16;
    aligned = (void *)(uintptr_t)1;
    errno = 0;
    if (posix_memalign(&aligned, 64, (size_t)-1) != ENOMEM ||
        aligned != (void *)(uintptr_t)1 || errno != ENOMEM)
        return 37;
    aligned = (void *)(uintptr_t)1;
    errno = 0;
    if (posix_memalign(&aligned, musl_mallocng_max_alignment, 1) != ENOMEM ||
        aligned != (void *)(uintptr_t)1 || errno != ENOMEM)
        return 42;

    /* realloc(p, 0) is implementation-defined; retain the pinned-musl
     * non-null/freeable observation without asserting pointer identity. */
    block = malloc(4);
    if (block == NULL)
        return 17;
    block = realloc(block, 0);
    if (block == NULL || (uintptr_t)block % 16 != 0)
        return 18;
    free(block);

    block = reallocarray(NULL, 4, sizeof(*block));
    if (block == NULL || (uintptr_t)block % 16 != 0)
        return 19;
    for (index = 0; index < 4; ++index)
        block[index] = (unsigned char)(index + 31);
    errno = EDOM;
    resized = reallocarray(block, 2048, sizeof(*block));
    if (resized == NULL || (uintptr_t)resized % 16 != 0 ||
        resized[0] != 31 || resized[3] != 34 || errno != EDOM)
        return 20;
    errno = 0;
    if (reallocarray(resized, (size_t)-1, 2) != NULL || errno != ENOMEM ||
        resized[0] != 31 || resized[3] != 34)
        return 21;
    free(resized);

    errno = ECHILD;
    aligned = memalign(64, 19);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0 || errno != ECHILD)
        return 22;
    free(aligned);
    errno = 0;
    if (memalign(24, 19) != NULL || errno != EINVAL)
        return 23;
    errno = ENOTTY;
    aligned = memalign(0, 7);
    if (aligned == NULL || (uintptr_t)aligned % 16 != 0 || errno != ENOTTY)
        return 24;
    free(aligned);

    errno = EBUSY;
    page_aligned = valloc(7);
    if (page_aligned == NULL || (uintptr_t)page_aligned % 4096 != 0 || errno != EBUSY)
        return 25;
    free(page_aligned);

    return 0;
}

int main(void)
{
    return crabc_x86_64_allocator_runtime_probe();
}

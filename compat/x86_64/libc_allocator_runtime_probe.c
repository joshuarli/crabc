/*
 * Native Linux/x86-64 C allocator boundary probe.
 *
 * The same body executes against pinned musl and against the opt-in static
 * crabc-libc allocator backend. The mixed-runtime candidate supplies the
 * target-owned wrapper, errno slot, and bundled backend; pinned musl supplies
 * the still-missing static startup and process primitives, but never an
 * allocator entry point.
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
    static const unsigned char prefix[] = { 1, 2, 3, 4 };
    unsigned char *zero_a;
    unsigned char *zero_b;
    unsigned char *block;
    void *aligned;
    size_t index;

#ifdef CRABC_ALLOCATOR_RUNTIME_CANDIDATE
    if (__crabc_x86_allocator_runtime_v1() != 1)
        return 100;
#endif

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

    for (index = 0; index < sizeof(sizes) / sizeof(sizes[0]); ++index) {
        block = malloc(sizes[index]);
        if (block == NULL || (uintptr_t)block % 16 != 0)
            return 3;
        block[0] = (unsigned char)index;
        block[sizes[index] - 1] = (unsigned char)(index + 17);
        free(block);
    }

    block = malloc(sizeof(prefix));
    if (block == NULL)
        return 4;
    for (index = 0; index < sizeof(prefix); ++index)
        block[index] = prefix[index];
    block = realloc(block, 8192);
    if (block == NULL || !bytes_equal(block, prefix, sizeof(prefix)))
        return 5;
    block = realloc(block, 2);
    if (block == NULL || !bytes_equal(block, prefix, 2))
        return 6;
    errno = 0;
    if (realloc(block, (size_t)-1) != NULL || errno != ENOMEM ||
        !bytes_equal(block, prefix, 2))
        return 7;
    free(block);

    block = calloc(17, sizeof(unsigned long));
    if (block == NULL)
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

    errno = EINTR;
    aligned = aligned_alloc(64, 65);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0 || errno != EINTR)
        return 12;
    free(aligned);
    errno = 0;
    if (aligned_alloc(3, 64) != NULL || errno != EINVAL)
        return 13;

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

    block = malloc(4);
    if (block == NULL)
        return 17;
    block = realloc(block, 0);
    if (block == NULL)
        return 18;
    free(block);

    return 0;
}

int main(void)
{
    return crabc_x86_64_allocator_runtime_probe();
}

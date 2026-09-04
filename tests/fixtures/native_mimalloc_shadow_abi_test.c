/*
 * Complements allocator_test.c with the musl-facing malloc-family cases that
 * fixture does not observe.  Keep this source independent so the selected
 * native-mimalloc shadow can be compared with the pinned musl runtime without
 * weakening the backend-independent allocator regression.
 */
#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int fail(const char *name)
{
    fputs(name, stderr);
    fputc('\n', stderr);
    return 1;
}

static int naturally_aligned(const void *pointer)
{
    return (uintptr_t)pointer % 16 == 0;
}

int main(void)
{
    unsigned char *allocation;
    unsigned char *replacement;
    void *zero_count;
    void *zero_size;
    void *aligned;
    void *output;
    uintptr_t old_address;
    int result;

    errno = EAGAIN;
    free(NULL);
    if (errno != EAGAIN)
        return fail("free-null-errno");

    errno = EDOM;
    if (malloc_usable_size(NULL) != 0 || errno != EDOM)
        return fail("usable-size-null");

    errno = 0;
    if (malloc(SIZE_MAX) != NULL || errno != ENOMEM)
        return fail("malloc-overflow");

    errno = ERANGE;
    allocation = malloc(33);
    if (allocation == NULL || !naturally_aligned(allocation)
            || errno != ERANGE)
        return fail("malloc-success-errno");
    allocation[0] = 0x31;
    allocation[32] = 0x32;
    errno = EAGAIN;
    if (malloc_usable_size(allocation) < 33 || errno != EAGAIN)
        return fail("usable-size-success-errno");
    errno = EDOM;
    free(allocation);
    if (errno != EDOM)
        return fail("free-success-errno");

    errno = ERANGE;
    zero_count = calloc(0, SIZE_MAX);
    if (zero_count == NULL || !naturally_aligned(zero_count)
            || errno != ERANGE)
        return fail("calloc-zero-count");
    errno = EAGAIN;
    zero_size = calloc(SIZE_MAX, 0);
    if (zero_size == NULL || zero_size == zero_count
            || !naturally_aligned(zero_size) || errno != EAGAIN)
        return fail("calloc-zero-size");
    free(zero_count);
    free(zero_size);

    allocation = malloc(33);
    if (allocation == NULL)
        return fail("realloc-success-setup");
    allocation[0] = 0x41;
    allocation[32] = 0x42;
    errno = EAGAIN;
    replacement = realloc(allocation, 8192);
    if (replacement == NULL || replacement[0] != 0x41
            || replacement[32] != 0x42 || errno != EAGAIN)
        return fail("realloc-grow-success-errno");
    errno = EDOM;
    allocation = realloc(replacement, 17);
    if (allocation == NULL || allocation[0] != 0x41 || errno != EDOM)
        return fail("realloc-shrink-success-errno");
    free(allocation);

    errno = EDOM;
    replacement = realloc(NULL, 0);
    if (replacement == NULL || !naturally_aligned(replacement)
            || errno != EDOM)
        return fail("realloc-null-zero");
    free(replacement);

    errno = EAGAIN;
    aligned = aligned_alloc(128 * 1024, 7);
    if (aligned == NULL || (uintptr_t)aligned % (128 * 1024) != 0
            || malloc_usable_size(aligned) < 7 || errno != EAGAIN)
        return fail("aligned-alloc-over-aligned");
    free(aligned);

    errno = EDOM;
    aligned = aligned_alloc(64, 0);
    if (aligned == NULL || (uintptr_t)aligned % 64 != 0
            || errno != EDOM)
        return fail("aligned-alloc-zero");
    free(aligned);

    output = (void *)(uintptr_t)0x1234;
    errno = EDOM;
    result = posix_memalign(&output, 64, SIZE_MAX);
    if (result != ENOMEM || output != (void *)(uintptr_t)0x1234
            || errno != ENOMEM)
        return fail("posix-memalign-nomem-output");

    output = NULL;
    errno = EAGAIN;
    result = posix_memalign(&output, 64, 0);
    if (result != 0 || output == NULL || (uintptr_t)output % 64 != 0
            || errno != EAGAIN)
        return fail("posix-memalign-zero");
    free(output);

    output = NULL;
    errno = ERANGE;
    result = posix_memalign(&output, 4096, 1);
    if (result != 0 || output == NULL || (uintptr_t)output % 4096 != 0
            || malloc_usable_size(output) < 1 || errno != ERANGE)
        return fail("posix-memalign-success-errno");
    free(output);

    allocation = malloc(33);
    if (allocation == NULL)
        return fail("realloc-zero-setup");
    allocation[0] = 0x41;
    allocation[32] = 0x42;
    old_address = (uintptr_t)allocation;
    errno = ERANGE;
    replacement = realloc(allocation, 0);
    if (replacement == NULL)
        return fail("realloc-zero-null");
    if ((uintptr_t)replacement == old_address)
        return fail("realloc-zero-not-distinct");
    if (!naturally_aligned(replacement))
        return fail("realloc-zero-alignment");
    if (errno != ERANGE)
        return fail("realloc-zero-errno");
    free(replacement);

    puts("native mimalloc shadow abi ok");
    return 0;
}

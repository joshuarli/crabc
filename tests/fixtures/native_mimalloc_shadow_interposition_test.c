/*
 * The main executable's definitions must preempt a DSO's malloc-family calls.
 * The deliberately tiny bump store is an observation mechanism only; it is
 * not an allocator oracle and the fixture never exposes it outside this one
 * process.
 */
#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Alignas(4096) unsigned char storage[64 * 1024];
static size_t storage_used;
static unsigned int malloc_calls;
static unsigned int free_calls;
static unsigned int calloc_calls;
static unsigned int realloc_calls;
static unsigned int aligned_alloc_calls;
static unsigned int posix_memalign_calls;
static unsigned int usable_size_calls;

static void *allocate_from_storage(size_t size, size_t alignment)
{
    size_t start;

    if (size == 0)
        size = 1;
    start = (storage_used + alignment - 1) & ~(alignment - 1);
    if (start > sizeof(storage) || size > sizeof(storage) - start)
        return NULL;
    storage_used = start + size;
    return storage + start;
}

void *malloc(size_t size)
{
    void *allocation = allocate_from_storage(size, 16);

    if (allocation != NULL)
        malloc_calls += 1;
    return allocation;
}

void free(void *allocation)
{
    if (allocation != NULL)
        free_calls += 1;
}

void *calloc(size_t count, size_t size)
{
    size_t total;
    void *allocation;

    if (size != 0 && count > SIZE_MAX / size)
        return NULL;
    total = count * size;
    allocation = allocate_from_storage(total, 16);
    if (allocation != NULL) {
        memset(allocation, 0, total);
        calloc_calls += 1;
    }
    return allocation;
}

void *realloc(void *allocation, size_t size)
{
    void *replacement;

    (void)allocation;
    replacement = allocate_from_storage(size, 16);
    if (replacement != NULL)
        realloc_calls += 1;
    return replacement;
}

void *aligned_alloc(size_t alignment, size_t size)
{
    void *allocation = allocate_from_storage(size, alignment);

    if (allocation != NULL)
        aligned_alloc_calls += 1;
    return allocation;
}

int posix_memalign(void **result, size_t alignment, size_t size)
{
    void *allocation = allocate_from_storage(size, alignment);

    if (allocation == NULL)
        return ENOMEM;
    *result = allocation;
    posix_memalign_calls += 1;
    return 0;
}

size_t malloc_usable_size(void *allocation)
{
    (void)allocation;
    usable_size_calls += 1;
    return 0x1234;
}

extern void *native_mimalloc_shadow_dso_allocate(size_t);
extern void native_mimalloc_shadow_dso_release(void *);
extern void *native_mimalloc_shadow_dso_callocate(size_t, size_t);
extern void *native_mimalloc_shadow_dso_reallocate(void *, size_t);
extern void *native_mimalloc_shadow_dso_allocate_aligned(size_t, size_t);
extern int native_mimalloc_shadow_dso_posix_memalign(void **, size_t, size_t);
extern size_t native_mimalloc_shadow_dso_usable_size(void *);

int main(void)
{
    unsigned int malloc_before = malloc_calls;
    unsigned int free_before = free_calls;
    unsigned int calloc_before = calloc_calls;
    unsigned int realloc_before = realloc_calls;
    unsigned int aligned_alloc_before = aligned_alloc_calls;
    unsigned int posix_memalign_before = posix_memalign_calls;
    unsigned int usable_size_before = usable_size_calls;
    unsigned char *allocation;
    unsigned char *zeroed;
    void *aligned;
    size_t index;
    static const char success[] = "native mimalloc shadow interposition ok\n";

    allocation = native_mimalloc_shadow_dso_allocate(37);
    if (allocation == NULL || (uintptr_t)allocation < (uintptr_t)storage
            || (uintptr_t)allocation + 37
                > (uintptr_t)storage + sizeof(storage)
            || malloc_calls != malloc_before + 1)
        return 1;
    allocation[0] = 0x51;
    allocation[36] = 0x52;
    native_mimalloc_shadow_dso_release(allocation);
    if (free_calls != free_before + 1)
        return 2;

    zeroed = native_mimalloc_shadow_dso_callocate(7, 11);
    if (zeroed == NULL || calloc_calls != calloc_before + 1)
        return 3;
    for (index = 0; index < 77; ++index) {
        if (zeroed[index] != 0)
            return 4;
    }

    allocation = native_mimalloc_shadow_dso_reallocate(NULL, 29);
    if (allocation == NULL || realloc_calls != realloc_before + 1)
        return 5;

    aligned = native_mimalloc_shadow_dso_allocate_aligned(256, 19);
    if (aligned == NULL || (uintptr_t)aligned % 256 != 0
            || aligned_alloc_calls != aligned_alloc_before + 1)
        return 6;

    aligned = NULL;
    if (native_mimalloc_shadow_dso_posix_memalign(&aligned, 4096, 31) != 0
            || aligned == NULL || (uintptr_t)aligned % 4096 != 0
            || posix_memalign_calls != posix_memalign_before + 1)
        return 7;

    if (native_mimalloc_shadow_dso_usable_size(aligned) != 0x1234
            || usable_size_calls != usable_size_before + 1)
        return 8;

    if (write(STDOUT_FILENO, success, sizeof(success) - 1)
            != (ssize_t)(sizeof(success) - 1))
        return 9;
    return 0;
}

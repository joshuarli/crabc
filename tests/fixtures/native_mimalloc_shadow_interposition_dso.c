#define _POSIX_C_SOURCE 200112L
#include <malloc.h>
#include <stddef.h>
#include <stdlib.h>

void *native_mimalloc_shadow_dso_allocate(size_t size)
{
    return malloc(size);
}

void native_mimalloc_shadow_dso_release(void *allocation)
{
    free(allocation);
}

void *native_mimalloc_shadow_dso_callocate(size_t count, size_t size)
{
    return calloc(count, size);
}

void *native_mimalloc_shadow_dso_reallocate(void *allocation, size_t size)
{
    return realloc(allocation, size);
}

void *native_mimalloc_shadow_dso_allocate_aligned(size_t alignment, size_t size)
{
    return aligned_alloc(alignment, size);
}

int native_mimalloc_shadow_dso_posix_memalign(
    void **result,
    size_t alignment,
    size_t size)
{
    return posix_memalign(result, alignment, size);
}

size_t native_mimalloc_shadow_dso_usable_size(void *allocation)
{
    return malloc_usable_size(allocation);
}

/* Shared interface of owned_native_allocator_dso_{probe,library}.c. */
#ifndef CRABC_OWNED_NATIVE_ALLOCATOR_DSO_H
#define CRABC_OWNED_NATIVE_ALLOCATOR_DSO_H

#include <stddef.h>
#include <stdint.h>

struct dso_api {
    void *(*allocate)(size_t size, unsigned char byte);
    void *(*grow)(void *block, size_t size);
    void (*release)(void *block);
    void *(*zeroed)(size_t count, size_t size);
    void *(*aligned)(size_t alignment, size_t size);
    uintptr_t (*malloc_address)(void);
    uintptr_t (*free_address)(void);
    int (*errno_contract)(void);
    void *(*thread_allocate)(size_t size);
    int (*constructor_count)(void);
};

#endif

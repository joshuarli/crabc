// Verify that dynamically allocated FILE state retains the application's
// malloc-family provider through fclose.  This is the upstream libc-test
// flockfile-list lifetime sequence with a self-contained failure protocol.
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { STORAGE_BYTES = 1 << 20, MAXIMUM_ALLOCS = 16, FREED_FILL = 42 };

struct allocation {
    unsigned char *address;
    size_t length;
    int released;
};

static _Alignas(max_align_t) unsigned char storage[STORAGE_BYTES];
static struct allocation allocations[MAXIMUM_ALLOCS];
static size_t storage_used;
static size_t allocation_count;
static int allocator_misuse;

static struct allocation *find_allocation(void *pointer)
{
    size_t index;

    for (index = 0; index < allocation_count; index++)
        if (allocations[index].address == pointer)
            return &allocations[index];
    return 0;
}

static int reserve_storage(size_t length, size_t *offset)
{
    size_t alignment = _Alignof(max_align_t);
    size_t padding = storage_used % alignment;

    if (padding != 0)
        padding = alignment - padding;
    if (padding > STORAGE_BYTES - storage_used)
        return 0;
    *offset = storage_used + padding;
    if (length > STORAGE_BYTES - *offset)
        return 0;
    storage_used = *offset + length;
    return 1;
}

void *malloc(size_t length)
{
    unsigned char *result;
    size_t offset;

    if (length == 0)
        length = 1;
    if (allocation_count == MAXIMUM_ALLOCS || !reserve_storage(length, &offset))
        return 0;
    result = storage + offset;
    allocations[allocation_count++] = (struct allocation){ result, length, 0 };
    return result;
}

void free(void *pointer)
{
    struct allocation *allocation;

    if (pointer == 0)
        return;
    allocation = find_allocation(pointer);
    if (allocation == 0 || allocation->released) {
        allocator_misuse = 1;
        return;
    }
    memset(allocation->address, FREED_FILL, allocation->length);
    allocation->released = 1;
}

void *realloc(void *pointer, size_t length)
{
    struct allocation *allocation;
    void *replacement;

    if (pointer == 0)
        return malloc(length);
    allocation = find_allocation(pointer);
    if (allocation == 0 || allocation->released) {
        allocator_misuse = 1;
        return 0;
    }
    replacement = malloc(length);
    if (replacement == 0)
        return 0;
    memcpy(replacement, pointer, allocation->length < length ? allocation->length : length);
    free(pointer);
    return replacement;
}

void *calloc(size_t count, size_t length)
{
    void *result;

    if (count != 0 && length > (size_t)-1 / count)
        return 0;
    result = malloc(count * length);
    if (result != 0)
        memset(result, 0, count * length);
    return result;
}

static int released_storage_is_unchanged(const struct allocation *first,
    const struct allocation *second)
{
    const struct allocation *released[2] = { first, second };
    size_t index;

    if (first == 0 || second == 0 || first == second)
        return 0;
    for (index = 0; index < sizeof released / sizeof *released; index++) {
        size_t byte;

        if (!released[index]->released)
            return 0;
        for (byte = 0; byte < released[index]->length; byte++)
            if (released[index]->address[byte] != FREED_FILL)
                return 0;
    }
    return 1;
}

int main(void)
{
    FILE *first = tmpfile();
    FILE *second = tmpfile();
    const struct allocation *first_allocation;
    const struct allocation *second_allocation;

    if (first == 0 || second == 0)
        return 10;
    first_allocation = find_allocation(first);
    second_allocation = find_allocation(second);
    flockfile(second);
    flockfile(first);
    funlockfile(second);
    if (fclose(second) != 0)
        return 11;
    // The second FILE has been returned to the application allocator.  Its
    // former lock-list neighbor must not write through stale list storage.
    funlockfile(first);
    if (fclose(first) != 0)
        return 12;
    return allocator_misuse
        || !released_storage_is_unchanged(first_allocation, second_allocation);
}

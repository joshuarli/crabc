// Verify that owned C APIs which publish or retire malloc-family storage keep
// the executable's provider selected.  asprintf publishes caller-owned bytes;
// the passwd lookup's private getline allocation is retired before return.
#define _GNU_SOURCE
#include <stddef.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { STORAGE_BYTES = 1 << 20, MAXIMUM_ALLOCS = 32, FREED_FILL = 42 };

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
    size_t offset;

    if (length == 0)
        length = 1;
    if (allocation_count == MAXIMUM_ALLOCS || !reserve_storage(length, &offset))
        return 0;
    allocations[allocation_count] = (struct allocation){ storage + offset, length, 0 };
    return allocations[allocation_count++].address;
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
    if (length == 0) {
        free(pointer);
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

static int released_storage_is_unchanged_since(size_t first)
{
    size_t index;

    if (first == allocation_count)
        return 0;
    for (index = first; index < allocation_count; index++) {
        size_t byte;

        if (!allocations[index].released)
            return 0;
        for (byte = 0; byte < allocations[index].length; byte++)
            if (allocations[index].address[byte] != FREED_FILL)
                return 0;
    }
    return 1;
}

static int check_asprintf_result(void)
{
    char *result = 0;
    size_t first = allocation_count;

    if (asprintf(&result, "%s %d", "caller-owned", 64) != 15)
        return 10;
    if (result == 0 || strcmp(result, "caller-owned 64") != 0)
        return 11;
    if (find_allocation(result) == 0)
        return 12;
    free(result);
    return allocator_misuse || !released_storage_is_unchanged_since(first) ? 13 : 0;
}

static int check_passwd_getdelim_release(void)
{
    struct passwd record;
    struct passwd *result = 0;
    char buffer[512];
    size_t first = allocation_count;

    if (getpwnam_r("crabc", &record, buffer, sizeof buffer, &result) != 0)
        return 20;
    if (result != &record || strcmp(record.pw_name, "crabc") != 0
        || strcmp(record.pw_shell, "/bin/sh") != 0)
        return 21;
    result = (void *)1;
    if (getpwnam_r("missing", &record, buffer, sizeof buffer, &result) != 0
        || result != 0)
        return 22;
    return allocator_misuse || !released_storage_is_unchanged_since(first) ? 23 : 0;
}

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    if (strcmp(argv[1], "asprintf") == 0)
        return check_asprintf_result();
    if (strcmp(argv[1], "passwd") == 0)
        return check_passwd_getdelim_release();
    return 3;
}

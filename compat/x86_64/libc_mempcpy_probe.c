/* Static Linux/x86-64 mempcpy C ABI and behavior fixture. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef void *(*mempcpy_signature)(void *, const void *, size_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&mempcpy), mempcpy_signature),
    "mempcpy declaration");

enum {
    CRABC_MEMPCPY_BYTES = 96,
    CRABC_MEMPCPY_MAX_OFFSET = 7,
    CRABC_MEMPCPY_MAX_LENGTH = 64,
};

static unsigned char source_byte(size_t source_offset, size_t index, size_t length)
{
    return (unsigned char)(0x31U + source_offset * 17U + index * 37U + length * 13U);
}

static void fill_source(unsigned char *bytes, size_t source_offset, size_t length)
{
    size_t index;

    for (index = 0; index < CRABC_MEMPCPY_BYTES; ++index)
        bytes[index] = source_byte(source_offset, index, length);
}

static void fill_destination(unsigned char *bytes, unsigned char fill)
{
    size_t index;

    for (index = 0; index < CRABC_MEMPCPY_BYTES; ++index)
        bytes[index] = fill;
}

static int check_case(size_t source_offset, size_t destination_offset, size_t length)
{
    unsigned char source[CRABC_MEMPCPY_BYTES];
    unsigned char destination[CRABC_MEMPCPY_BYTES];
    unsigned char untouched = (unsigned char)(0xa5U ^ length ^ destination_offset);
    size_t index;
    void *result;

    fill_source(source, source_offset, length);
    fill_destination(destination, untouched);

    result = mempcpy(destination + destination_offset, source + source_offset, length);
    if (result != destination + destination_offset + length)
        return 1;

    for (index = 0; index < CRABC_MEMPCPY_BYTES; ++index) {
        unsigned char expected = untouched;

        if (index >= destination_offset && index - destination_offset < length)
            expected = source[source_offset + index - destination_offset];
        if (destination[index] != expected)
            return 2;
        if (source[index] != source_byte(source_offset, index, length))
            return 3;
    }
    return 0;
}

static int check_mempcpy_matrix(void)
{
    static const size_t lengths[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        23, 24, 25, 31, 32, 33, 47, 48, 49, 63, 64,
    };
    size_t source_offset;
    size_t destination_offset;
    size_t length_index;
    int result;

    for (source_offset = 0; source_offset <= CRABC_MEMPCPY_MAX_OFFSET;
        ++source_offset) {
        for (destination_offset = 0;
            destination_offset <= CRABC_MEMPCPY_MAX_OFFSET;
            ++destination_offset) {
            for (length_index = 0;
                length_index < sizeof(lengths) / sizeof(lengths[0]);
                ++length_index) {
                result = check_case(source_offset, destination_offset,
                    lengths[length_index]);
                if (result != 0)
                    return result;
            }
        }
    }
    return 0;
}

int crabc_x86_64_mempcpy_probe(void)
{
    return check_mempcpy_matrix();
}

#ifndef CRABC_MEMPCPY_FREESTANDING
int main(void)
{
    return crabc_x86_64_mempcpy_probe();
}
#endif

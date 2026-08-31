/* Static Linux/x86-64 memccpy C ABI and behavior fixture. */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <string.h>

typedef void *(*memccpy_signature)(void *, const void *, int, size_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&memccpy), memccpy_signature),
    "memccpy declaration");

enum {
    CRABC_MEMCCPY_BYTES = 96,
    CRABC_MEMCCPY_MAX_OFFSET = 7,
    CRABC_MEMCCPY_MAX_LENGTH = 64,
};

static unsigned char byte_other_than(unsigned value, unsigned char target)
{
    unsigned char byte = (unsigned char)value;

    return byte == target ? (unsigned char)(byte ^ 1U) : byte;
}

static void fill_source(unsigned char *bytes, unsigned char target, unsigned seed)
{
    size_t index;

    for (index = 0; index < CRABC_MEMCCPY_BYTES; ++index)
        bytes[index] = byte_other_than(seed + index * 37U, target);
}

static void fill_destination(unsigned char *bytes, unsigned char fill)
{
    size_t index;

    for (index = 0; index < CRABC_MEMCCPY_BYTES; ++index)
        bytes[index] = fill;
}

static int check_case(
    size_t source_offset,
    size_t destination_offset,
    size_t length,
    size_t stop,
    int requested_target)
{
    unsigned char source[CRABC_MEMCCPY_BYTES];
    unsigned char destination[CRABC_MEMCCPY_BYTES];
    unsigned char target = (unsigned char)requested_target;
    unsigned char untouched = (unsigned char)(0xa5U ^ target);
    size_t copied = stop < length ? stop + 1 : length;
    size_t index;
    void *result;
    void *expected_result;

    fill_source(source, target,
        (unsigned)(source_offset * 17U + destination_offset * 29U + length));
    if (stop < length)
        source[source_offset + stop] = target;
    fill_destination(destination, untouched);

    result = memccpy(destination + destination_offset, source + source_offset,
        requested_target, length);
    expected_result = stop < length ? destination + destination_offset + copied : NULL;
    if (result != expected_result)
        return 1;

    for (index = 0; index < CRABC_MEMCCPY_BYTES; ++index) {
        unsigned char expected = untouched;

        if (index >= destination_offset && index - destination_offset < copied)
            expected = source[source_offset + index - destination_offset];
        if (destination[index] != expected)
            return 2;
    }
    return 0;
}

static int check_memccpy_matrix(void)
{
    static const int requested_targets[] = {
        -128, -1, 0, 1, 0x7f, 0x80, 0xff, 0x100, 0x1ff,
    };
    static const size_t lengths[] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        23, 24, 25, 31, 32, 33, 47, 48, 49, 63, 64,
    };
    size_t target_index;
    size_t source_offset;
    size_t destination_offset;
    size_t length_index;
    size_t stop;
    int result;

    for (target_index = 0;
        target_index < sizeof(requested_targets) / sizeof(requested_targets[0]);
        ++target_index) {
        for (source_offset = 0; source_offset <= CRABC_MEMCCPY_MAX_OFFSET;
            ++source_offset) {
            for (destination_offset = 0;
                destination_offset <= CRABC_MEMCCPY_MAX_OFFSET;
                ++destination_offset) {
                for (length_index = 0;
                    length_index < sizeof(lengths) / sizeof(lengths[0]);
                    ++length_index) {
                    size_t length = lengths[length_index];

                    for (stop = 0; stop <= length; ++stop) {
                        result = check_case(source_offset, destination_offset, length,
                            stop, requested_targets[target_index]);
                        if (result != 0)
                            return result;
                    }
                }
            }
        }
    }
    return 0;
}

int crabc_x86_64_memccpy_probe(void)
{
    return check_memccpy_matrix();
}

#ifndef CRABC_MEMCCPY_FREESTANDING
int main(void)
{
    return crabc_x86_64_memccpy_probe();
}
#endif

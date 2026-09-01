/*
 * Pinned-musl Linux/x86-64 explicit_bzero/swab C ABI differential body.
 *
 * It uses only disjoint caller-owned arrays. The paired-byte matrix keeps
 * swab's restrict precondition intact, including its no-write negative/short
 * counts and the odd trailing byte rule. The separate optimized dead-wipe
 * probe covers explicit_bzero's non-elision property.
 */

#define _GNU_SOURCE 1

#include <string.h>
#include <unistd.h>

enum {
    CRABC_MEMORY_SPECIAL_BYTES = 96,
    CRABC_MEMORY_SPECIAL_MAX_OFFSET = 7,
    CRABC_MEMORY_SPECIAL_MAX_LENGTH = 65,
};

static void fill_bytes(unsigned char *bytes, size_t count, unsigned char seed)
{
    size_t index;

    for (index = 0; index < count; ++index)
        bytes[index] = (unsigned char)(seed + index * 29U);
}

static int check_explicit_bzero_case(size_t offset, size_t length)
{
    unsigned char buffer[CRABC_MEMORY_SPECIAL_BYTES];
    unsigned char before[CRABC_MEMORY_SPECIAL_BYTES];
    size_t index;

    fill_bytes(buffer, sizeof(buffer), (unsigned char)(offset + length + 1));
    for (index = 0; index < sizeof(buffer); ++index)
        before[index] = buffer[index];
    explicit_bzero(buffer + offset, length);
    explicit_bzero(buffer + offset, length);

    for (index = 0; index < sizeof(buffer); ++index) {
        unsigned char expected = before[index];

        if (index >= offset && index - offset < length)
            expected = 0;
        if (buffer[index] != expected)
            return 1;
    }
    return 0;
}

static int check_explicit_bzero_matrix(void)
{
    size_t offset;
    size_t length;

    for (offset = 0; offset <= CRABC_MEMORY_SPECIAL_MAX_OFFSET; ++offset) {
        for (length = 0; length <= 64; ++length) {
            if (check_explicit_bzero_case(offset, length) != 0)
                return 1;
        }
    }
    return 0;
}

static int check_swab_case(size_t source_offset, size_t destination_offset,
    ssize_t count)
{
    unsigned char source[CRABC_MEMORY_SPECIAL_BYTES];
    unsigned char source_before[CRABC_MEMORY_SPECIAL_BYTES];
    unsigned char destination[CRABC_MEMORY_SPECIAL_BYTES];
    const unsigned char destination_fill = 0xa5;
    size_t paired = count > 1 ? (size_t)count & ~(size_t)1 : 0;
    size_t index;

    fill_bytes(source, sizeof(source), (unsigned char)(source_offset + 3));
    for (index = 0; index < sizeof(source); ++index)
        source_before[index] = source[index];
    for (index = 0; index < sizeof(destination); ++index)
        destination[index] = destination_fill;

    swab(source + source_offset, destination + destination_offset, count);

    for (index = 0; index < sizeof(source); ++index) {
        if (source[index] != source_before[index])
            return 1;
    }
    for (index = 0; index < sizeof(destination); ++index) {
        unsigned char expected = destination_fill;

        if (index >= destination_offset && index - destination_offset < paired) {
            size_t relative = index - destination_offset;

            expected = source_before[source_offset + (relative ^ 1U)];
        }
        if (destination[index] != expected)
            return 2;
    }
    return 0;
}

static int check_swab_matrix(void)
{
    static const ssize_t counts[] = {
        -1, 0, 1, 2, 3, 4, 5, 7, 8, 15, 16, 31, 32, 63, 64, 65,
    };
    size_t source_offset;
    size_t destination_offset;
    size_t count_index;

    for (source_offset = 0; source_offset <= CRABC_MEMORY_SPECIAL_MAX_OFFSET;
        ++source_offset) {
        for (destination_offset = 0;
            destination_offset <= CRABC_MEMORY_SPECIAL_MAX_OFFSET;
            ++destination_offset) {
            for (count_index = 0;
                count_index < sizeof(counts) / sizeof(counts[0]);
                ++count_index) {
                if (check_swab_case(source_offset, destination_offset,
                        counts[count_index]) != 0)
                    return 1;
            }
        }
    }
    return 0;
}

int crabc_x86_64_memory_special_probe(void)
{
    if (check_explicit_bzero_matrix() != 0)
        return 1;
    return check_swab_matrix() == 0 ? 0 : 2;
}

#ifndef CRABC_MEMORY_SPECIAL_FREESTANDING
int main(void)
{
    return crabc_x86_64_memory_special_probe();
}
#endif

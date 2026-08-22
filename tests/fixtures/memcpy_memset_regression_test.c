#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

enum {
    MAX_LENGTH = 262143,
    STORAGE_SIZE = MAX_LENGTH + 64,
};

static unsigned random_state = 0x243f6a88U;

static unsigned next_random(void)
{
    random_state = random_state * 1664525U + 1013904223U;
    return random_state;
}

static unsigned char pattern(size_t index)
{
    return (unsigned char)(index * 131U + 19U);
}

static void fill_bytes(unsigned char *bytes, size_t length, unsigned char value)
{
    for (size_t index = 0; index < length; ++index)
        bytes[index] = value;
}

static int has_pattern(const unsigned char *bytes, size_t length)
{
    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] != pattern(index))
            return 0;
    }
    return 1;
}

static int test_size_and_alignment_matrix(void)
{
    static const size_t lengths[] = {
        0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255,
        256, 511, 512, 1023, 1024, 4095, 4096, 16383, 16384, 65535,
        65536, MAX_LENGTH,
    };
    static const int values[] = { 0, 1, 0x7f, 0x80, 0xff, 0x100, -1, 0x1234 };
    static unsigned char source_storage[STORAGE_SIZE];
    static unsigned char destination_storage[STORAGE_SIZE];

    for (size_t source_offset = 0; source_offset < 16; ++source_offset) {
        size_t destination_offset = (source_offset * 7 + 3) & 15;
        for (size_t length_index = 0;
            length_index < sizeof(lengths) / sizeof(lengths[0]); ++length_index) {
            size_t length = lengths[length_index];
            unsigned char *source = source_storage + source_offset;
            unsigned char *destination = destination_storage + destination_offset;

            for (size_t index = 0; index < length; ++index)
                source[index] = pattern(index);
            fill_bytes(destination_storage, sizeof(destination_storage), 0xa5);
            if (memcpy(destination, source, length) != destination)
                return 1;
            if (!has_pattern(destination, length) || !has_pattern(source, length))
                return 2;
            for (size_t index = 0; index < sizeof(destination_storage); ++index) {
                int copied = index >= destination_offset
                    && index < destination_offset + length;
                if (destination_storage[index] != (copied ? pattern(index - destination_offset) : 0xa5))
                    return 3;
            }

            for (size_t value_index = 0;
                value_index < sizeof(values) / sizeof(values[0]); ++value_index) {
                unsigned char expected = (unsigned char)values[value_index];
                fill_bytes(destination_storage, sizeof(destination_storage), 0x5a);
                if (memset(destination, values[value_index], length) != destination)
                    return 4;
                for (size_t index = 0; index < sizeof(destination_storage); ++index) {
                    int written = index >= destination_offset
                        && index < destination_offset + length;
                    if (destination_storage[index] != (written ? expected : 0x5a))
                        return 5;
                }
            }
        }
    }
    return 0;
}

static int test_guard_page_matrix(void)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0)
        return 1;
    unsigned char *source_mapping = mmap(NULL, (size_t)page * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (source_mapping == MAP_FAILED)
        return 2;
    unsigned char *destination_mapping = mmap(NULL, (size_t)page * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (destination_mapping == MAP_FAILED) {
        munmap(source_mapping, (size_t)page * 2);
        return 3;
    }
    if (mprotect(source_mapping + page, (size_t)page, PROT_NONE) != 0
        || mprotect(destination_mapping + page, (size_t)page, PROT_NONE) != 0) {
        munmap(destination_mapping, (size_t)page * 2);
        munmap(source_mapping, (size_t)page * 2);
        return 4;
    }

    for (size_t length = 0; length <= 64; ++length) {
        unsigned char *source = source_mapping + page - (length == 0 ? 1 : length);
        unsigned char *destination = destination_mapping + page - (length == 0 ? 1 : length);
        for (size_t index = 0; index < length; ++index)
            source[index] = pattern(index);
        if (memcpy(destination, source, length) != destination
            || !has_pattern(destination, length)
            || !has_pattern(source, length)) {
            munmap(destination_mapping, (size_t)page * 2);
            munmap(source_mapping, (size_t)page * 2);
            return 5;
        }
        if (memset(destination, -1, length) != destination) {
            munmap(destination_mapping, (size_t)page * 2);
            munmap(source_mapping, (size_t)page * 2);
            return 6;
        }
        for (size_t index = 0; index < length; ++index) {
            if (destination[index] != 0xff) {
                munmap(destination_mapping, (size_t)page * 2);
                munmap(source_mapping, (size_t)page * 2);
                return 7;
            }
        }
    }
    if (munmap(destination_mapping, (size_t)page * 2) != 0
        || munmap(source_mapping, (size_t)page * 2) != 0)
        return 8;
    return 0;
}

static int test_randomized_misalignment(void)
{
    for (unsigned sample = 0; sample < 4096; ++sample) {
        unsigned char source_storage[273];
        unsigned char destination_storage[273];
        unsigned char *source = source_storage + (next_random() & 15U);
        unsigned char *destination = destination_storage + (next_random() & 15U);
        size_t length = next_random() % 257;
        int value = (int)next_random();

        for (size_t index = 0; index < length; ++index)
            source[index] = pattern(index);
        fill_bytes(destination_storage, sizeof(destination_storage), 0x3c);
        if (memcpy(destination, source, length) != destination
            || !has_pattern(destination, length)
            || !has_pattern(source, length))
            return 1;
        if (memset(destination, value, length) != destination)
            return 2;
        for (size_t index = 0; index < length; ++index) {
            if (destination[index] != (unsigned char)value)
                return 3;
        }
    }
    return 0;
}

int main(void)
{
    if (test_size_and_alignment_matrix() != 0)
        return 1;
    if (test_guard_page_matrix() != 0)
        return 2;
    if (test_randomized_misalignment() != 0)
        return 3;

    puts("memcpy/memset oracle ok");
    return 0;
}

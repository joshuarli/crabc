#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned random_state = 0x6d2b79f5U;

static unsigned next_random(void)
{
    random_state = random_state * 1664525U + 1013904223U;
    return random_state;
}

static void *naive_memchr(const unsigned char *bytes, int value, size_t length)
{
    unsigned char target = (unsigned char)value;
    for (size_t index = 0; index < length; ++index) {
        if (bytes[index] == target)
            return (void *)(bytes + index);
    }
    return NULL;
}

static int test_size_and_alignment_matrix(void)
{
    static const size_t lengths[] = {
        0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255,
        256, 511, 512, 1023, 1024, 4095, 4096, 16383, 16384, 65535,
        65536, 262143,
    };
    static unsigned char storage[262144 + 64];

    for (size_t offset = 0; offset < 16; ++offset) {
        for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]); ++index) {
            unsigned char *bytes = storage + offset;
            size_t length = lengths[index];
            memset(bytes, 0x41, length);
            if (memchr(bytes, 0x7f, length) != NULL)
                return 1;
            if (length != 0) {
                bytes[length - 1] = 0x7f;
                if (memchr(bytes, 0x7f, length) != bytes + length - 1
                    || memchr(bytes, 0x7f, length - 1) != NULL)
                    return 2;
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
    unsigned char *mapping = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 2;
    if (mprotect(mapping + page, (size_t)page, PROT_NONE) != 0)
        return 3;
    for (size_t length = 0; length <= 64; ++length) {
        unsigned char *edge = mapping + page - (length == 0 ? 1 : length);
        memset(edge, 0x41, length);
        if (memchr(edge, 0x7f, length) != NULL) {
            munmap(mapping, (size_t)page * 2);
            return 4;
        }
        if (length != 0) {
            edge[length - 1] = 0x7f;
            if (memchr(edge, 0x7f, length) != edge + length - 1) {
                munmap(mapping, (size_t)page * 2);
                return 5;
            }
        }
    }
    if (munmap(mapping, (size_t)page * 2) != 0)
        return 6;
    return 0;
}

int main(void)
{
    if (test_size_and_alignment_matrix() != 0)
        return 1;

    unsigned char bytes[] = { 0, 0xff, 0x11, 0xff, 0x22 };
    if (memchr(bytes, 0xff, sizeof(bytes)) != bytes + 1)
        return 1;
    if (memchr(bytes, 0x1ff, sizeof(bytes)) != bytes + 1)
        return 2;
    if (memchr(bytes, 0x22, sizeof(bytes) - 1) != NULL)
        return 3;
    if (memchr(bytes, 0, 0) != NULL)
        return 4;

    if (test_guard_page_matrix() != 0)
        return 5;

    for (unsigned sample = 0; sample < 4096; ++sample) {
        unsigned char storage[273];
        unsigned char *data = storage + (next_random() & 15U);
        size_t length = next_random() % 257;
        int target = (int)next_random();
        for (size_t index = 0; index < length; ++index)
            data[index] = (unsigned char)next_random();
        if (memchr(data, target, length) != naive_memchr(data, target, length))
            return 11;
    }

    puts("memchr oracle ok");
    return 0;
}

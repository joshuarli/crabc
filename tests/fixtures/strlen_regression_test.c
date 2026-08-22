#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned random_state = 0x85ebca6bU;

static unsigned next_random(void)
{
    random_state = random_state * 1664525U + 1013904223U;
    return random_state;
}

static size_t naive_strlen(const char *text)
{
    size_t length = 0;
    while (text[length] != '\0')
        ++length;
    return length;
}

static int test_size_and_alignment_matrix(void)
{
    static const size_t lengths[] = {
        0, 1, 2, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255,
        256, 511, 512, 1023, 1024, 4095, 4096, 16383, 16384, 65535,
        65536, 262143,
    };
    static char storage[262144 + 64];

    for (size_t offset = 0; offset < 16; ++offset) {
        for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]); ++index) {
            char *text = storage + offset;
            size_t length = lengths[index];
            memset(text, 'a', length);
            text[length] = '\0';
            if (strlen(text) != length)
                return 1;
        }
    }
    return 0;
}

static int test_guard_page_matrix(void)
{
    long page = sysconf(_SC_PAGESIZE);
    if (page <= 0)
        return 1;
    char *mapping = mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 2;
    if (mprotect(mapping + page, (size_t)page, PROT_NONE) != 0)
        return 3;
    for (size_t length = 0; length <= 64; ++length) {
        char *edge = mapping + page - length - 1;
        memset(edge, 'b', length);
        edge[length] = '\0';
        if (strlen(edge) != length) {
            munmap(mapping, (size_t)page * 2);
            return 4;
        }
    }
    if (munmap(mapping, (size_t)page * 2) != 0)
        return 5;
    return 0;
}

int main(void)
{
    if (test_size_and_alignment_matrix() != 0)
        return 1;

    char buffer[80];
    for (size_t offset = 0; offset < 16; ++offset) {
        for (size_t length = 0; length < 48; ++length) {
            memset(buffer, 'a', sizeof(buffer));
            buffer[offset + length] = '\0';
            if (strlen(buffer + offset) != length)
                return 1;
        }
    }

    if (test_guard_page_matrix() != 0)
        return 2;

    for (unsigned sample = 0; sample < 4096; ++sample) {
        char storage[273];
        char *text = storage + (next_random() & 15U);
        size_t length = next_random() % 257;
        for (size_t index = 0; index < length; ++index)
            text[index] = (char)('a' + next_random() % 26);
        text[length] = '\0';
        if (strlen(text) != naive_strlen(text))
            return 7;
    }

    puts("strlen oracle ok");
    return 0;
}

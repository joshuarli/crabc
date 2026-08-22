#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int require(int condition)
{
    return condition ? 0 : 1;
}

static unsigned random_state = 0x9e3779b9U;

static unsigned next_random(void)
{
    random_state = random_state * 1664525U + 1013904223U;
    return random_state;
}

static void *naive_memmem(const unsigned char *haystack, size_t haystacklen,
    const unsigned char *needle, size_t needlelen)
{
    if (needlelen == 0)
        return (void *)haystack;
    if (haystacklen < needlelen)
        return NULL;
    for (size_t start = 0; start <= haystacklen - needlelen; ++start) {
        size_t index = 0;
        while (index < needlelen && haystack[start + index] == needle[index])
            ++index;
        if (index == needlelen)
            return (void *)(haystack + start);
    }
    return NULL;
}

static int test_size_and_alignment_matrix(void)
{
    static const size_t lengths[] = {
        0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128, 255,
        256, 511, 512, 1023, 1024, 4095, 4096, 16383, 16384, 65535,
        65536, 262143,
    };
    static unsigned char storage[262144 + 64];
    static const unsigned char needle[] = { 0, 0x7f, 0xfe };

    for (size_t offset = 0; offset < 16; ++offset) {
        for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]); ++index) {
            unsigned char *bytes = storage + offset;
            size_t length = lengths[index];
            memset(bytes, 0x41, length);
            if (memmem(bytes, length, needle, 0) != bytes)
                return 1;
            if (length < sizeof(needle)) {
                if (memmem(bytes, length, needle, sizeof(needle)) != NULL)
                    return 2;
            } else {
                memcpy(bytes + length - sizeof(needle), needle, sizeof(needle));
                if (memmem(bytes, length, needle, sizeof(needle))
                    != bytes + length - sizeof(needle))
                    return 3;
            }
        }
    }
    return 0;
}

static int test_guard_page_matrix(void)
{
    static const unsigned char needle[] = { 0, 0x7f, 0xfe };
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
        if (memmem(edge, length, needle, 0) != edge) {
            munmap(mapping, (size_t)page * 2);
            return 4;
        }
        if (length < sizeof(needle)) {
            if (memmem(edge, length, needle, sizeof(needle)) != NULL) {
                munmap(mapping, (size_t)page * 2);
                return 5;
            }
        } else {
            memcpy(edge + length - sizeof(needle), needle, sizeof(needle));
            if (memmem(edge, length, needle, sizeof(needle))
                != edge + length - sizeof(needle)) {
                munmap(mapping, (size_t)page * 2);
                return 6;
            }
        }
    }
    {
        static const unsigned char edge_needle[] = "edge-end";
        unsigned char *edge = mapping + page - 16;
        memset(edge, 'x', 16);
        memcpy(edge + 8, edge_needle, sizeof(edge_needle) - 1);
        if (memmem(edge, 16, edge_needle, sizeof(edge_needle) - 1) != edge + 8
            || memmem(edge, 8, edge_needle, sizeof(edge_needle) - 1) != NULL) {
            munmap(mapping, (size_t)page * 2);
            return 7;
        }
    }
    if (munmap(mapping, (size_t)page * 2) != 0)
        return 8;
    return 0;
}

int main(void)
{
    unsigned char binary_haystack[] = { 0x40, 0, 0x41, 0, 0x42, 0x43, 0 };
    const unsigned char binary_needle[] = { 0, 0x42, 0x43 };
    unsigned char overlap[] = "abababababababa";
    unsigned char worst_case[4096];
    unsigned char worst_needle[128];

    if (test_size_and_alignment_matrix() != 0)
        return 1;
    if (require(memmem(binary_haystack, sizeof(binary_haystack), binary_needle,
            sizeof(binary_needle)) == binary_haystack + 3))
        return 2;
    if (require(memmem(binary_haystack, sizeof(binary_haystack), binary_needle,
            0) == binary_haystack))
        return 3;
    if (require(memmem(overlap, sizeof(overlap) - 1, "ababa", 5) == overlap))
        return 4;
    if (require(memmem(overlap, sizeof(overlap) - 1, "babab", 5) == overlap + 1))
        return 5;

    memset(worst_case, 'a', sizeof(worst_case));
    memset(worst_needle, 'a', sizeof(worst_needle));
    worst_needle[sizeof(worst_needle) - 1] = 'b';
    if (require(memmem(worst_case, sizeof(worst_case), worst_needle,
            sizeof(worst_needle)) == NULL))
        return 6;
    if (test_guard_page_matrix() != 0)
        return 7;

    for (unsigned sample = 0; sample < 4096; ++sample) {
        unsigned char haystack_storage[144];
        unsigned char needle_storage[80];
        unsigned char *haystack = haystack_storage + (next_random() & 15U);
        unsigned char *needle = needle_storage + (next_random() & 15U);
        size_t haystacklen = next_random() % 129;
        size_t needlelen = next_random() % 65;
        for (size_t index = 0; index < haystacklen; ++index)
            haystack[index] = (unsigned char)next_random();
        for (size_t index = 0; index < needlelen; ++index)
            needle[index] = (unsigned char)next_random();
        if ((next_random() & 1) && needlelen <= haystacklen) {
            size_t start = needlelen == 0 ? 0 : next_random() % (haystacklen - needlelen + 1);
            memcpy(needle, haystack + start, needlelen);
        }
        if (memmem(haystack, haystacklen, needle, needlelen) !=
            naive_memmem(haystack, haystacklen, needle, needlelen))
            return 8;
    }

    puts("memmem oracle ok");
    return 0;
}

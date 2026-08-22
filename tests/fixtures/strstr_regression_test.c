#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static unsigned random_state = 0x9e3779b9U;

static unsigned next_random(void)
{
    random_state = random_state * 1664525U + 1013904223U;
    return random_state;
}

static char *naive_strstr(const char *haystack, const char *needle)
{
    if (*needle == '\0')
        return (char *)haystack;
    for (; *haystack != '\0'; ++haystack) {
        size_t index = 0;
        while (needle[index] != '\0' && haystack[index] == needle[index])
            ++index;
        if (needle[index] == '\0')
            return (char *)haystack;
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
    static char storage[262144 + 64];
    static const char needle[] = "xYz";

    for (size_t offset = 0; offset < 16; ++offset) {
        for (size_t index = 0; index < sizeof(lengths) / sizeof(lengths[0]); ++index) {
            char *text = storage + offset;
            size_t length = lengths[index];
            memset(text, 'a', length);
            text[length] = '\0';
            if (strstr(text, "") != text)
                return 1;
            if (length < sizeof(needle) - 1) {
                if (strstr(text, needle) != NULL)
                    return 2;
            } else {
                memcpy(text + length - (sizeof(needle) - 1), needle,
                    sizeof(needle) - 1);
                if (strstr(text, needle) != text + length - (sizeof(needle) - 1))
                    return 3;
            }
        }
    }
    return 0;
}

static int test_five_to_eight_byte_needles(void)
{
    static const char needles[][9] = {
        "aBcDe", "aBcDef", "aBcDefG", "aBcDefGh",
    };
    char storage[96 + 16];

    for (size_t offset = 0; offset < 16; ++offset) {
        char *text = storage + offset;
        for (size_t index = 0; index < sizeof(needles) / sizeof(needles[0]); ++index) {
            size_t length = strlen(needles[index]);
            memset(text, 'x', 64);
            memcpy(text + 64 - length, needles[index], length);
            text[64] = '\0';
            if (strstr(text, needles[index]) != text + 64 - length)
                return 1;
            text[64 - 1] = 'z';
            if (strstr(text, needles[index]) != NULL)
                return 2;
        }
    }
    return 0;
}

static int test_guard_page_matrix(void)
{
    static const char needle[] = "xYz";
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
        memset(edge, 'a', length);
        edge[length] = '\0';
        if (strstr(edge, "") != edge) {
            munmap(mapping, (size_t)page * 2);
            return 4;
        }
        if (length < sizeof(needle) - 1) {
            if (strstr(edge, needle) != NULL) {
                munmap(mapping, (size_t)page * 2);
                return 5;
            }
        } else {
            memcpy(edge + length - (sizeof(needle) - 1), needle,
                sizeof(needle) - 1);
            if (strstr(edge, needle) != edge + length - (sizeof(needle) - 1)) {
                munmap(mapping, (size_t)page * 2);
                return 6;
            }
        }
    }
    {
        static const char needles[][9] = {
            "aBcDe", "aBcDef", "aBcDefG", "aBcDefGh",
        };
        for (size_t index = 0; index < sizeof(needles) / sizeof(needles[0]); ++index) {
            size_t length = strlen(needles[index]);
            char *edge = mapping + page - length - 1;
            memcpy(edge, needles[index], length);
            edge[length] = '\0';
            if (strstr(edge, needles[index]) != edge) {
                munmap(mapping, (size_t)page * 2);
                return 7;
            }
        }
    }
    {
        char *edge = mapping + page - 16;
        const char *edge_text = "abcabcabcabcabc";
        for (size_t index = 0; index < 15; ++index)
            edge[index] = edge_text[index];
        edge[15] = '\0';
        if (strstr(edge, edge_text) != edge
            || strstr(edge, "abcabcabcabcabz") != NULL
            || strstr(edge, "abcabcabcabcabca") != NULL) {
            munmap(mapping, (size_t)page * 2);
            return 8;
        }
    }
    if (munmap(mapping, (size_t)page * 2) != 0)
        return 9;
    return 0;
}

int main(void)
{
    static const char short_text[] = "abc";

    if (test_size_and_alignment_matrix() != 0)
        return 1;
    if (test_five_to_eight_byte_needles() != 0)
        return 2;

    if (strstr("", "") == NULL)
        return 3;
    if (strstr(short_text, "") != short_text)
        return 4;
    if (strstr(short_text, "b") != short_text + 1)
        return 5;
    if (strstr("ababa", "aba") != (char *)"ababa")
        return 6;
    if (strstr("abc", "abcd") != NULL)
        return 7;

    char periodic[513];
    for (size_t index = 0; index < sizeof(periodic) - 1; ++index)
        periodic[index] = 'a';
    periodic[sizeof(periodic) - 1] = '\0';
    char periodic_needle[258];
    for (size_t index = 0; index < sizeof(periodic_needle) - 2; ++index)
        periodic_needle[index] = 'a';
    periodic_needle[sizeof(periodic_needle) - 2] = 'b';
    periodic_needle[sizeof(periodic_needle) - 1] = '\0';
    if (strstr(periodic, periodic_needle) != NULL)
        return 8;
    periodic[sizeof(periodic) - 2] = 'b';
    if (strstr(periodic, periodic_needle) != periodic + sizeof(periodic) - 258)
        return 9;

    if (test_guard_page_matrix() != 0)
        return 10;

    for (unsigned sample = 0; sample < 4096; ++sample) {
        char haystack_storage[273];
        char needle_storage[80];
        char *haystack = haystack_storage + (next_random() & 15U);
        char *needle = needle_storage + (next_random() & 15U);
        size_t haystack_length = next_random() % 256;
        size_t needle_length = next_random() % 64;
        for (size_t index = 0; index < haystack_length; ++index)
            haystack[index] = (char)('a' + next_random() % 4);
        for (size_t index = 0; index < needle_length; ++index)
            needle[index] = (char)('a' + next_random() % 4);
        haystack[haystack_length] = '\0';
        needle[needle_length] = '\0';
        if (strstr(haystack, needle) != naive_strstr(haystack, needle))
            return 15;
    }

    puts("strstr oracle ok");
    return 0;
}

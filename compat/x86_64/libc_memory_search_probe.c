/* Static x86-64 memory-search ABI and behavior fixture.
 *
 * This is deliberately limited to the three bounded byte-range operations
 * selected by the artifact: memchr, GNU memrchr, and GNU memmem.  The same
 * source is first run with pinned musl headers/runtime and then as a
 * freestanding program linked to the selected crabc archive.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8,
    "x86-64 LP64 widths");
_Static_assert(SYS_mmap == 9 && SYS_mprotect == 10 && SYS_munmap == 11,
    "Linux x86-64 mapping syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memchr),
    void *(*)(const void *, int, size_t)), "memchr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memrchr),
    void *(*)(const void *, int, size_t)), "memrchr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memmem),
    void *(*)(const void *, size_t, const void *, size_t)),
    "memmem declaration");

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall6(long number, long argument1, long argument2,
    long argument3, long argument4, long argument5, long argument6)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;
    register long register6 __asm__("r9") = argument6;

    __asm__ volatile("syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5), "r"(register6)
        : "rcx", "r11", "memory");
    return result;
}

static int raw_failed(long result)
{
    return result < 0 && result >= -4095;
}

static void *raw_mmap(size_t length)
{
    long result = raw_syscall6(SYS_mmap, 0, (long)length,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return raw_failed(result) ? MAP_FAILED : (void *)result;
}

static int raw_mprotect(void *address, size_t length, int protection)
{
    return raw_syscall4(SYS_mprotect, (long)address, (long)length,
        protection, 0) == 0 ? 0 : -1;
}

static int raw_munmap(void *address, size_t length)
{
    return raw_syscall4(SYS_munmap, (long)address, (long)length,
        0, 0) == 0 ? 0 : -1;
}

static int test_null_zero_and_conversion(void)
{
    unsigned char bytes[] = { 0x00, 0x80, 0xff, 0x01, 0x80 };
    unsigned char needle[] = { 0x80, 0xff };

    if (memchr(NULL, 0, 0) != NULL || memrchr(NULL, 0, 0) != NULL ||
        memmem(NULL, 0, NULL, 0) != NULL ||
        memmem(bytes, sizeof bytes, NULL, 0) != bytes)
        return 1;
    if (memchr(bytes, -1, sizeof bytes) != bytes + 2 ||
        memchr(bytes, 0x100, sizeof bytes) != bytes ||
        memrchr(bytes, -1, sizeof bytes) != bytes + 2 ||
        memrchr(bytes, 0x180, sizeof bytes) != bytes + 4)
        return 2;
    if (memmem(bytes, sizeof bytes, needle, sizeof needle) != bytes + 1)
        return 3;
    return 0;
}

static int test_memchr_and_memrchr_ranges(void)
{
    static const unsigned char bytes[] = {
        0x10, 0x00, 0x80, 0x10, 0xff, 0x00, 0x80, 0x10
    };

    if (memchr(bytes, 0x10, 0) != NULL || memrchr(bytes, 0x10, 0) != NULL)
        return 1;
    if (memchr(bytes, 0x80, 2) != NULL ||
        memchr(bytes, 0x80, sizeof bytes) != bytes + 2 ||
        memrchr(bytes, 0x80, 6) != bytes + 2 ||
        memrchr(bytes, 0x10, sizeof bytes) != bytes + 7)
        return 2;
    if (memchr(bytes, 0, sizeof bytes) != bytes + 1 ||
        memrchr(bytes, 0, sizeof bytes) != bytes + 5)
        return 3;
    if (memchr(bytes + 2, 0x10, 4) != bytes + 3 ||
        memrchr(bytes + 2, 0x10, 4) != bytes + 3)
        return 4;
    return 0;
}

static int test_memmem_shapes(void)
{
    static const unsigned char haystack[] = {
        'x', 'a', 'b', 'c', 'a', 'b', 'c', 'd', 'a', 'b', 'c', 'y'
    };
    static const unsigned char short1[] = { 'c' };
    static const unsigned char short2[] = { 'a', 'b' };
    static const unsigned char short3[] = { 'b', 'c', 'a' };
    static const unsigned char short4[] = { 'a', 'b', 'c', 'd' };
    static const unsigned char absent[] = { 'z' };
    static const unsigned char longer[] = { 'a', 'b', 'c', 'd', 'e', 'f' };
    unsigned char overlap[] = { '0', 'a', 'b', 'c', 'd', 'e', 'f', '1' };

    if (memmem(haystack, sizeof haystack, short1, sizeof short1) != haystack + 3 ||
        memmem(haystack, sizeof haystack, short2, sizeof short2) != haystack + 1 ||
        memmem(haystack, sizeof haystack, short3, sizeof short3) != haystack + 2 ||
        memmem(haystack, sizeof haystack, short4, sizeof short4) != haystack + 4)
        return 1;
    if (memmem(haystack, sizeof haystack, absent, sizeof absent) != NULL ||
        memmem(haystack, 3, longer, sizeof longer) != NULL ||
        memmem(haystack, sizeof haystack, longer, 0) != haystack)
        return 2;
    if (memmem(overlap + 1, 6, overlap + 2, 4) != overlap + 2 ||
        memmem(overlap + 2, 4, overlap + 1, 6) != NULL)
        return 3;
    return 0;
}

static unsigned search_random_state = 0x243f6a1dU;

static unsigned next_search_random(void)
{
    search_random_state = search_random_state * 1664525U + 1013904223U;
    return search_random_state;
}

static size_t naive_memmem(const unsigned char *haystack, size_t haystack_length,
    const unsigned char *needle, size_t needle_length)
{
    size_t start;

    if (needle_length == 0)
        return 0;
    if (haystack_length < needle_length)
        return (size_t)-1;
    for (start = 0; start <= haystack_length - needle_length; ++start) {
        size_t offset;
        for (offset = 0; offset < needle_length; ++offset)
            if (haystack[start + offset] != needle[offset])
                break;
        if (offset == needle_length)
            return start;
    }
    return (size_t)-1;
}

static int test_long_periodic_and_random(void)
{
    unsigned char haystack[768];
    unsigned char needle[260];
    unsigned sample;
    size_t index;

    for (index = 0; index < sizeof haystack; ++index)
        haystack[index] = 'a';
    haystack[sizeof haystack - 1] = 'z';
    for (index = 0; index < sizeof needle - 1; ++index)
        needle[index] = 'a';
    needle[sizeof needle - 1] = 'b';
    if (memmem(haystack, sizeof haystack, needle, sizeof needle) != NULL)
        return 1;
    for (index = 0; index < sizeof needle - 1; ++index)
        needle[index] = 'a';
    needle[sizeof needle - 1] = 'b';
    for (index = 0; index < sizeof needle; ++index)
        haystack[200 + index] = needle[index];
    if (memmem(haystack, sizeof haystack, needle, sizeof needle) != haystack + 200)
        return 2;

    for (sample = 0; sample < 256; ++sample) {
        unsigned char random_haystack[96];
        unsigned char random_needle[40];
        size_t haystack_length = next_search_random() % sizeof random_haystack;
        size_t needle_length = next_search_random() % sizeof random_needle;
        size_t expected;

        for (index = 0; index < haystack_length; ++index)
            random_haystack[index] = (unsigned char)next_search_random();
        for (index = 0; index < needle_length; ++index)
            random_needle[index] = (unsigned char)next_search_random();
        expected = naive_memmem(random_haystack, haystack_length,
            random_needle, needle_length);
        if (memmem(random_haystack, haystack_length, random_needle,
                needle_length) != (expected == (size_t)-1 ? NULL :
                random_haystack + expected))
            return 3;
    }
    return 0;
}

static int test_page_edge_bounds(void)
{
    enum { PAGE_BYTES = 4096, RANGE_BYTES = 32 };
    unsigned char *mapping = raw_mmap(PAGE_BYTES * 2);
    unsigned char *edge;
    unsigned char needle[RANGE_BYTES];
    int status = 0;
    size_t index;

    if (mapping == MAP_FAILED)
        return 1;
    if (raw_mprotect(mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0) {
        raw_munmap(mapping, PAGE_BYTES * 2);
        return 2;
    }
    edge = mapping + PAGE_BYTES - RANGE_BYTES;
    for (index = 0; index < RANGE_BYTES; ++index) {
        edge[index] = (unsigned char)('A' + index);
        needle[index] = edge[index];
    }
    edge[RANGE_BYTES - 1] = 0xff;
    needle[RANGE_BYTES - 1] = 0xff;
    if (memchr(edge, -1, RANGE_BYTES) != edge + RANGE_BYTES - 1 ||
        memrchr(edge, -1, RANGE_BYTES) != edge + RANGE_BYTES - 1 ||
        memmem(edge, RANGE_BYTES, "A", 1) != edge ||
        memmem(edge, RANGE_BYTES, needle, RANGE_BYTES) != edge)
        status = 3;
    /* The next byte is inaccessible; a bounded operation must not inspect it. */
    if (memchr(edge, 'A', RANGE_BYTES - 1) != edge ||
        memrchr(edge, -1, RANGE_BYTES - 1) != NULL ||
        memmem(edge, RANGE_BYTES - 1, needle, RANGE_BYTES) != NULL)
        status = 4;
    if (raw_munmap(mapping, PAGE_BYTES * 2) != 0)
        status = 5;
    return status;
}

int crabc_x86_64_memory_search_probe(void)
{
    int status;

    status = test_null_zero_and_conversion();
    if (status != 0)
        return 10 + status;
    status = test_memchr_and_memrchr_ranges();
    if (status != 0)
        return 20 + status;
    status = test_memmem_shapes();
    if (status != 0)
        return 30 + status;
    status = test_long_periodic_and_random();
    if (status != 0)
        return 40 + status;
    status = test_page_edge_bounds();
    if (status != 0)
        return 50 + status;
    return 0;
}

#ifndef CRABC_MEMORY_SEARCH_FREESTANDING
int main(void)
{
    return crabc_x86_64_memory_search_probe();
}
#endif

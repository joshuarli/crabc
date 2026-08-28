/* Static crabc-libc x86-64 byte-string fixture.
 *
 * The project-header C body first runs against pinned musl 1.2.6 and then as
 * a freestanding executable linked only with the selected crabc archive. It
 * deliberately closes over the 13 byte-string entry points below. The test
 * cases pin byte (rather than signed-char) ordering, bounded zero-length
 * calls, high-bit data, returned pointer offsets, set scans, and substring
 * edge cases. Raw mapping syscalls are fixture plumbing for the page-edge
 * terminator check; this is not a copy, token, locale, or allocator surface.
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
#include <strings.h>
#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_mmap == 9 && SYS_mprotect == 10 && SYS_munmap == 11,
    "x86 mapping syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&index),
    char *(*)(const char *, int)), "index declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&rindex),
    char *(*)(const char *, int)), "rindex declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strchr),
    char *(*)(const char *, int)), "strchr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strchrnul),
    char *(*)(const char *, int)), "strchrnul declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strcmp),
    int (*)(const char *, const char *)), "strcmp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strcspn),
    size_t (*)(const char *, const char *)), "strcspn declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strlen),
    size_t (*)(const char *)), "strlen declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strncmp),
    int (*)(const char *, const char *, size_t)), "strncmp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strnlen),
    size_t (*)(const char *, size_t)), "strnlen declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strpbrk),
    char *(*)(const char *, const char *)), "strpbrk declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strrchr),
    char *(*)(const char *, int)), "strrchr declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strspn),
    size_t (*)(const char *, const char *)), "strspn declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strstr),
    char *(*)(const char *, const char *)), "strstr declaration");

static long raw_syscall4(long number, long argument1, long argument2,
    long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
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

    __asm__ volatile(
        "syscall"
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

static int check_order_and_bounds(void)
{
    static const char high[] = { (char)0x80, '\0' };
    static const char low[] = { (char)0x7f, '\0' };
    static const char max[] = { (char)0xff, '\0' };

    /* C string ordering is the difference of unsigned byte values. */
    if (strcmp(high, low) != 1 || strcmp(low, high) != -1 ||
        strcmp(max, "\1") != 254 || strcmp("\1", max) != -254)
        return 1;
    if (strncmp(high, low, 1) != 1 || strncmp(low, high, 1) != -1 ||
        strncmp(high, low, 0) != 0 || strncmp("left", "right", 0) != 0 ||
        strncmp(NULL, NULL, 0) != 0 || strncmp("same", "sameX", 4) != 0)
        return 2;
    if (strlen("") != 0 || strlen("crabc") != 5 ||
        strnlen(NULL, 0) != 0 || strnlen("crabc", 0) != 0 ||
        strnlen("crabc", 3) != 3 ||
        strnlen("crabc", 20) != 5)
        return 3;
    return 0;
}

static int check_search_offsets_and_high_bytes(void)
{
    static const char text[] = { 'a', (char)0x80, 'b', 'a', 'b', '\0' };
    static const char sets[] = { 'x', (char)0x80, 'b', 'x', '\0' };
    static const char needle[] = { (char)0x80, 'b', '\0' };
    static const char byte_max[] = { 'x', (char)0xff, '\0' };

    if (strchr(text, 0x180) != text + 1 || strchr(text, 'b') != text + 2 ||
        strchr(text, '\0') != text + 5 || strchr(text, 'z') != NULL)
        return 1;
    if (index(text, 0x180) != text + 1 || index(text, 'z') != NULL ||
        rindex(text, 'a') != text + 3 || rindex(text, 0x180) != text + 1 ||
        rindex(text, '\0') != text + 5)
        return 2;
    if (strrchr(text, 'b') != text + 4 || strrchr(text, 0x180) != text + 1 ||
        strrchr(text, 'z') != NULL || strrchr(text, '\0') != text + 5)
        return 3;
    if (strchrnul(text, 'b') != text + 2 || strchrnul(text, 'z') != text + 5 ||
        strchrnul(text, '\0') != text + 5)
        return 4;
    if (strpbrk(text, sets) != text + 1 ||
        strpbrk("abc", "xz") != NULL || strpbrk("abc", "") != NULL)
        return 5;
    if (strpbrk(text, "b") != text + 2 ||
        strstr(text, needle) != text + 1)
        return 6;
    if (strchr(byte_max, -1) != byte_max + 1 ||
        strchrnul(byte_max, -1) != byte_max + 1 ||
        strrchr(byte_max, -1) != byte_max + 1 ||
        index(byte_max, -1) != byte_max + 1 ||
        rindex(byte_max, -1) != byte_max + 1)
        return 7;
    return 0;
}

static int check_sets(void)
{
    static const char repeating[] = { 'a', 'a', 'b', 'a', '\0' };
    static const char high[] = { 'q', (char)0x80, 'q', '\0' };

    if (strspn(repeating, "abbaa") != 4 || strspn(repeating, "") != 0 ||
        strspn(high, high + 1) != 3 || strspn(high + 1, high) != 2)
        return 1;
    if (strcspn(repeating, "") != 4 || strcspn(repeating, "aab") != 0 ||
        strcspn("xyz", "yyx") != 0 || strcspn(high, "q") != 0)
        return 2;
    return 0;
}

static int check_substrings(void)
{
    static const char overlap[] = "aaaaab";
    static const char repeating[] = "abababab";
    static const char empty[] = "";

    if (strstr(overlap, "aaab") != overlap + 2 ||
        strstr(repeating, "abab") != repeating ||
        strstr(repeating + 1, "abab") != repeating + 2)
        return 1;
    if (strstr(overlap, empty) != overlap || strstr(overlap, "ba") != NULL ||
        strstr(empty, "x") != NULL || strstr(empty, empty) != empty)
        return 2;
    return 0;
}

static unsigned string_random_state = 0x9e3779b9U;

static unsigned next_string_random(void)
{
    string_random_state = string_random_state * 1664525U + 1013904223U;
    return string_random_state;
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

static int check_two_way_substrings(void)
{
    char periodic[513];
    char periodic_needle[258];
    static const char high_haystack[] = {
        'p', (char)0x80, 'a', (char)0xff, 'b', (char)0x81,
        'c', 'd', 'e', 'q', '\0'
    };
    static const char high_needle[] = {
        (char)0x80, 'a', (char)0xff, 'b', (char)0x81, 'c', 'd', 'e', '\0'
    };
    static const char high_missing[] = {
        (char)0x80, 'a', (char)0xff, 'b', (char)0x81, 'c', 'd', 'f', '\0'
    };
    unsigned sample;
    size_t index;

    for (index = 0; index < sizeof(periodic) - 1; ++index)
        periodic[index] = 'a';
    periodic[sizeof(periodic) - 1] = '\0';
    for (index = 0; index < sizeof(periodic_needle) - 2; ++index)
        periodic_needle[index] = 'a';
    periodic_needle[sizeof(periodic_needle) - 2] = 'b';
    periodic_needle[sizeof(periodic_needle) - 1] = '\0';
    if (strstr(periodic, periodic_needle) != NULL)
        return 1;
    periodic[sizeof(periodic) - 2] = 'b';
    if (strstr(periodic, periodic_needle) != periodic + sizeof(periodic) - 258)
        return 2;
    if (strstr(high_haystack, high_needle) != high_haystack + 1 ||
        strstr(high_haystack, high_missing) != NULL)
        return 3;

    for (sample = 0; sample < 1024; ++sample) {
        char haystack_storage[97];
        char needle_storage[49];
        char *haystack = haystack_storage + (next_string_random() & 7U);
        char *needle = needle_storage + (next_string_random() & 7U);
        size_t haystack_length = next_string_random() % 64;
        size_t needle_length = next_string_random() % 24;

        for (index = 0; index < haystack_length; ++index)
            haystack[index] = (char)('a' + next_string_random() % 4);
        for (index = 0; index < needle_length; ++index)
            needle[index] = (char)('a' + next_string_random() % 4);
        haystack[haystack_length] = '\0';
        needle[needle_length] = '\0';
        if (strstr(haystack, needle) != naive_strstr(haystack, needle))
            return 4;
    }
    return 0;
}

static int check_page_edge_terminator(void)
{
    enum { PAGE_BYTES = 4096 };
    static const char long_edge_text[] = "abcabcabcabcabc";
    unsigned char *mapping = raw_mmap(PAGE_BYTES * 2);
    char *edge;
    int status = 0;

    if (mapping == MAP_FAILED)
        return 1;
    if (raw_mprotect(mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0) {
        raw_munmap(mapping, PAGE_BYTES * 2);
        return 2;
    }
    edge = (char *)(mapping + PAGE_BYTES - 4);
    edge[0] = 'b';
    edge[1] = 'o';
    edge[2] = 'u';
    edge[3] = 'n';
    if (strnlen(edge, 4) != 4)
        status = 3;
    edge = (char *)(mapping + PAGE_BYTES - 5);
    edge[0] = 'e';
    edge[1] = 'd';
    edge[2] = 'g';
    edge[3] = 'e';
    edge[4] = '\0';
    if (strlen(edge) != 4 || strnlen(edge, 5) != 4 ||
        strchrnul(edge, 'x') != edge + 4 || strchr(edge, '\0') != edge + 4 ||
        strrchr(edge, 'e') != edge + 3 || strstr(edge, "ge") != edge + 2)
        status = 4;
    edge = (char *)(mapping + PAGE_BYTES - sizeof(long_edge_text));
    for (size_t index = 0; index < sizeof(long_edge_text) - 1; ++index)
        edge[index] = long_edge_text[index];
    edge[sizeof(long_edge_text) - 1] = '\0';
    if (strstr(edge, long_edge_text) != edge ||
        strstr(edge, "abcabcabcabcabz") != NULL ||
        strstr(edge, "abcabcabcabcabca") != NULL)
        status = 5;
    if (raw_munmap(mapping, PAGE_BYTES * 2) != 0)
        status = 6;
    return status;
}

int crabc_x86_64_byte_strings_probe(void)
{
    int status;

    status = check_order_and_bounds();
    if (status != 0)
        return 10 + status;
    status = check_search_offsets_and_high_bytes();
    if (status != 0)
        return 20 + status;
    status = check_sets();
    if (status != 0)
        return 30 + status;
    status = check_substrings();
    if (status != 0)
        return 40 + status;
    status = check_two_way_substrings();
    if (status != 0)
        return 50 + status;
    status = check_page_edge_terminator();
    if (status != 0)
        return 60 + status;
    return 0;
}

#ifndef CRABC_BYTE_STRINGS_FREESTANDING
int main(void)
{
    return crabc_x86_64_byte_strings_probe();
}
#endif

/* Static x86-64 memccpy ABI and behavior differential.
 *
 * The same project-header C body first runs through pinned musl 1.2.6 and
 * then through an archive-free `-nostdlib -static` candidate containing only
 * the selected memccpy object. It covers low-eight-bit marker conversion,
 * return-after-marker behavior, no-match and zero-count behavior, equal and
 * unequal alignment paths, and a source page edge. It selects no general
 * bulk-memory family, C-string state, errno/TLS, syscall, stdio, resolver, or
 * runtime behavior; fixture-local raw mapping calls exist only to guard the
 * input range.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

typedef void *(*memccpy_signature)(void *__restrict, const void *__restrict,
    int, size_t);

_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8,
    "x86-64 LP64 widths");
_Static_assert(SYS_mmap == 9 && SYS_mprotect == 10 && SYS_munmap == 11,
    "Linux x86-64 mapping syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memccpy),
    memccpy_signature), "memccpy declaration");

static const memccpy_signature memccpy_function = memccpy;

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

static int check_copy(const unsigned char *source, size_t count, int marker,
    unsigned char *destination, size_t destination_capacity)
{
    unsigned char expected[80];
    size_t copied = 0;
    size_t index;
    int found = 0;
    void *result;

    if (destination_capacity > sizeof expected || count > destination_capacity)
        return 1;
    for (index = 0; index < destination_capacity; ++index) {
        destination[index] = 0xa5;
        expected[index] = 0xa5;
    }
    for (index = 0; index < count; ++index) {
        expected[index] = source[index];
        copied = index + 1;
        if (source[index] == (unsigned char)marker) {
            found = 1;
            break;
        }
    }

    result = memccpy_function(destination, source, marker, count);
    if (result != (found ? (void *)(destination + copied) : NULL))
        return 2;
    for (index = 0; index < destination_capacity; ++index)
        if (destination[index] != expected[index])
            return 3;
    return 0;
}

static int test_basic_boundaries(void)
{
    static const unsigned char source[] = {
        0x00, 0x7f, 0x80, 0xff, 0x01, 0x00, 0x42
    };
    unsigned char destination[16];
    size_t index;

    for (index = 0; index < sizeof destination; ++index)
        destination[index] = 0x5a;
    if (memccpy_function(NULL, NULL, 0, 0) != NULL)
        return 1;
    if (memccpy_function(destination, source, 0x00, 0) != NULL)
        return 2;
    for (index = 0; index < sizeof destination; ++index)
        if (destination[index] != 0x5a)
            return 3;
    if (check_copy(source, sizeof source, 0x100, destination,
            sizeof destination) != 0)
        return 4;
    if (check_copy(source, sizeof source, -1, destination,
            sizeof destination) != 0)
        return 5;
    if (check_copy(source, 3, 0xff, destination,
            sizeof destination) != 0)
        return 6;
    if (check_copy(source, 4, 0xff, destination,
            sizeof destination) != 0)
        return 7;
    if (check_copy(source, sizeof source, 0x33, destination,
            sizeof destination) != 0)
        return 8;
    return 0;
}

static int test_word_and_alignment_paths(void)
{
    unsigned char source[56];
    unsigned char destination[56];
    size_t index;

    for (index = 0; index < sizeof source; ++index)
        source[index] = (unsigned char)(0x20 + index);
    source[24] = 0x5a;
    source[38] = 0x5a;

    /* +1/+1 reaches musl's equal-alignment size_t path after seven bytes. */
    if (check_copy(source + 1, 40, 0x5a, destination + 1,
            sizeof destination - 1) != 0)
        return 1;
    /* No marker lets that same equal-alignment path copy complete words. */
    if (check_copy(source + 1, 20, 0x11, destination + 1,
            sizeof destination - 1) != 0)
        return 2;
    /* Unequal low address bits deliberately retain the source byte loop. */
    if (check_copy(source + 1, 40, 0x5a, destination + 2,
            sizeof destination - 2) != 0)
        return 3;
    return 0;
}

static int test_source_page_edge(void)
{
    enum { PAGE_BYTES = 4096, RANGE_BYTES = 32 };
    unsigned char *mapping = raw_mmap(PAGE_BYTES * 2);
    unsigned char destination[40];
    unsigned char *edge;
    size_t index;
    int status = 0;

    if (mapping == MAP_FAILED)
        return 1;
    if (raw_mprotect(mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0) {
        raw_munmap(mapping, PAGE_BYTES * 2);
        return 2;
    }
    edge = mapping + PAGE_BYTES - RANGE_BYTES;
    for (index = 0; index < RANGE_BYTES; ++index)
        edge[index] = (unsigned char)(0x10 + index);
    edge[RANGE_BYTES - 1] = 0xff;

    if (check_copy(edge, RANGE_BYTES, -1, destination,
            sizeof destination) != 0)
        status = 3;
    /* The next byte is inaccessible: a no-match bounded copy may not read it. */
    if (status == 0 && check_copy(edge, RANGE_BYTES - 1, -1, destination,
            sizeof destination) != 0)
        status = 4;
    if (raw_munmap(mapping, PAGE_BYTES * 2) != 0 && status == 0)
        status = 5;
    return status;
}

int crabc_x86_64_memccpy_probe(void)
{
    int status;

    status = test_basic_boundaries();
    if (status != 0)
        return 10 + status;
    status = test_word_and_alignment_paths();
    if (status != 0)
        return 30 + status;
    status = test_source_page_edge();
    if (status != 0)
        return 50 + status;
    return 0;
}

#ifndef CRABC_MEMCCPY_FREESTANDING
int main(void)
{
    return crabc_x86_64_memccpy_probe();
}
#endif

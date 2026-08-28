/* Static x86-64 string-copy ABI and behavior fixture.
 *
 * The project-header C body first runs against pinned musl 1.2.6 and then as
 * a freestanding executable linked only with the selected crabc archive. Its
 * closed surface is the bounded and unbounded string-copy family: stpcpy,
 * stpncpy, strcpy, strncpy, strcat, strncat, strlcpy, and strlcat. Inputs and
 * outputs are disjoint as required by the restrict-qualified interfaces.
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
_Static_assert(__builtin_types_compatible_p(__typeof__(&stpcpy),
    char *(*)(char *, const char *)), "stpcpy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&stpncpy),
    char *(*)(char *, const char *, size_t)), "stpncpy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strcpy),
    char *(*)(char *, const char *)), "strcpy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strncpy),
    char *(*)(char *, const char *, size_t)), "strncpy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strcat),
    char *(*)(char *, const char *)), "strcat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strncat),
    char *(*)(char *, const char *, size_t)), "strncat declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strlcpy),
    size_t (*)(char *, const char *, size_t)), "strlcpy declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strlcat),
    size_t (*)(char *, const char *, size_t)), "strlcat declaration");

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

static int bytes_equal(const unsigned char *left, const unsigned char *right,
    size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index)
        if (left[index] != right[index])
            return 0;
    return 1;
}

static int bytes_zero(const unsigned char *bytes, size_t length)
{
    size_t index;

    for (index = 0; index < length; ++index)
        if (bytes[index] != 0)
            return 0;
    return 1;
}

static int check_basic_copy_and_returns(void)
{
    static const char source[] = "crabc-A\200-Z";
    char destination[32];
    char padding[32];
    char *end;
    size_t result;

    end = stpcpy(destination, source);
    if (end != destination + sizeof(source) - 1 ||
        !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)source, sizeof(source)))
        return 1;
    if (strcpy(destination, "exact") != destination ||
        !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)"exact\0", 6))
        return 2;

    for (result = 0; result < sizeof padding; ++result)
        padding[result] = (char)0xa5;
    end = stpncpy(padding, "xy", 7);
    if (end != padding + 2 || padding[0] != 'x' || padding[1] != 'y' ||
        !bytes_zero((const unsigned char *)padding + 2, 5) ||
        (unsigned char)padding[7] != 0xa5)
        return 3;
    for (result = 0; result < sizeof padding; ++result)
        padding[result] = (char)0xa5;
    if (strncpy(padding, "1234567", 7) != padding ||
        !bytes_equal((const unsigned char *)padding,
            (const unsigned char *)"1234567", 7) ||
        (unsigned char)padding[7] != 0xa5)
        return 4;

    destination[0] = 'a';
    destination[1] = '\0';
    if (strcat(destination, "b\200") != destination ||
        !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)"ab\200\0", 4))
        return 5;
    if (strncat(destination, "XYZ", 0) != destination ||
        strncat(destination, "12", 1) != destination ||
        !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)"ab\2001\0", 5))
        return 6;

    destination[0] = (char)0xa5;
    result = strlcpy(destination, "long\200", 4);
    if (result != 5 || !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)"lon\0", 4))
        return 7;
    destination[0] = 'q';
    destination[1] = 'w';
    destination[2] = '\0';
    result = strlcat(destination, "xyz\200", sizeof destination);
    if (result != 6 || !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)"qwxyz\200\0", 7))
        return 8;
    return 0;
}

static int check_bounds_padding_and_zero_lengths(void)
{
    char destination[16];
    char before[16];
    size_t index;
    size_t result;

    for (index = 0; index < sizeof destination; ++index)
        destination[index] = (char)0xc3;
    if (stpncpy(destination, "abcdef", 0) != destination ||
        !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)before, 0))
        return 1;
    for (index = 0; index < sizeof destination; ++index)
        destination[index] = before[index] = (char)0xc3;
    if (strncpy(destination, "abcdef", 0) != destination ||
        !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)before, sizeof destination))
        return 2;
    for (index = 0; index < sizeof destination; ++index)
        destination[index] = (char)0xc3;
    result = strlcpy(destination, "abcdef", 0);
    if (result != 6 || !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)before, 0) ||
        (unsigned char)destination[0] != 0xc3)
        return 3;

    for (index = 0; index < sizeof destination; ++index)
        destination[index] = (char)0xc3;
    destination[0] = '\0';
    if (strncat(destination, "abc", 0) != destination ||
        !bytes_equal((const unsigned char *)destination,
            (const unsigned char *)"\0", 1))
        return 4;
    for (index = 0; index < sizeof destination; ++index)
        destination[index] = (char)0xc3;
    destination[0] = 'a';
    destination[1] = 'b';
    destination[2] = '\0';
    result = strlcat(destination, "xyz", 3);
    if (result != 5 || (unsigned char)destination[2] != 0)
        return 5;
    for (index = 0; index < sizeof destination; ++index)
        destination[index] = (char)0xc3;
    destination[0] = 'a';
    destination[1] = 'b';
    result = strlcat(destination, "xyz", 2);
    if (result != 5 || (unsigned char)destination[0] != 'a' ||
        (unsigned char)destination[1] != 'b' ||
        (unsigned char)destination[2] != 0xc3)
        return 6;
    return 0;
}

static int check_exact_fit_and_misalignment(void)
{
    unsigned char storage[64];
    const char source[] = "1234567";
    size_t index;

    for (index = 0; index < sizeof storage; ++index)
        storage[index] = 0xa5;
    if (strlcpy((char *)storage + 1, source, sizeof(source)) != 7 ||
        !bytes_equal(storage + 1, (const unsigned char *)source, sizeof source))
        return 1;
    for (index = 0; index < sizeof storage; ++index)
        storage[index] = 0xa5;
    if (stpcpy((char *)storage + 3, source) != (char *)storage + 10 ||
        !bytes_equal(storage + 3, (const unsigned char *)source, sizeof source))
        return 2;
    for (index = 0; index < sizeof storage; ++index)
        storage[index] = 0xa5;
    if (strncpy((char *)storage + 5, source, sizeof source) !=
            (char *)storage + 5 ||
        !bytes_equal(storage + 5, (const unsigned char *)source, sizeof source))
        return 3;
    return 0;
}

static int check_page_edges(void)
{
    enum { PAGE_BYTES = 4096 };
    unsigned char *mapping = raw_mmap(PAGE_BYTES * 2);
    unsigned char *source;
    unsigned char *destination;
    size_t index;
    size_t result;
    int status = 0;

    if (mapping == MAP_FAILED)
        return 1;
    if (raw_mprotect(mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0) {
        raw_munmap(mapping, PAGE_BYTES * 2);
        return 2;
    }
    destination = mapping + 128;

    /* A full C string terminates at the final readable source byte. */
    source = mapping + PAGE_BYTES - 4;
    source[0] = 'A';
    source[1] = 'B';
    source[2] = 'C';
    source[3] = '\0';
    for (index = 0; index < 32; ++index)
        destination[index] = 0xa5;
    if (strcpy((char *)destination, (const char *)source) != (char *)destination ||
        !bytes_equal(destination, source, 4)) {
        status = 3;
        goto cleanup;
    }
    for (index = 0; index < 32; ++index)
        destination[index] = 0xa5;
    if (stpcpy((char *)destination, (const char *)source) !=
            (char *)destination + 3 ||
        !bytes_equal(destination, source, 4)) {
        status = 4;
        goto cleanup;
    }
    for (index = 0; index < 32; ++index)
        destination[index] = 0xa5;
    if (strlcpy((char *)destination, (const char *)source, 4) != 3 ||
        !bytes_equal(destination, source, 4)) {
        status = 5;
        goto cleanup;
    }

    /* A bounded source has no terminator before its protected-page edge. */
    source[0] = 'W';
    source[1] = 'X';
    source[2] = 'Y';
    source[3] = 'Z';
    if (stpncpy((char *)destination, (const char *)source, 4) !=
            (char *)destination + 4 ||
        !bytes_equal(destination, source, 4)) {
        status = 6;
        goto cleanup;
    }
    for (index = 0; index < 32; ++index)
        destination[index] = 0xa5;
    if (strncpy((char *)destination, (const char *)source, 4) !=
            (char *)destination ||
        !bytes_equal(destination, source, 4)) {
        status = 7;
        goto cleanup;
    }

    /* Exact output ends at the final writable byte before PROT_NONE. */
    source = mapping + 256;
    source[0] = 'A';
    source[1] = 'B';
    source[2] = 'C';
    source[3] = '\0';
    destination = mapping + PAGE_BYTES - 4;
    destination[0] = '\0';
    if (strcat((char *)destination, (const char *)source) !=
            (char *)destination ||
        !bytes_equal(destination, source, 4)) {
        status = 8;
        goto cleanup;
    }
    destination[0] = 'A';
    destination[1] = '\0';
    source[0] = 'B';
    source[1] = 'C';
    source[2] = '\0';
    if (strncat((char *)destination, (const char *)source, 2) !=
            (char *)destination ||
        !bytes_equal(destination, (const unsigned char *)"ABC\0", 4)) {
        status = 9;
        goto cleanup;
    }

    /* strlcat must not read beyond its bounded, unterminated destination. */
    destination[0] = 'W';
    destination[1] = 'X';
    destination[2] = 'Y';
    destination[3] = 'Z';
    source[0] = 'q';
    source[1] = '\0';
    result = strlcat((char *)destination, (const char *)source, 4);
    if (result != 5 || !bytes_equal(destination,
            (const unsigned char *)"WXYZ", 4)) {
        status = 10;
        goto cleanup;
    }

    /* Bounded padding must also stop at the exact destination boundary. */
    source[0] = 'x';
    source[1] = 'y';
    source[2] = '\0';
    if (stpncpy((char *)destination, (const char *)source, 4) !=
            (char *)destination + 2 ||
        !bytes_equal(destination, (const unsigned char *)"xy\0\0", 4)) {
        status = 11;
        goto cleanup;
    }

cleanup:
    if (raw_munmap(mapping, PAGE_BYTES * 2) != 0 && status == 0)
        status = 12;
    return status;
}

int crabc_x86_64_string_copy_probe(void)
{
    int status;

    status = check_basic_copy_and_returns();
    if (status != 0)
        return 10 + status;
    status = check_bounds_padding_and_zero_lengths();
    if (status != 0)
        return 20 + status;
    status = check_exact_fit_and_misalignment();
    if (status != 0)
        return 30 + status;
    status = check_page_edges();
    if (status != 0)
        return 40 + status;
    return 0;
}

#ifndef CRABC_STRING_COPY_FREESTANDING
int main(void)
{
    return crabc_x86_64_string_copy_probe();
}
#endif

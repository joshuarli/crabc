/*
 * Native Linux/x86-64 C string-duplication allocation boundary probe.
 *
 * The same body executes against pinned musl and the opt-in static crabc-libc
 * candidate. The candidate owns strdup/strndup plus the existing allocation
 * wrapper, errno slot, and bundled backend; pinned musl still supplies its
 * unselected startup/process graph, but never a duplication or allocator
 * implementation object.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(sizeof(size_t) == 8 && sizeof(void *) == 8,
    "x86-64 LP64 widths");
_Static_assert(SYS_mmap == 9 && SYS_mprotect == 10 && SYS_munmap == 11,
    "Linux x86-64 mapping syscall numbers");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strdup),
    char *(*)(const char *)), "strdup declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&strndup),
    char *(*)(const char *, size_t)), "strndup declaration");

#ifdef CRABC_ALLOCATOR_STRING_DUPLICATION_CANDIDATE
extern size_t __crabc_x86_allocator_string_duplication_v1(void);
#endif

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

static int check_strdup_ownership(void)
{
    static const char source[] = { 'A', (char)0x80, 'Z', '\0' };
    char *copy;

    errno = E2BIG;
    copy = strdup(source);
    if (copy == NULL || copy == source ||
        !bytes_equal((const unsigned char *)copy,
            (const unsigned char *)source, sizeof source) || errno != E2BIG)
        return 1;
    copy[0] = 'B';
    if (source[0] != 'A')
        return 2;
    free(copy);
    if (errno != E2BIG)
        return 3;
    return 0;
}

static int check_strndup_limits(void)
{
    char *copy;

    errno = ENOTTY;
    copy = strndup("abcdef", 3);
    if (copy == NULL || !bytes_equal((const unsigned char *)copy,
            (const unsigned char *)"abc\0", 4) || errno != ENOTTY)
        return 1;
    free(copy);
    if (errno != ENOTTY)
        return 2;

    copy = strndup("abc", 64);
    if (copy == NULL || !bytes_equal((const unsigned char *)copy,
            (const unsigned char *)"abc\0", 4))
        return 3;
    free(copy);

    errno = EDOM;
    copy = strndup("ignored", 0);
    if (copy == NULL || copy[0] != '\0' || errno != EDOM)
        return 4;
    free(copy);
    if (errno != EDOM)
        return 5;
    return 0;
}

static int check_page_edges(void)
{
    enum { PAGE_BYTES = 4096 };
    unsigned char *mapping = raw_mmap(PAGE_BYTES * 2);
    unsigned char *edge;
    char *copy;
    int status = 0;

    if (mapping == MAP_FAILED)
        return 1;
    if (raw_mprotect(mapping + PAGE_BYTES, PAGE_BYTES, PROT_NONE) != 0) {
        raw_munmap(mapping, PAGE_BYTES * 2);
        return 2;
    }

    /* strndup must not inspect past its exact bounded source range. */
    edge = mapping + PAGE_BYTES - 4;
    edge[0] = 'W';
    edge[1] = 'X';
    edge[2] = 'Y';
    edge[3] = 'Z';
    errno = EINTR;
    copy = strndup((const char *)edge, 4);
    if (copy == NULL || !bytes_equal((const unsigned char *)copy,
            (const unsigned char *)"WXYZ\0", 5) || errno != EINTR) {
        status = 3;
        goto cleanup;
    }
    free(copy);

    /* strdup may read through its terminator, but never past the page edge. */
    edge[0] = 'Q';
    edge[1] = (unsigned char)0x80;
    edge[2] = 'R';
    edge[3] = '\0';
    copy = strdup((const char *)edge);
    if (copy == NULL || !bytes_equal((const unsigned char *)copy, edge, 4)) {
        status = 4;
        goto cleanup;
    }
    free(copy);

cleanup:
    if (raw_munmap(mapping, PAGE_BYTES * 2) != 0 && status == 0)
        status = 5;
    return status;
}

int crabc_x86_64_allocator_string_duplication_probe(void)
{
#ifdef CRABC_ALLOCATOR_STRING_DUPLICATION_CANDIDATE
    if (__crabc_x86_allocator_string_duplication_v1() != 1)
        return 100;
#endif
    if (check_strdup_ownership() != 0)
        return 1;
    if (check_strndup_limits() != 0)
        return 2;
    if (check_page_edges() != 0)
        return 3;
    return 0;
}

int main(void)
{
    return crabc_x86_64_allocator_string_duplication_probe();
}

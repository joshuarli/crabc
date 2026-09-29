/* Native Linux/x86-64 selected-static C mapping-core fixture.
 *
 * One project-header C body executes first with pinned musl 1.2.6 and then
 * with the dependency-free static crabc-libc archive. It proves only the
 * caller-owned mmap/munmap/mprotect/madvise/posix_madvise/mincore/msync lifecycle;
 * it is not evidence for the broader <sys/mman.h> family, allocator, CRT,
 * loader, pthread/TLS lifecycle, sysroot, or public x86 support.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

enum {
    CRABC_PAGE_SIZE = 4096,
    CRABC_RESIDENCY_SENTINEL = 0xa5,
};

#define CRABC_MMAP_TYPE void *(*)(void *, size_t, int, int, int, off_t)

_Static_assert(SYS_mmap == 9, "x86 mmap syscall");
_Static_assert(SYS_mprotect == 10, "x86 mprotect syscall");
_Static_assert(SYS_munmap == 11, "x86 munmap syscall");
_Static_assert(SYS_mincore == 27, "x86 mincore syscall");
_Static_assert(SYS_madvise == 28, "x86 madvise syscall");
_Static_assert(SYS_msync == 26, "x86 msync syscall");
_Static_assert(SYS_memfd_create == 319 && SYS_ftruncate == 77 &&
    SYS_dup == 32 && SYS_close == 3 && SYS_pread64 == 17,
    "x86 descriptor syscalls for the file mapping control");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mmap), CRABC_MMAP_TYPE),
    "mmap declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&munmap),
    int (*)(void *, size_t)), "munmap declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mprotect),
    int (*)(void *, size_t, int)), "mprotect declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&madvise),
    int (*)(void *, size_t, int)), "madvise declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&posix_madvise),
    int (*)(void *, size_t, int)), "posix_madvise declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mincore),
    int (*)(void *, size_t, unsigned char *)), "mincore declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msync),
    int (*)(void *, size_t, int)), "msync declaration");

/* Keep descriptor setup independent of either libc. The candidate still has
 * to use its selected mapping and synchronization entry points below. */
static long raw_descriptor_call(long number, long first, long second,
    long third, long fourth)
{
    register long fourth_arg __asm__("r10") = fourth;
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third), "r"(fourth_arg)
        : "rcx", "r11", "cc", "memory");
    return result;
}

static int file_mapping_survives_descriptor_close(void)
{
    const char name[] = "crabc-mapping-core";
    unsigned char file_bytes[2] = {0, 0};
    volatile unsigned char *first;
    volatile unsigned char *second;
    volatile unsigned char *private_copy;
    long descriptor = raw_descriptor_call(SYS_memfd_create, (long)name, 0, 0, 0);
    long retained;

    if (descriptor < 0 || raw_descriptor_call(SYS_ftruncate, descriptor,
            CRABC_PAGE_SIZE * 2, 0, 0) != 0)
        return 30;
    retained = raw_descriptor_call(SYS_dup, descriptor, 0, 0, 0);
    if (retained < 0)
        return 31;
    first = mmap(0, CRABC_PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
        MAP_SHARED, (int)descriptor, 0);
    second = mmap(0, CRABC_PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
        MAP_SHARED, (int)descriptor, 0);
    private_copy = mmap(0, CRABC_PAGE_SIZE, PROT_READ | PROT_WRITE,
        MAP_PRIVATE, (int)descriptor, 0);
    if (first == MAP_FAILED || second == MAP_FAILED || private_copy == MAP_FAILED)
        return 32;
    if (raw_descriptor_call(SYS_close, descriptor, 0, 0, 0) != 0)
        return 33;

    errno = ERANGE;
    if (mmap((void *)first, CRABC_PAGE_SIZE, PROT_READ,
            MAP_SHARED | MAP_FIXED_NOREPLACE, (int)retained, 0) != MAP_FAILED ||
            errno != EEXIST)
        return 34;
    first[0] = 0x41;
    first[CRABC_PAGE_SIZE] = 0x62;
    if (second[0] != 0x41 || second[CRABC_PAGE_SIZE] != 0x62)
        return 35;

    private_copy[0] = 0x7e;
    if (first[0] != 0x41 || second[0] != 0x41)
        return 36;
    errno = ERANGE;
    if (mprotect((void *)(first + 1), CRABC_PAGE_SIZE - 1, PROT_READ) != 0 ||
            errno != ERANGE)
        return 37;
    second[0] = 0x53;
    if (first[0] != 0x53 || private_copy[0] != 0x7e)
        return 38;

    errno = ERANGE;
    if (msync((void *)first, CRABC_PAGE_SIZE * 2, MS_SYNC) != 0 ||
            errno != ERANGE)
        return 39;
    if (raw_descriptor_call(SYS_pread64, retained, (long)file_bytes,
            sizeof file_bytes, 0) != (long)sizeof file_bytes ||
            file_bytes[0] != 0x53)
        return 40;
    if (raw_descriptor_call(SYS_pread64, retained, (long)file_bytes,
            1, CRABC_PAGE_SIZE) != 1 || file_bytes[0] != 0x62)
        return 41;
    if (raw_descriptor_call(SYS_close, retained, 0, 0, 0) != 0)
        return 42;
    second[1] = 0x29;
    if (first[1] != 0x29 || private_copy[0] != 0x7e)
        return 43;
    errno = ERANGE;
    if (msync((void *)second, CRABC_PAGE_SIZE * 2, MS_SYNC) != 0 ||
            errno != ERANGE)
        return 44;
    if (munmap((void *)private_copy, CRABC_PAGE_SIZE) != 0 ||
            munmap((void *)second, CRABC_PAGE_SIZE * 2) != 0 ||
            munmap((void *)first, CRABC_PAGE_SIZE * 2) != 0)
        return 45;
    return 0;
}

int crabc_x86_64_mapping_core_probe(void)
{
    volatile unsigned char *bytes;
    unsigned char residency[3] = {
        CRABC_RESIDENCY_SENTINEL,
        CRABC_RESIDENCY_SENTINEL,
        CRABC_RESIDENCY_SENTINEL,
    };
    void *mapping;

    errno = ERANGE;
    mapping = mmap(0, CRABC_PAGE_SIZE * 2, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || errno != ERANGE)
        return 10;
    bytes = mapping;

    errno = 0;
    if (mmap(0, (size_t)PTRDIFF_MAX, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED || errno != ENOMEM)
        return 11;

    errno = 0;
    if (mmap(0, CRABC_PAGE_SIZE, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 1) != MAP_FAILED || errno != EINVAL)
        return 12;

    /* Pinned musl rounds an unaligned address and the ending range before
     * mprotect. A raw Linux x86 syscall would reject this request with EINVAL. */
    errno = ERANGE;
    if (mprotect((void *)(bytes + 1), CRABC_PAGE_SIZE, PROT_READ) != 0 || errno != ERANGE)
        return 13;
    if (mprotect(mapping, CRABC_PAGE_SIZE * 2, PROT_READ | PROT_WRITE) != 0)
        return 14;

    errno = ERANGE;
    if (madvise(mapping, 0, MADV_NORMAL) != 0 || errno != ERANGE)
        return 15;
    errno = ERANGE;
    if (madvise((void *)(bytes + 1), CRABC_PAGE_SIZE, MADV_NORMAL) != -1 || errno != EINVAL)
        return 16;

    bytes[0] = 0x5a;
    if (madvise(mapping, CRABC_PAGE_SIZE, MADV_DONTNEED) != 0 || bytes[0] != 0)
        return 17;

    bytes[0] = 0x5a;
    errno = ERANGE;
    if (posix_madvise((void *)(bytes + 1), CRABC_PAGE_SIZE, POSIX_MADV_DONTNEED) != 0 ||
            errno != ERANGE || bytes[0] != 0x5a)
        return 18;
    errno = ERANGE;
    if (posix_madvise((void *)(bytes + 1), CRABC_PAGE_SIZE, POSIX_MADV_NORMAL) != EINVAL ||
            errno != ERANGE)
        return 19;

    bytes[0] = 0x2b;
    bytes[CRABC_PAGE_SIZE] = 0x3c;
    if (mincore(mapping, CRABC_PAGE_SIZE * 2, residency) != 0 ||
            (residency[0] & 1) == 0 || (residency[1] & 1) == 0 ||
            residency[2] != CRABC_RESIDENCY_SENTINEL)
        return 20;

    residency[0] = CRABC_RESIDENCY_SENTINEL;
    residency[1] = CRABC_RESIDENCY_SENTINEL;
    residency[2] = CRABC_RESIDENCY_SENTINEL;
    if (mincore(mapping, CRABC_PAGE_SIZE + 1, residency) != 0 ||
            (residency[0] & 1) == 0 || (residency[1] & 1) == 0 ||
            residency[2] != CRABC_RESIDENCY_SENTINEL)
        return 21;

    errno = ERANGE;
    if (munmap(mapping, CRABC_PAGE_SIZE * 2) != 0 || errno != ERANGE)
        return 22;
    return file_mapping_survives_descriptor_close();
}

#ifndef CRABC_MAPPING_CORE_FREESTANDING
int main(void)
{
    return crabc_x86_64_mapping_core_probe();
}
#endif

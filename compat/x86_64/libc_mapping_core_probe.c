/* Native Linux/x86-64 selected-static C mapping-core fixture.
 *
 * One project-header C body executes first with pinned musl 1.2.6 and then
 * with the dependency-free static crabc-libc archive. It proves only the
 * caller-owned mmap/munmap/mprotect/madvise/posix_madvise/mincore lifecycle;
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
    return 0;
}

#ifndef CRABC_MAPPING_CORE_FREESTANDING
int main(void)
{
    return crabc_x86_64_mapping_core_probe();
}
#endif

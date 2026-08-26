/*
 * Source-only Linux/x86-64 <sys/mman.h> declaration and value probe.
 *
 * The pinned musl 1.2.6 x86 headers are the source-level oracle. This probe
 * is compiled with the project headers first and never links or selects a
 * crabc C runtime artifact.
 */

#if !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/mman.h>

#define CRABC_MMAP_TYPE void *(*)(void *, size_t, int, int, int, off_t)
#define CRABC_MREMAP_TYPE void *(*)(void *, size_t, size_t, int, ...)

_Static_assert(PROT_NONE == 0, "x86 PROT_NONE");
_Static_assert(PROT_READ == 1, "x86 PROT_READ");
_Static_assert(PROT_WRITE == 2, "x86 PROT_WRITE");
_Static_assert(PROT_EXEC == 4, "x86 PROT_EXEC");
_Static_assert(PROT_GROWSDOWN == 0x01000000, "x86 PROT_GROWSDOWN");
_Static_assert(PROT_GROWSUP == 0x02000000, "x86 PROT_GROWSUP");

_Static_assert(MAP_SHARED == 0x01, "x86 MAP_SHARED");
_Static_assert(MAP_PRIVATE == 0x02, "x86 MAP_PRIVATE");
_Static_assert(MAP_SHARED_VALIDATE == 0x03, "x86 MAP_SHARED_VALIDATE");
_Static_assert(MAP_TYPE == 0x0f, "x86 MAP_TYPE");
_Static_assert(MAP_FIXED == 0x10, "x86 MAP_FIXED");
_Static_assert(MAP_ANONYMOUS == 0x20, "x86 MAP_ANONYMOUS");
_Static_assert(MAP_32BIT == 0x40, "x86 MAP_32BIT");
_Static_assert(MAP_GROWSDOWN == 0x0100, "x86 MAP_GROWSDOWN");
_Static_assert(MAP_DENYWRITE == 0x0800, "x86 MAP_DENYWRITE");
_Static_assert(MAP_EXECUTABLE == 0x1000, "x86 MAP_EXECUTABLE");
_Static_assert(MAP_LOCKED == 0x2000, "x86 MAP_LOCKED");
_Static_assert(MAP_NORESERVE == 0x4000, "x86 MAP_NORESERVE");
_Static_assert(MAP_POPULATE == 0x8000, "x86 MAP_POPULATE");
_Static_assert(MAP_NONBLOCK == 0x10000, "x86 MAP_NONBLOCK");
_Static_assert(MAP_STACK == 0x20000, "x86 MAP_STACK");
_Static_assert(MAP_HUGETLB == 0x40000, "x86 MAP_HUGETLB");
_Static_assert(MAP_SYNC == 0x80000, "x86 MAP_SYNC");
_Static_assert(MAP_FIXED_NOREPLACE == 0x100000, "x86 MAP_FIXED_NOREPLACE");
_Static_assert(MAP_FILE == 0, "x86 MAP_FILE");
_Static_assert(MAP_HUGE_SHIFT == 26 && MAP_HUGE_MASK == 0x3f,
    "x86 huge-page encoding");

_Static_assert(MS_ASYNC == 1 && MS_INVALIDATE == 2 && MS_SYNC == 4,
    "x86 msync modes");
_Static_assert(MCL_CURRENT == 1 && MCL_FUTURE == 2,
    "x86 memory-lock modes");
_Static_assert(POSIX_MADV_NORMAL == 0 && POSIX_MADV_DONTNEED == 4,
    "POSIX memory-advice modes");
_Static_assert(MADV_NORMAL == 0 && MADV_COLLAPSE == 25 && MADV_SOFT_OFFLINE == 101,
    "Linux memory-advice modes");
_Static_assert(MREMAP_MAYMOVE == 1 && MREMAP_FIXED == 2 && MREMAP_DONTUNMAP == 4,
    "Linux remap modes");
_Static_assert(MLOCK_ONFAULT == 1U && MFD_CLOEXEC == 1U,
    "GNU memory flags");

_Static_assert(__builtin_types_compatible_p(__typeof__(&mmap), CRABC_MMAP_TYPE),
    "mmap declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mremap), CRABC_MREMAP_TYPE),
    "mremap declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&munmap),
    int (*)(void *, size_t)), "munmap declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mprotect),
    int (*)(void *, size_t, int)), "mprotect declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mincore),
    int (*)(void *, size_t, unsigned char *)), "mincore declaration");

int crabc_x86_64_mman_header_abi_probe(void)
{
    return MAP_32BIT + MAP_FIXED_NOREPLACE + MREMAP_DONTUNMAP;
}

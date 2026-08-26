/*
 * Pinned-musl Linux/x86-64 mapping ABI reference constants.
 *
 * This is a reference-only C fixture for the staged Rust mapping facade. It
 * deliberately does not include project headers or link a crabc artifact.
 */

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#define _GNU_SOURCE

#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(PROT_NONE == 0x0, "x86 PROT_NONE");
_Static_assert(PROT_READ == 0x1, "x86 PROT_READ");
_Static_assert(PROT_WRITE == 0x2, "x86 PROT_WRITE");
_Static_assert(PROT_EXEC == 0x4, "x86 PROT_EXEC");
_Static_assert(MAP_SHARED == 0x01, "x86 MAP_SHARED");
_Static_assert(MAP_PRIVATE == 0x02, "x86 MAP_PRIVATE");
_Static_assert(MAP_ANONYMOUS == 0x20, "x86 MAP_ANONYMOUS");
_Static_assert(MAP_32BIT == 0x40, "x86 MAP_32BIT is intentionally deferred");
_Static_assert(MAP_FIXED == 0x10, "x86 MAP_FIXED is intentionally deferred");
_Static_assert(MAP_FIXED_NOREPLACE == 0x00100000,
    "x86 MAP_FIXED_NOREPLACE is intentionally deferred");
_Static_assert(MREMAP_MAYMOVE == 0x1, "x86 MREMAP_MAYMOVE");
_Static_assert(MREMAP_FIXED == 0x2, "x86 MREMAP_FIXED is facade-internal");
_Static_assert(MREMAP_DONTUNMAP == 0x4,
    "x86 MREMAP_DONTUNMAP is intentionally deferred");
_Static_assert(SYS_mmap == 9, "x86 mmap syscall number");
_Static_assert(SYS_mprotect == 10, "x86 mprotect syscall number");
_Static_assert(SYS_munmap == 11, "x86 munmap syscall number");
_Static_assert(SYS_mremap == 25, "x86 mremap syscall number");

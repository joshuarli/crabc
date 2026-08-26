/* Pinned-musl Linux/x86-64 madvise ABI and behavior reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>

enum { PAGE_SIZE_REFERENCE = 4096 };

_Static_assert(MADV_NORMAL == 0x0, "x86 MADV_NORMAL");
_Static_assert(MADV_RANDOM == 0x1, "x86 MADV_RANDOM");
_Static_assert(MADV_SEQUENTIAL == 0x2, "x86 MADV_SEQUENTIAL");
_Static_assert(MADV_WILLNEED == 0x3, "x86 MADV_WILLNEED");
_Static_assert(MADV_DONTNEED == 0x4, "x86 MADV_DONTNEED");
_Static_assert(POSIX_MADV_NORMAL == 0x0, "x86 POSIX_MADV_NORMAL");
_Static_assert(POSIX_MADV_RANDOM == 0x1, "x86 POSIX_MADV_RANDOM");
_Static_assert(POSIX_MADV_SEQUENTIAL == 0x2, "x86 POSIX_MADV_SEQUENTIAL");
_Static_assert(POSIX_MADV_WILLNEED == 0x3, "x86 POSIX_MADV_WILLNEED");
_Static_assert(POSIX_MADV_DONTNEED == 0x4, "x86 POSIX_MADV_DONTNEED");
_Static_assert(SYS_madvise == 28, "x86 madvise syscall number");

int main(void)
{
    void *mapping = mmap(NULL, PAGE_SIZE_REFERENCE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile unsigned char *byte;
    unsigned char observed;

    if (mapping == MAP_FAILED)
        return 1;
    byte = (volatile unsigned char *)mapping;
    *byte = 0x5a;
    if (madvise(mapping, 0, MADV_NORMAL) != 0)
        return 2;
    if (madvise(mapping, PAGE_SIZE_REFERENCE, MADV_NORMAL) != 0 ||
        madvise(mapping, PAGE_SIZE_REFERENCE, MADV_RANDOM) != 0 ||
        madvise(mapping, PAGE_SIZE_REFERENCE, MADV_SEQUENTIAL) != 0 ||
        madvise(mapping, PAGE_SIZE_REFERENCE, MADV_WILLNEED) != 0)
        return 3;
    errno = 0;
    if (madvise((unsigned char *)mapping + 1, PAGE_SIZE_REFERENCE,
                MADV_NORMAL) != -1 || errno != EINVAL)
        return 4;
    if (madvise(mapping, PAGE_SIZE_REFERENCE, MADV_DONTNEED) != 0)
        return 5;
    observed = *byte;
    *byte = 0x6b;
    if (posix_madvise((unsigned char *)mapping + 1, PAGE_SIZE_REFERENCE,
                      POSIX_MADV_DONTNEED) != 0)
        return 6;
    if (*byte != 0x6b)
        return 7;
    if (munmap(mapping, PAGE_SIZE_REFERENCE) != 0)
        return 8;

    if (observed != 0)
        return 9;
    puts("syscall=28 advice=0,1,2,3,4 zero-length=noop unaligned=EINVAL private-anonymous-dontneed=zero posix-dontneed=noop");
    return 0;
}

/* Pinned-musl Linux/x86-64 msync ABI and behavior reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>

enum { PAGE_SIZE_REFERENCE = 4096 };

_Static_assert(MS_ASYNC == 0x1, "x86 MS_ASYNC");
_Static_assert(MS_INVALIDATE == 0x2, "x86 MS_INVALIDATE");
_Static_assert(MS_SYNC == 0x4, "x86 MS_SYNC");
_Static_assert(SYS_msync == 26, "x86 msync syscall number");

static int check_msync(void *mapping, int flags, int expected_success)
{
    errno = 0;
    if (msync(mapping, PAGE_SIZE_REFERENCE, flags) == 0)
        return expected_success;
    return !expected_success && errno == EINVAL;
}

int main(void)
{
    void *mapping = mmap(NULL, PAGE_SIZE_REFERENCE, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    volatile unsigned char *byte;

    if (mapping == MAP_FAILED)
        return 1;
    byte = (volatile unsigned char *)mapping;
    *byte = 0x5a;

    if (msync(mapping, 0, 0) != 0)
        return 2;

    /* Linux accepts each single mode, MS_INVALIDATE alone, and its valid
       combinations; setting both synchronization modes remains EINVAL. */
    if (!check_msync(mapping, 0, 1) ||
        !check_msync(mapping, MS_ASYNC, 1) ||
        !check_msync(mapping, MS_INVALIDATE, 1) ||
        !check_msync(mapping, MS_ASYNC | MS_INVALIDATE, 1) ||
        !check_msync(mapping, MS_SYNC, 1) ||
        !check_msync(mapping, MS_SYNC | MS_INVALIDATE, 1) ||
        !check_msync(mapping, MS_ASYNC | MS_SYNC, 0) ||
        !check_msync(mapping, MS_ASYNC | MS_SYNC | MS_INVALIDATE, 0))
        return 3;

    if (*byte != 0x5a)
        return 4;
    if (munmap(mapping, PAGE_SIZE_REFERENCE) != 0)
        return 5;

    puts("syscall=26 flags=0,1,2,3,4,6 accepted invalid=5,7=EINVAL");
    return 0;
}

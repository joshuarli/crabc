/* Pinned-musl Linux/x86-64 memory-locking ABI and behavior reference. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

enum { PAGE_SIZE_REFERENCE = 4096 };

_Static_assert(MLOCK_ONFAULT == 0x1, "x86 MLOCK_ONFAULT");
_Static_assert(SYS_mlock == 149, "x86 mlock syscall number");
_Static_assert(SYS_munlock == 150, "x86 munlock syscall number");
_Static_assert(SYS_mlock2 == 325, "x86 mlock2 syscall number");

static int permitted_lock_error(int error)
{
    return error == EPERM || error == EAGAIN || error == ENOMEM;
}

int main(void)
{
    void *mapping;
    int lock_available = 0;
    unsigned char *overflowing = (unsigned char *)(uintptr_t)(UINTPTR_MAX -
                                                               PAGE_SIZE_REFERENCE + 1);

    mapping = mmap(NULL, PAGE_SIZE_REFERENCE, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 1;

    errno = 0;
    if (syscall(SYS_mlock, mapping, PAGE_SIZE_REFERENCE) == 0) {
        lock_available = 1;
        if (syscall(SYS_munlock, mapping, PAGE_SIZE_REFERENCE) != 0)
            return 2;
    } else if (!permitted_lock_error(errno)) {
        return 3;
    }

    errno = 0;
    if (syscall(SYS_mlock2, mapping, PAGE_SIZE_REFERENCE, MLOCK_ONFAULT) == 0) {
        if (syscall(SYS_munlock, mapping, PAGE_SIZE_REFERENCE) != 0)
            return 4;
    } else if (!permitted_lock_error(errno)) {
        return 5;
    }

    errno = 0;
    if (syscall(SYS_mlock2, mapping, PAGE_SIZE_REFERENCE, 2U) != -1 ||
        errno != EINVAL)
        return 6;

    errno = 0;
    if (syscall(SYS_mlock, overflowing, PAGE_SIZE_REFERENCE) != -1 ||
        errno != EINVAL)
        return 7;
    errno = 0;
    if (syscall(SYS_munlock, overflowing, PAGE_SIZE_REFERENCE) != -1 ||
        errno != EINVAL)
        return 8;

    if (munmap(mapping, PAGE_SIZE_REFERENCE) != 0)
        return 9;

    printf("syscalls=149,325,150 flag=1 lock=%s unknown=EINVAL overflow=EINVAL\n",
           lock_available ? "available" : "limited");
    return 0;
}

/* Native Linux/x86-64 selected-static C per-range memory-locking fixture.
 *
 * One project-header C body first executes with pinned musl 1.2.6 and then
 * with a dependency-free static crabc-libc archive. Raw Linux mapping setup
 * and teardown keep the candidate surface limited to mlock, munlock, and GNU
 * mlock2(MLOCK_ONFAULT). The fixture records the direct Linux limit outcomes
 * rather than assuming CAP_IPC_LOCK or a particular RLIMIT_MEMLOCK value.
 * It does not select mlockall/munlockall, msync, mremap, mapping policy,
 * allocator, CRT, loader, sysroot, or public x86 support.
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
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

enum { CRABC_MEMORY_LOCK_PAGE_SIZE = 4096 };

#define CRABC_MLOCK_TYPE int (*)(const void *, size_t)
#define CRABC_MLOCK2_TYPE int (*)(const void *, size_t, unsigned)

_Static_assert(SYS_mmap == 9 && SYS_munmap == 11, "x86 raw mapping syscalls");
_Static_assert(SYS_mlock == 149 && SYS_munlock == 150 && SYS_mlock2 == 325,
    "x86 selected memory-locking syscalls");
_Static_assert(MLOCK_ONFAULT == 0x01U, "GNU MLOCK_ONFAULT value");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mlock),
    CRABC_MLOCK_TYPE), "mlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&munlock),
    CRABC_MLOCK_TYPE), "munlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mlock2),
    CRABC_MLOCK2_TYPE), "mlock2 declaration");

static long raw2(long number, long argument_one, long argument_two)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two)
        : "rcx", "r11", "memory");
    return result;
}

static long raw6(long number, long argument_one, long argument_two,
    long argument_three, long argument_four, long argument_five,
    long argument_six)
{
    long result;
    register long fourth __asm__("r10") = argument_four;
    register long fifth __asm__("r8") = argument_five;
    register long sixth __asm__("r9") = argument_six;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three), "r"(fourth), "r"(fifth), "r"(sixth)
        : "rcx", "r11", "memory");
    return result;
}

static int permitted_lock_error(int error)
{
    return error == EPERM || error == EAGAIN || error == ENOMEM;
}

static int release_if_locked(const void *mapping, int was_locked,
    int expected_errno, int failure)
{
    if (was_locked && (munlock(mapping, CRABC_MEMORY_LOCK_PAGE_SIZE) != 0 ||
        errno != expected_errno))
        return failure;
    return 0;
}

int crabc_x86_64_memory_locking_probe(void)
{
    const void *overflowing = (const void *)(uintptr_t)(UINTPTR_MAX -
        CRABC_MEMORY_LOCK_PAGE_SIZE + 1);
    volatile unsigned char *bytes;
    void *mapping;
    long raw_mapping;
    int locked = 0;
    int result = 0;

    raw_mapping = raw6(SYS_mmap, 0, CRABC_MEMORY_LOCK_PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw_mapping < 0 && raw_mapping >= -4095)
        return 10;
    mapping = (void *)raw_mapping;
    bytes = mapping;
    bytes[0] = 0x5a;

    errno = EDOM;
    if (mlock(mapping, CRABC_MEMORY_LOCK_PAGE_SIZE) == 0) {
        locked = 1;
        if (errno != EDOM) {
            result = 11;
            goto cleanup;
        }
        result = release_if_locked(mapping, locked, EDOM, 12);
        if (result != 0)
            goto cleanup;
        locked = 0;
    } else if (!permitted_lock_error(errno)) {
        result = 13;
        goto cleanup;
    }

    /* musl's GNU mlock2 source delegates its zero-flags form to mlock. */
    errno = ERANGE;
    if (mlock2(mapping, CRABC_MEMORY_LOCK_PAGE_SIZE, 0) == 0) {
        locked = 1;
        if (errno != ERANGE) {
            result = 14;
            goto cleanup;
        }
        result = release_if_locked(mapping, locked, ERANGE, 15);
        if (result != 0)
            goto cleanup;
        locked = 0;
    } else if (!permitted_lock_error(errno)) {
        result = 16;
        goto cleanup;
    }

    errno = EILSEQ;
    if (mlock2(mapping, CRABC_MEMORY_LOCK_PAGE_SIZE, MLOCK_ONFAULT) == 0) {
        locked = 1;
        bytes[0] = 0xa5;
        if (bytes[0] != 0xa5 || errno != EILSEQ) {
            result = 17;
            goto cleanup;
        }
        result = release_if_locked(mapping, locked, EILSEQ, 18);
        if (result != 0)
            goto cleanup;
        locked = 0;
    } else if (!permitted_lock_error(errno)) {
        result = 19;
        goto cleanup;
    }

    errno = 0;
    if (mlock2(mapping, CRABC_MEMORY_LOCK_PAGE_SIZE, 2U) != -1 ||
        errno != EINVAL) {
        result = 20;
        goto cleanup;
    }
    errno = 0;
    if (mlock(overflowing, CRABC_MEMORY_LOCK_PAGE_SIZE) != -1 ||
        errno != EINVAL) {
        result = 21;
        goto cleanup;
    }
    errno = 0;
    if (mlock2(overflowing, CRABC_MEMORY_LOCK_PAGE_SIZE, MLOCK_ONFAULT) != -1 ||
        errno != EINVAL) {
        result = 22;
        goto cleanup;
    }
    errno = 0;
    if (munlock(overflowing, CRABC_MEMORY_LOCK_PAGE_SIZE) != -1 ||
        errno != EINVAL) {
        result = 23;
        goto cleanup;
    }

cleanup:
    if (locked && munlock(mapping, CRABC_MEMORY_LOCK_PAGE_SIZE) != 0 &&
        result == 0)
        result = 24;
    if (raw2(SYS_munmap, (long)mapping, CRABC_MEMORY_LOCK_PAGE_SIZE) < 0 &&
        result == 0)
        result = 25;
    return result;
}

#ifndef CRABC_MEMORY_LOCKING_FREESTANDING
int main(void)
{
    return crabc_x86_64_memory_locking_probe();
}
#endif

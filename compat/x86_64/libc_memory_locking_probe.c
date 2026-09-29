/* Native Linux/x86-64 selected-static C memory-locking fixture.
 *
 * One project-header C body first executes with pinned musl 1.2.6 and then
 * with a dependency-free static crabc-libc archive. Raw Linux mapping setup
 * and teardown keep the candidate surface limited to memory-locking calls.
 * Lock acquisition may depend on CAP_IPC_LOCK and RLIMIT_MEMLOCK, so every
 * successful lock is released and resource-limit failures are accepted.
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
_Static_assert(SYS_write == 1, "x86 raw transcript syscall");
_Static_assert(SYS_mlock == 149 && SYS_munlock == 150 && SYS_mlock2 == 325,
    "x86 selected memory-locking syscalls");
_Static_assert(SYS_mlockall == 151 && SYS_munlockall == 152,
    "x86 process memory-locking syscalls");
_Static_assert(MLOCK_ONFAULT == 0x01U, "GNU MLOCK_ONFAULT value");
_Static_assert(MCL_CURRENT == 1 && MCL_FUTURE == 2 && MCL_ONFAULT == 4,
    "process memory-locking flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mlock),
    CRABC_MLOCK_TYPE), "mlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&munlock),
    CRABC_MLOCK_TYPE), "munlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mlock2),
    CRABC_MLOCK2_TYPE), "mlock2 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&mlockall),
    int (*)(int)), "mlockall declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&munlockall),
    int (*)(void)), "munlockall declaration");

static long raw2(long number, long argument_one, long argument_two)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two)
        : "rcx", "r11", "memory");
    return result;
}

static long raw3(long number, long argument_one, long argument_two,
    long argument_three)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(argument_one), "S"(argument_two),
          "d"(argument_three) : "rcx", "r11", "memory");
    return result;
}

#define EMIT(message, failure) do { \
    if (raw3(SYS_write, 1, (long)(message), sizeof(message) - 1) != \
        (long)(sizeof(message) - 1)) { \
        result = (failure); \
        goto cleanup; \
    } \
} while (0)

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
    int second_mapped = 1;
    int result = 0;

    raw_mapping = raw6(SYS_mmap, 0, 2 * CRABC_MEMORY_LOCK_PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw_mapping < 0 && raw_mapping >= -4095)
        return 10;
    mapping = (void *)raw_mapping;
    bytes = mapping;
    bytes[0] = 0x5a;
    bytes[CRABC_MEMORY_LOCK_PAGE_SIZE] = 0x6b;

    errno = EDOM;
    if (munlockall() != 0 || errno != EDOM) {
        result = 26;
        goto cleanup;
    }
    EMIT("initial-unlock=ok\n", 41);

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

    /* A one-byte unaligned unlock covers the page containing its address. */
    errno = ERANGE;
    if (munlock((const char *)mapping + 1, 1) != 0 || errno != ERANGE) {
        result = 27;
        goto cleanup;
    }
    EMIT("range-page=ok\n", 42);

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
    EMIT("range-onfault=ok\n", 43);

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
    EMIT("range-errors=ok\n", 44);

    errno = 0;
    if (mlockall(0) != -1 || errno != EINVAL) {
        result = 28;
        goto cleanup;
    }
    errno = 0;
    if (mlockall(MCL_ONFAULT) != -1 || errno != EINVAL) {
        result = 29;
        goto cleanup;
    }
    errno = 0;
    if (mlockall(MCL_CURRENT | MCL_FUTURE | (1 << 30)) != -1 ||
        errno != EINVAL) {
        result = 30;
        goto cleanup;
    }
    EMIT("process-errors=ok\n", 45);

    errno = EDOM;
    if (mlockall(MCL_CURRENT | MCL_ONFAULT) == 0) {
        if (errno != EDOM) {
            result = 31;
            goto cleanup;
        }
    } else if (!permitted_lock_error(errno)) {
        result = 32;
        goto cleanup;
    }
    errno = EILSEQ;
    if (munlockall() != 0 || errno != EILSEQ) {
        result = 33;
        goto cleanup;
    }
    EMIT("process-current=ok\n", 46);

    errno = EDOM;
    if (mlockall(MCL_FUTURE) == 0) {
        if (errno != EDOM) {
            result = 34;
            goto cleanup;
        }
    } else if (!permitted_lock_error(errno)) {
        result = 35;
        goto cleanup;
    }
    errno = ERANGE;
    if (munlockall() != 0 || errno != ERANGE) {
        result = 36;
        goto cleanup;
    }
    EMIT("process-future=ok\n", 47);

    /* Unmapping a locked page ends that mapping's lock lifetime. */
    errno = EDOM;
    if (mlock((const char *)mapping + CRABC_MEMORY_LOCK_PAGE_SIZE, 1) == 0) {
        if (errno != EDOM) {
            result = 37;
            goto cleanup;
        }
    } else if (!permitted_lock_error(errno)) {
        result = 38;
        goto cleanup;
    }
    if (raw2(SYS_munmap, (long)mapping + CRABC_MEMORY_LOCK_PAGE_SIZE,
        CRABC_MEMORY_LOCK_PAGE_SIZE) != 0) {
        result = 39;
        goto cleanup;
    }
    second_mapped = 0;
    errno = 0;
    if (munlock((const char *)mapping + CRABC_MEMORY_LOCK_PAGE_SIZE, 1)
        != -1 || errno != ENOMEM) {
        result = 50;
        goto cleanup;
    }
    errno = EILSEQ;
    if (munlock(mapping, 1) != 0 || errno != EILSEQ) {
        result = 40;
        goto cleanup;
    }
    EMIT("mapping-lifetime=ok\n", 48);

cleanup:
    if (locked && munlock(mapping, CRABC_MEMORY_LOCK_PAGE_SIZE) != 0 &&
        result == 0)
        result = 24;
    if (second_mapped && raw2(SYS_munmap,
        (long)mapping + CRABC_MEMORY_LOCK_PAGE_SIZE,
        CRABC_MEMORY_LOCK_PAGE_SIZE) < 0 && result == 0)
        result = 51;
    if (raw2(SYS_munmap, (long)mapping, CRABC_MEMORY_LOCK_PAGE_SIZE) < 0 &&
        result == 0)
        result = 25;
    if (result == 0 && raw3(SYS_write, 1, (long)"memory-locking=ok\n",
        sizeof("memory-locking=ok\n") - 1) !=
        (long)(sizeof("memory-locking=ok\n") - 1))
        result = 49;
    return result;
}

#ifndef CRABC_MEMORY_LOCKING_FREESTANDING
int main(void)
{
    return crabc_x86_64_memory_locking_probe();
}
#endif

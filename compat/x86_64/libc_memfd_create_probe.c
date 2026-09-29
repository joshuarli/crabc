/* Static crabc-libc x86-64 GNU memfd_create fixture.
 *
 * The project-header C body first executes through pinned musl 1.2.6, then
 * through a freestanding executable linked solely with the selected crabc
 * archive. It selects the direct memfd_create C ABI and initial-TLS errno
 * translation. Fixture-local raw syscalls observe the kernel-owned file
 * state without selecting other C ABI entries.
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
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

_Static_assert(sizeof(long) == 8 && sizeof(void *) == 8,
    "x86 LP64 scalar widths");
_Static_assert(SYS_close == 3 && SYS_memfd_create == 319,
    "x86 selected memfd syscall numbers");
_Static_assert(MFD_CLOEXEC == 0x0001U && MFD_ALLOW_SEALING == 0x0002U &&
    MFD_HUGETLB == 0x0004U, "x86 GNU memfd flags");
_Static_assert(__builtin_types_compatible_p(__typeof__(&memfd_create),
    int (*)(const char *, unsigned)), "memfd_create declaration");

static long raw_close(int descriptor)
{
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"((long)SYS_close), "D"((long)descriptor)
        : "rcx", "r11", "memory"
    );
    return result;
}

static long raw_one(long number, long first)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first) : "rcx", "r11", "memory");
    return result;
}

static long raw_two(long number, long first, long second)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first), "S"(second)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_three(long number, long first, long second, long third)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_mmap(int descriptor, long protection)
{
    register long fourth __asm__("r10") = MAP_SHARED;
    register long fifth __asm__("r8") = descriptor;
    register long sixth __asm__("r9") = 0;
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"((long)SYS_mmap), "D"(0L), "S"(4096L), "d"(protection),
          "r"(fourth), "r"(fifth), "r"(sixth)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_wait4(int child, int *status)
{
    register long fourth __asm__("r10") = 0;
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"((long)SYS_wait4), "D"((long)child), "S"((long)status),
          "d"(0L), "r"(fourth) : "rcx", "r11", "memory");
    return result;
}

static int close_descriptor(int descriptor)
{
    return raw_close(descriptor) == 0 ? 0 : -1;
}

static int check_valid_names_and_flags(void)
{
    static const char ordinary_name[] = "crabc-x86-static-memfd";
    static const char cloexec_name[] = "crabc-x86-static-memfd-cloexec";
    char boundary_name[251];
    int descriptor;
    unsigned index;

    for (index = 0; index < 249U; ++index)
        boundary_name[index] = 'x';
    boundary_name[249] = '\0';

    errno = EDOM;
    descriptor = memfd_create(ordinary_name, 0);
    if (descriptor < 0 || errno != EDOM)
        return 1;
    if (close_descriptor(descriptor) != 0)
        return 2;

    /* 249 content bytes are accepted by Linux 5.10; the NUL is excluded. */
    errno = ERANGE;
    descriptor = memfd_create(boundary_name, MFD_CLOEXEC);
    if (descriptor < 0 || errno != ERANGE)
        return 3;
    if (close_descriptor(descriptor) != 0)
        return 4;

    /* This only proves creation-flag forwarding, not a seal operation. */
    errno = EILSEQ;
    descriptor = memfd_create(cloexec_name, MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (descriptor < 0 || errno != EILSEQ)
        return 5;
    if (close_descriptor(descriptor) != 0)
        return 6;

    return 0;
}

static int check_direct_errors(void)
{
    static const char ordinary_name[] = "crabc-x86-static-memfd-error";
    char overlong_name[251];
    unsigned index;

    /* Linux 5.10 rejects exactly 250 content bytes with EINVAL. */
    for (index = 0; index < 250U; ++index)
        overlong_name[index] = 'x';
    overlong_name[250] = '\0';
    errno = 0;
    if (memfd_create(overlong_name, 0) != -1 || errno != EINVAL)
        return 1;

    /* Musl forwards an invalid flag word directly to Linux validation. */
    errno = 0;
    if (memfd_create(ordinary_name, UINT_MAX) != -1 || errno != EINVAL)
        return 2;

    /* Huge-page size bits require MFD_HUGETLB. */
    errno = 0;
    if (memfd_create(ordinary_name, 0x78000000U) != -1 || errno != EINVAL)
        return 4;

    /* Linux reads the label, so a non-null inaccessible pointer is EFAULT. */
    errno = 0;
    if (memfd_create((const char *)(uintptr_t)1, 0) != -1 || errno != EFAULT)
        return 3;

    return 0;
}

static int check_flags_seals_and_mapping(void)
{
    int plain = memfd_create("crabc-memfd-plain", 0);
    int descriptor;
    long mapping;

    if (plain < 0)
        return 1;
    if (raw_two(SYS_fcntl, plain, F_GETFD) != 0 ||
        raw_three(SYS_fcntl, plain, F_GET_SEALS, 0) != F_SEAL_SEAL ||
        raw_three(SYS_fcntl, plain, F_ADD_SEALS, F_SEAL_SHRINK) != -EPERM)
        return 2;
    if (close_descriptor(plain) != 0)
        return 3;

    descriptor = memfd_create("crabc-memfd-sealable",
        MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (descriptor < 0)
        return 4;
    if (raw_two(SYS_fcntl, descriptor, F_GETFD) != FD_CLOEXEC ||
        raw_three(SYS_fcntl, descriptor, F_GET_SEALS, 0) != 0 ||
        raw_two(SYS_ftruncate, descriptor, 4096) != 0)
        return 5;
    mapping = raw_mmap(descriptor, PROT_READ | PROT_WRITE);
    if (mapping < 0)
        return 6;
    if (raw_three(SYS_fcntl, descriptor, F_ADD_SEALS, F_SEAL_WRITE) != -EBUSY ||
        raw_three(SYS_fcntl, descriptor, F_ADD_SEALS,
            F_SEAL_FUTURE_WRITE) != 0 ||
        raw_mmap(descriptor, PROT_READ | PROT_WRITE) != -EPERM)
        return 7;
    *(volatile char *)(uintptr_t)mapping = 'm';
    if (raw_two(SYS_munmap, mapping, 4096) != 0 ||
        raw_three(SYS_fcntl, descriptor, F_ADD_SEALS,
            F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) != 0 ||
        raw_three(SYS_fcntl, descriptor, F_GET_SEALS, 0) !=
            (F_SEAL_FUTURE_WRITE | F_SEAL_WRITE | F_SEAL_GROW |
             F_SEAL_SHRINK | F_SEAL_SEAL) ||
        raw_two(SYS_ftruncate, descriptor, 8192) != -EPERM ||
        raw_two(SYS_ftruncate, descriptor, 2048) != -EPERM ||
        raw_three(SYS_fcntl, descriptor, F_ADD_SEALS, F_SEAL_WRITE) != -EPERM)
        return 8;
    if (close_descriptor(descriptor) != 0)
        return 9;
    return 0;
}

static int check_fork_and_descriptor_lifetime(void)
{
    int descriptor = memfd_create("crabc-memfd-fork", MFD_ALLOW_SEALING);
    long duplicate;
    long child;
    int status = -1;

    if (descriptor < 0)
        return 1;
    duplicate = raw_one(SYS_dup, descriptor);
    if (duplicate < 0 || raw_close(descriptor) != 0 ||
        raw_two(SYS_fcntl, descriptor, F_GETFD) != -EBADF ||
        raw_three(SYS_fcntl, duplicate, F_GET_SEALS, 0) != 0)
        return 2;
    child = raw_one(SYS_fork, 0);
    if (child < 0)
        return 3;
    if (child == 0) {
        int child_ok = raw_two(SYS_ftruncate, duplicate, 4096) == 0 &&
            raw_three(SYS_fcntl, duplicate, F_ADD_SEALS, F_SEAL_GROW) == 0;
        raw_one(SYS_exit, child_ok ? 0 : 1);
        __builtin_unreachable();
    }
    if (raw_wait4((int)child, &status) != child || status != 0 ||
        raw_three(SYS_fcntl, duplicate, F_GET_SEALS, 0) != F_SEAL_GROW ||
        raw_two(SYS_ftruncate, duplicate, 8192) != -EPERM ||
        raw_two(SYS_ftruncate, duplicate, 2048) != 0 ||
        raw_close((int)duplicate) != 0 ||
        raw_two(SYS_ftruncate, duplicate, 1024) != -EBADF)
        return 4;
    return 0;
}

int crabc_x86_64_memfd_create_probe(void)
{
    int result = check_valid_names_and_flags();

    if (result != 0)
        return result;
    result = check_direct_errors();
    if (result != 0)
        return 10 + result;
    result = check_flags_seals_and_mapping();
    if (result != 0)
        return 20 + result;
    result = check_fork_and_descriptor_lifetime();
    if (result != 0)
        return 30 + result;
    static const char record[] = "memfd flags seals mapping fork lifetime: PASS\n";
    return raw_three(SYS_write, 1, (long)record, sizeof(record) - 1) ==
        (long)(sizeof(record) - 1) ? 0 : 40;
}

#ifndef CRABC_MEMFD_CREATE_FREESTANDING
int main(void)
{
    return crabc_x86_64_memfd_create_probe();
}
#endif

/*
 * Pinned-musl/raw Linux/x86-64 anonymous-private mapping behavior reference.
 *
 * This fixture is C-oracle evidence only.  Its raw arm invokes the three
 * Linux syscall numbers directly; its adjacent musl arm invokes the standard
 * C wrappers.  The unaligned-address error is deliberately a raw syscall
 * assertion: musl's mprotect wrapper rounds its input range before invoking
 * the kernel. Neither arm selects a C API for crabc nor expands the bounded
 * Rust mapping contract beyond this anonymous private page lifecycle.
 */

#define _GNU_SOURCE 1

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

enum { PAGE_SIZE_REFERENCE = 4096 };

_Static_assert(sizeof(int) == 4 && sizeof(long) == 8 && sizeof(size_t) == 8 &&
                   sizeof(void *) == 8,
               "x86 little-endian LP64 scalar widths");
_Static_assert(PROT_NONE == 0x0 && PROT_READ == 0x1 && PROT_WRITE == 0x2,
               "x86 closed protection constants");
_Static_assert(MAP_PRIVATE == 0x02 && MAP_ANONYMOUS == 0x20,
               "x86 closed anonymous-private mapping constants");
_Static_assert((MAP_PRIVATE | MAP_ANONYMOUS) == 0x22,
               "x86 anonymous-private mapping flags");
_Static_assert(SYS_mmap == 9 && SYS_mprotect == 10 && SYS_munmap == 11,
               "x86 mapping syscall numbers");

enum mapping_arm {
    RAW_SYSCALL_ARM,
    MUSL_WRAPPER_ARM,
};

static void *map_private_page(enum mapping_arm arm)
{
    if (arm == RAW_SYSCALL_ARM) {
        return (void *)syscall(SYS_mmap, NULL, PAGE_SIZE_REFERENCE,
                               PROT_READ | PROT_WRITE,
                               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    return mmap(NULL, PAGE_SIZE_REFERENCE, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

static int protect_page(enum mapping_arm arm, void *mapping, int protection)
{
    if (arm == RAW_SYSCALL_ARM)
        return (int)syscall(SYS_mprotect, mapping, PAGE_SIZE_REFERENCE,
                            protection);
    return mprotect(mapping, PAGE_SIZE_REFERENCE, protection);
}

static int unmap_page(enum mapping_arm arm, void *mapping)
{
    if (arm == RAW_SYSCALL_ARM)
        return (int)syscall(SYS_munmap, mapping, PAGE_SIZE_REFERENCE);
    return munmap(mapping, PAGE_SIZE_REFERENCE);
}

static int raw_unaligned_mprotect_is_einval(unsigned char *mapping)
{
    errno = 0;
    return syscall(SYS_mprotect, mapping + 1, PAGE_SIZE_REFERENCE, PROT_READ) ==
               -1 &&
           errno == EINVAL;
}

static int run_mapping_lifecycle(enum mapping_arm arm)
{
    unsigned char *mapping;
    volatile unsigned char observed;

    if (sysconf(_SC_PAGESIZE) != PAGE_SIZE_REFERENCE)
        return 10;

    mapping = map_private_page(arm);
    if (mapping == MAP_FAILED)
        return 11;

    mapping[0] = 0x41;
    if (protect_page(arm, mapping, PROT_READ) != 0)
        return 12;
    observed = ((volatile unsigned char *)mapping)[0];
    if (observed != 0x41)
        return 13;

    if (protect_page(arm, mapping, PROT_READ | PROT_WRITE) != 0)
        return 14;
    mapping[0] = 0x5a;
    observed = ((volatile unsigned char *)mapping)[0];
    if (observed != 0x5a)
        return 15;

    if (arm == RAW_SYSCALL_ARM && !raw_unaligned_mprotect_is_einval(mapping))
        return 16;

    if (unmap_page(arm, mapping) != 0)
        return 17;
    return 0;
}

static int run_in_child(enum mapping_arm arm)
{
    int status;
    pid_t child = fork();

    if (child < 0)
        return -1;
    if (child == 0)
        _exit(run_mapping_lifecycle(arm));

    while (waitpid(child, &status, 0) == -1) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(void)
{
    if (run_in_child(RAW_SYSCALL_ARM) != 0 ||
        run_in_child(MUSL_WRAPPER_ARM) != 0)
        return 1;

    puts("mmap=9 mprotect=10 munmap=11 raw+musl=anonymous-private rw=write ro=readback rw-restored=write raw-unaligned-mprotect=EINVAL unmap=exact child-contained");
    return 0;
}

/* Native Linux/x86-64 selected-static C mapping-synchronization fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * with a dependency-free static crabc-libc archive. Raw Linux mapping setup
 * and teardown keep the candidate surface limited to `msync` alone. The
 * selected candidate deliberately has no musl syscall_cp/pthread-cancellation
 * machinery; its private anonymous mapping proves only direct no-cancellation
 * Linux flag/error plumbing, not file-backed shared-map writeback,
 * invalidation effects, persistence, or durability. It does not select
 * mremap, mlock*, shared memory, mapping policy, allocator, CRT, loader,
 * sysroot, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>

enum { CRABC_MEMORY_SYNC_PAGE_SIZE = 4096 };

#define CRABC_MSYNC_TYPE int (*)(void *, size_t, int)

_Static_assert(SYS_mmap == 9 && SYS_munmap == 11,
    "x86 raw mapping syscalls");
_Static_assert(SYS_msync == 26, "x86 msync syscall");
_Static_assert(MS_ASYNC == 1 && MS_INVALIDATE == 2 && MS_SYNC == 4,
    "x86 msync modes");
_Static_assert(__builtin_types_compatible_p(__typeof__(&msync),
    CRABC_MSYNC_TYPE), "msync declaration");

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

static int expect_success(void *mapping, int flags, int stale_errno,
    int failure)
{
    errno = stale_errno;
    if (msync(mapping, CRABC_MEMORY_SYNC_PAGE_SIZE, flags) != 0 ||
        errno != stale_errno)
        return failure;
    return 0;
}

static int expect_einval(void *mapping, size_t length, int flags, int failure)
{
    errno = 0;
    if (msync(mapping, length, flags) != -1 ||
        errno != EINVAL)
        return failure;
    return 0;
}

int crabc_x86_64_memory_sync_probe(void)
{
    const int accepted[] = {
        0,
        MS_ASYNC,
        MS_INVALIDATE,
        MS_ASYNC | MS_INVALIDATE,
        MS_SYNC,
        MS_SYNC | MS_INVALIDATE,
    };
    volatile unsigned char *bytes;
    void *mapping;
    long raw_mapping;
    unsigned index;
    int result = 0;

    raw_mapping = raw6(SYS_mmap, 0, CRABC_MEMORY_SYNC_PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (raw_mapping < 0 && raw_mapping >= -4095)
        return 10;
    mapping = (void *)raw_mapping;
    bytes = mapping;
    bytes[0] = 0x5a;

    errno = EDOM;
    if (msync(mapping, 0, 0) != 0 || errno != EDOM) {
        result = 11;
        goto cleanup;
    }

    for (index = 0; index < sizeof(accepted) / sizeof(accepted[0]); index++) {
        result = expect_success(mapping, accepted[index], ERANGE,
            12 + (int)index);
        if (result != 0)
            goto cleanup;
    }

    /* Linux 5.10 rejects invalid modes before its zero-length no-op. */
    result = expect_einval(mapping, 0, MS_ASYNC | MS_SYNC, 18);
    if (result != 0)
        goto cleanup;
    result = expect_einval(mapping, CRABC_MEMORY_SYNC_PAGE_SIZE,
        MS_ASYNC | MS_SYNC | MS_INVALIDATE, 19);
    if (result != 0)
        goto cleanup;

    /* Alignment is likewise checked before the zero-length no-op. */
    result = expect_einval((void *)(bytes + 1), 0, 0, 20);
    if (result != 0)
        goto cleanup;
    result = expect_einval((void *)(bytes + 1), CRABC_MEMORY_SYNC_PAGE_SIZE,
        0, 21);
    if (result != 0)
        goto cleanup;
    if (bytes[0] != 0x5a)
        result = 22;

cleanup:
    if (raw2(SYS_munmap, (long)mapping, CRABC_MEMORY_SYNC_PAGE_SIZE) < 0 &&
        result == 0)
        result = 23;
    return result;
}

#ifndef CRABC_MEMORY_SYNC_FREESTANDING
int main(void)
{
    return crabc_x86_64_memory_sync_probe();
}
#endif

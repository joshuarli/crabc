/*
 * Pinned-musl/raw Linux/x86-64 mapping ownership and private/shared behavior reference.
 *
 * This fixture is C-oracle evidence only.  Its raw arm invokes the
 * Linux syscall numbers directly; its adjacent musl arm invokes the standard
 * C wrappers.  The unaligned-address error is deliberately a raw syscall
 * assertion: musl's mprotect wrapper rounds its input range before invoking
 * the kernel. Neither arm selects a C API for crabc nor expands the bounded
 * Rust mapping contract. File mappings additionally exercise descriptor-close
 * lifetime, COW discard, and shared visibility without external truncation.
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

static void *map_range(enum mapping_arm arm, void *hint, size_t length,
                       int flags, int fd)
{
    if (arm == RAW_SYSCALL_ARM)
        return (void *)syscall(SYS_mmap, hint, length, PROT_READ | PROT_WRITE,
                              flags, fd, 0);
    return mmap(hint, length, PROT_READ | PROT_WRITE, flags, fd, 0);
}

static void *remap_range(enum mapping_arm arm, void *source, size_t old_length,
                         size_t new_length, int flags, void *destination)
{
    if (arm == RAW_SYSCALL_ARM)
        return (void *)syscall(SYS_mremap, source, old_length, new_length,
                              flags, destination);
    return mremap(source, old_length, new_length, flags, destination);
}

static int discard_range(enum mapping_arm arm, void *mapping, size_t length)
{
    if (arm == RAW_SYSCALL_ARM)
        return (int)syscall(SYS_madvise, mapping, length, MADV_DONTNEED);
    return madvise(mapping, length, MADV_DONTNEED);
}

static int run_mapping_boundaries(enum mapping_arm arm)
{
    const size_t page = PAGE_SIZE_REFERENCE;
    int fd = memfd_create("mapping-reference", 0);
    unsigned char *private, *shared, *observer, *source, *destination, *next;
    unsigned char backing[2];
    size_t index;

    if (fd < 0 || ftruncate(fd, page) || pwrite(fd, "backing", 7, 0) != 7)
        return 20;
    private = map_range(arm, NULL, page, MAP_PRIVATE, fd);
    shared = map_range(arm, NULL, page, MAP_SHARED, fd);
    observer = map_range(arm, NULL, page, MAP_SHARED, fd);
    if (private == MAP_FAILED || shared == MAP_FAILED || observer == MAP_FAILED)
        return 21;
    private[0] = 'P';
    shared[1] = 'S';
    if (shared[0] != 'b' || observer[1] != 'S' || private[1] != 'a' ||
        pread(fd, backing, 2, 0) != 2 || backing[0] != 'b' || backing[1] != 'S')
        return 22;
    if (close(fd) || discard_range(arm, private, page))
        return 23;
    if (private[0] != 'b' || private[1] != 'S')
        return 24;
    shared[2] = 'C';
    if (observer[2] != 'C' || unmap_page(arm, private) ||
        unmap_page(arm, shared) || unmap_page(arm, observer))
        return 25;

    source = map_range(arm, NULL, 3 * page, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    destination = map_private_page(arm);
    if (source == MAP_FAILED || destination == MAP_FAILED)
        return 26;
    for (index = 0; index < 3 * page; ++index)
        source[index] = index % 251;
    destination[0] = 0x72;
    errno = 0;
    next = remap_range(arm, source, 3 * page, page, MREMAP_FIXED, destination);
    if (next != MAP_FAILED || errno != EINVAL || source[1] != 1 || destination[0] != 0x72)
        return 27;
    if (unmap_page(arm, destination))
        return 28;
    next = remap_range(arm, source, 3 * page, 5 * page, MREMAP_MAYMOVE, NULL);
    if (next == MAP_FAILED)
        return 29;
    source = next;
    for (index = 0; index < 5 * page; ++index)
        if (source[index] != (index < 3 * page ? index % 251 : 0))
            return 30;
    next = remap_range(arm, source, 5 * page, 2 * page, 0, NULL);
    if (next == MAP_FAILED)
        return 31;
    source = next;
    for (index = 0; index < 2 * page; ++index)
        if (source[index] != index % 251)
            return 32;
    destination = map_range(arm, NULL, 2 * page, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    if (destination == MAP_FAILED)
        return 37;
    next = remap_range(arm, source, 2 * page, 2 * page,
                       MREMAP_MAYMOVE | MREMAP_FIXED, destination);
    if (next == MAP_FAILED || next != destination)
        return 38;
    /* Both inputs are consumed; only the returned mapping is used below. */
    source = next;
    for (index = 0; index < 2 * page; ++index)
        if (source[index] != index % 251)
            return 39;
    if (discard_range(arm, source + page, 1))
        return 33;
    for (index = 0; index < 2 * page; ++index)
        if (source[index] != (index < page ? index % 251 : 0))
            return 34;
    destination = map_range(arm, source, page, MAP_PRIVATE | MAP_ANONYMOUS, -1);
    if (destination == MAP_FAILED || destination == source || source[1] != 1)
        return 35;
    if (unmap_page(arm, destination) || munmap(source, 2 * page))
        return 36;
    return 0;
}

static int run_in_child(enum mapping_arm arm)
{
    int status;
    pid_t child = fork();

    if (child < 0)
        return -1;
    if (child == 0) {
        int result = run_mapping_lifecycle(arm);
        _exit(result ? result : run_mapping_boundaries(arm));
    }

    while (waitpid(child, &status, 0) == -1) {
        if (errno != EINTR)
            return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

int main(void)
{
    int raw_result = run_in_child(RAW_SYSCALL_ARM);
    int musl_result = run_in_child(MUSL_WRAPPER_ARM);
    if (raw_result != 0 || musl_result != 0) {
        fprintf(stderr, "mapping reference failed: raw=%d musl=%d\n",
                raw_result, musl_result);
        return 1;
    }

    puts("mmap=9 mprotect=10 munmap=11 raw+musl=anonymous-private rw=write ro=readback rw-restored=write raw-unaligned-mprotect=EINVAL unmap=exact child-contained");
    return 0;
}

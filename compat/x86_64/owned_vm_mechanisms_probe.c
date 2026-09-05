#define _GNU_SOURCE

#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE_SIZE 4096u

_Static_assert(PTRDIFF_MAX == INT64_MAX, "x86-64 ptrdiff maximum");
_Static_assert(SYS_brk == 12, "x86-64 brk syscall number");
_Static_assert(SYS_mremap == 25, "x86-64 mremap syscall number");
_Static_assert(SYS_remap_file_pages == 216, "x86-64 remap_file_pages syscall number");

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "owned-vm-mechanisms:%d errno=%d\n", __LINE__, errno); \
        return -1; \
    } \
} while (0)

static long raw5(long number, long first, long second, long third, long fourth, long fifth)
{
    register long r10 __asm__("r10") = fourth;
    register long r8 __asm__("r8") = fifth;
    long result;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(first), "S"(second), "d"(third), "r"(r10), "r"(r8)
        : "rcx", "r11", "cc", "memory"
    );
    return result;
}

static int expect_write_fault(const volatile unsigned char *address)
{
    pid_t child = fork();
    int status;

    CHECK(child >= 0);
    if (child == 0) {
        *(volatile unsigned char *)address = 0x5a;
        _exit(90);
    }
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
    return 0;
}

static int resize_preserves_content_protection_and_error_boundary(void)
{
    volatile unsigned char *mapping = mmap(
        NULL,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    volatile unsigned char *resized;

    CHECK(mapping != MAP_FAILED);
    mapping[0] = 0x31;
    mapping[PAGE_SIZE - 1] = 0x7c;
    CHECK(mprotect((void *)mapping, PAGE_SIZE, PROT_READ) == 0);

    errno = E2BIG;
    resized = mremap((void *)mapping, PAGE_SIZE, PAGE_SIZE * 2, MREMAP_MAYMOVE);
    CHECK(resized != MAP_FAILED && errno == E2BIG);
    CHECK(resized[0] == 0x31 && resized[PAGE_SIZE - 1] == 0x7c);
    CHECK(expect_write_fault(resized) == 0);
    CHECK(mprotect((void *)resized, PAGE_SIZE * 2, PROT_READ | PROT_WRITE) == 0);
    resized[PAGE_SIZE] = 0x56;
    CHECK(resized[PAGE_SIZE] == 0x56);

    errno = 0;
    CHECK(
        mremap((void *)resized, PAGE_SIZE * 2, (size_t)PTRDIFF_MAX, MREMAP_MAYMOVE)
            == MAP_FAILED
            && errno == ENOMEM
    );
    CHECK(resized[0] == 0x31 && resized[PAGE_SIZE] == 0x56);
    CHECK(munmap((void *)resized, PAGE_SIZE * 2) == 0);
    return 0;
}

static int fixed_move_retires_old_mapping_and_replaces_destination(void)
{
    volatile unsigned char *source = mmap(
        NULL,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    void *destination = mmap(
        NULL,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    volatile unsigned char *moved;
    unsigned char residency = 0;

    CHECK(source != MAP_FAILED && destination != MAP_FAILED && (void *)source != destination);
    source[0] = 0x21;
    source[PAGE_SIZE - 1] = 0x6d;
    memset(destination, 0xa5, PAGE_SIZE);

    errno = E2BIG;
    moved = mremap(
        (void *)source,
        PAGE_SIZE,
        PAGE_SIZE,
        MREMAP_MAYMOVE | MREMAP_FIXED,
        destination
    );
    CHECK((void *)moved == destination && errno == E2BIG);
    CHECK(moved[0] == 0x21 && moved[PAGE_SIZE - 1] == 0x6d);
    errno = 0;
    CHECK(mincore((void *)source, PAGE_SIZE, &residency) == -1 && errno == ENOMEM);
    moved[1] = 0x39;
    CHECK(moved[1] == 0x39);
    CHECK(munmap((void *)moved, PAGE_SIZE) == 0);
    return 0;
}

static int zero_size_shared_remap_is_an_alias(void)
{
    volatile unsigned char *source = mmap(
        NULL,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS,
        -1,
        0
    );
    volatile unsigned char *alias;

    CHECK(source != MAP_FAILED);
    source[0] = 0x42;
    errno = E2BIG;
    alias = mremap((void *)source, 0, PAGE_SIZE, MREMAP_MAYMOVE);
    CHECK(alias != MAP_FAILED && (void *)alias != (void *)source && errno == E2BIG);
    CHECK(alias[0] == 0x42);
    alias[1] = 0x73;
    CHECK(source[1] == 0x73);
    source[2] = 0x18;
    CHECK(alias[2] == 0x18);
    CHECK(munmap((void *)alias, PAGE_SIZE) == 0);
    CHECK(munmap((void *)source, PAGE_SIZE) == 0);
    return 0;
}

static int musl_brk_limit(void)
{
    void *current = sbrk(0);

    CHECK(current != (void *)-1);
    errno = E2BIG;
    CHECK(sbrk(0) == current && errno == E2BIG);
    errno = 0;
    CHECK(sbrk(1) == (void *)-1 && errno == ENOMEM);
    errno = 0;
    CHECK(brk(current) == -1 && errno == ENOMEM);
    return 0;
}

static int remap_file_pages_has_raw_linux_error_translation(void)
{
    volatile unsigned char *mapping = mmap(
        NULL,
        PAGE_SIZE,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    long raw;

    CHECK(mapping != MAP_FAILED);
    mapping[0] = 0x4e;
    errno = E2BIG;
    raw = raw5(SYS_remap_file_pages, (long)mapping, PAGE_SIZE, 0, 0, 0);
    CHECK(raw < 0 && raw >= -4095 && errno == E2BIG);
    errno = ERANGE;
    CHECK(remap_file_pages((void *)mapping, PAGE_SIZE, 0, 0, 0) == -1 && errno == -raw);
    CHECK(mapping[0] == 0x4e);
    CHECK(munmap((void *)mapping, PAGE_SIZE) == 0);
    return 0;
}

int main(void)
{
    alarm(20);
    CHECK(resize_preserves_content_protection_and_error_boundary() == 0);
    CHECK(fixed_move_retires_old_mapping_and_replaces_destination() == 0);
    CHECK(zero_size_shared_remap_is_an_alias() == 0);
    CHECK(musl_brk_limit() == 0);
    CHECK(remap_file_pages_has_raw_linux_error_translation() == 0);
    puts("owned-vm-mechanisms-ok");
    return 0;
}

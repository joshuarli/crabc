/* Pinned-musl Linux/x86-64 mincore ABI and behavior reference. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this probe requires native Linux/x86-64 LP64"
#endif

#define _GNU_SOURCE 1

#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

_Static_assert(SYS_mincore == 27, "x86 mincore syscall number");

int main(void)
{
    long page_size = sysconf(_SC_PAGESIZE);
    size_t page;
    size_t mapping_length;
    void *mapping;
    volatile unsigned char *bytes;
    unsigned char residency[3] = {0xa5, 0xa5, 0xa5};
    unsigned char partial[3] = {0xa5, 0xa5, 0xa5};

    if (page_size != 4096)
        return 1;
    page = (size_t)page_size;
    mapping_length = page * 2;
    mapping = mmap(NULL, mapping_length, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED)
        return 2;
    bytes = (volatile unsigned char *)mapping;

    /* Start from dropped anonymous pages, then fault only the first page. */
    if (madvise(mapping, mapping_length, MADV_DONTNEED) != 0)
        return 3;
    bytes[0] = 0x5a;
    if (mincore(mapping, mapping_length, residency) != 0)
        return 4;
    if ((residency[0] & 1) == 0 || residency[2] != 0xa5)
        return 5;

    /* A one-byte tail in page two still requires a second output byte. */
    bytes[page] = 0x7b;
    if (mincore(mapping, page + 1, partial) != 0)
        return 6;
    if ((partial[0] & 1) == 0 || (partial[1] & 1) == 0 ||
        partial[2] != 0xa5)
        return 7;

    if (munmap(mapping, mapping_length) != 0)
        return 8;
    puts("syscall=27 page=4096 full=one-byte-per-page partial=ceil tail=preserved");
    return 0;
}

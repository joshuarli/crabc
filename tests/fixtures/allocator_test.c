#define _GNU_SOURCE 1

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *name)
{
    puts(name);
    return 1;
}

int main(void)
{
    unsigned char *small;
    unsigned char *grown;
    unsigned char *shrunk;
    void *zero_a = malloc(0);
    void *zero_b = malloc(0);
    void *aligned = (void *)1;
    void *page_aligned;
    const size_t natural_alignment_sizes[] = {1, 15, 16, 17, 4096, 262144};
    size_t i;

    if (zero_a == NULL || zero_b == NULL || zero_a == zero_b)
        return fail("malloc-zero");
    if ((unsigned long)zero_a % 16 != 0 || (unsigned long)zero_b % 16 != 0)
        return fail("malloc-alignment");
    free(zero_a);
    free(zero_b);

    for (i = 0; i < sizeof(natural_alignment_sizes) / sizeof(natural_alignment_sizes[0]); ++i) {
        void *p = malloc(natural_alignment_sizes[i]);
        if (p == NULL || (unsigned long)p % 16 != 0)
            return fail("malloc-natural-alignment");
        free(p);
    }

    small = malloc(4);
    if (small == NULL)
        return fail("malloc");
    small[0] = 1;
    small[1] = 2;
    small[2] = 3;
    small[3] = 4;
    grown = realloc(small, 8192);
    if (grown == NULL || memcmp(grown, "\1\2\3\4", 4) != 0)
        return fail("realloc-grow");
    shrunk = realloc(grown, 2);
    if (shrunk == NULL || shrunk[0] != 1 || shrunk[1] != 2)
        return fail("realloc-shrink");
    errno = 0;
    if (realloc(shrunk, (size_t)-1) != NULL || errno != ENOMEM || shrunk[0] != 1)
        return fail("realloc-overflow");
    free(shrunk);

    small = reallocarray(NULL, 4, sizeof *small);
    if (small == NULL)
        return fail("reallocarray");
    small[0] = 1;
    small[3] = 4;
    errno = 0;
    grown = reallocarray(small, (size_t)-1, 2);
    if (grown != NULL || errno != ENOMEM || small[0] != 1 || small[3] != 4)
        return fail("reallocarray-overflow");
    free(small);

    aligned = memalign(64, 19);
    if (aligned == NULL || (unsigned long)aligned % 64 != 0)
        return fail("memalign");
    free(aligned);
    errno = 0;
    if (memalign(24, 19) != NULL || errno != EINVAL)
        return fail("memalign-invalid");
    page_aligned = valloc(7);
    if (page_aligned == NULL || (unsigned long)page_aligned % 4096 != 0)
        return fail("valloc");
    free(page_aligned);

    small = malloc(4);
    if (small == NULL)
        return fail("realloc-zero-setup");
    grown = realloc(small, 0);
    if (grown == NULL)
        return fail("realloc-zero");
    free(grown);

    grown = calloc(17, sizeof(unsigned long));
    if (grown == NULL)
        return fail("calloc");
    for (i = 0; i < 17 * sizeof(unsigned long); ++i) {
        if (grown[i] != 0)
            return fail("calloc-zero");
    }
    errno = EAGAIN;
    free(grown);
    if (errno != EAGAIN)
        return fail("free-errno");

    errno = 0;
    if (calloc((size_t)-1, 2) != NULL || errno != ENOMEM)
        return fail("calloc-overflow");

    errno = 0;
    aligned = aligned_alloc(64, 65);
    if (aligned == NULL || (unsigned long)aligned % 64 != 0)
        return fail("aligned-alloc");
    free(aligned);
    errno = 0;
    if (aligned_alloc(3, 64) != NULL || errno != EINVAL)
        return fail("aligned-alloc-invalid");

    aligned = (void *)1;
    if (posix_memalign(&aligned, 24, 64) != EINVAL || aligned != (void *)1)
        return fail("posix-memalign-invalid");
    if (posix_memalign(&aligned, 64, 1) != 0 || (unsigned long)aligned % 64 != 0)
        return fail("posix-memalign");
    free(aligned);

    for (i = 1; i <= 256; ++i) {
        void *p = malloc(i);
        if (p == NULL)
            return fail("allocation-stress");
        memset(p, (int)i, i);
        free(p);
    }

    puts("allocator ok");
    return 0;
}

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
    size_t i;

    if (zero_a == NULL || zero_b == NULL || zero_a == zero_b)
        return fail("malloc-zero");
    if ((unsigned long)zero_a % 16 != 0 || (unsigned long)zero_b % 16 != 0)
        return fail("malloc-alignment");
    free(zero_a);
    free(zero_b);

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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *name)
{
    fputs(name, stderr);
    fputc('\n', stderr);
    return 1;
}

int main(void)
{
    unsigned char *grown;
    unsigned char *shrunk;
    void *aligned;

    grown = malloc(4);
    if (!grown)
        return fail("malloc");
    memcpy(grown, "abc", 4);
    grown = realloc(grown, 8192);
    if (!grown || strcmp((char *)grown, "abc") != 0)
        return fail("realloc-grow");
    shrunk = realloc(grown, 2);
    if (!shrunk || shrunk[0] != 'a' || shrunk[1] != 'b')
        return fail("realloc-shrink");
    free(shrunk);

    errno = 0;
    if (calloc((size_t)-1, 2) != NULL || errno != ENOMEM)
        return fail("calloc-overflow");
    errno = 0;
    aligned = aligned_alloc(64, 65);
    if (!aligned || (unsigned long)aligned % 64 != 0)
        return fail("aligned-alloc");
    free(aligned);
    errno = 0;
    if (aligned_alloc(3, 64) != NULL || errno != EINVAL)
        return fail("aligned-alloc-invalid");

    errno = 0;
    printf("allocator: errno=%d ok\n", errno);
    return 0;
}

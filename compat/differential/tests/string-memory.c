#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int fail(const char *name)
{
    fputs(name, stderr);
    fputc('\n', stderr);
    return 1;
}

int main(void)
{
    char overlap[] = "0123456789";
    char padded[5] = { 9, 9, 9, 9, 9 };
    char joined[8] = "abc";
    char copied[4] = { 7, 7, 7, 7 };
    char cat[6] = "ab";
    const char haystack[] = "ababa";
    const unsigned char bytes[] = { 1, 2, 3, 2, 1 };

    if (memmove(overlap + 2, overlap, 8) != overlap + 2 ||
        memcmp(overlap, "0101234567", sizeof(overlap)) != 0)
        return fail("memmove-backward");
    if (memmove(overlap, overlap + 2, 8) != overlap ||
        memcmp(overlap, "0123456767", sizeof(overlap)) != 0)
        return fail("memmove-forward");
    if (memchr(bytes, 2, 1) != NULL || memrchr(bytes, 2, sizeof(bytes)) != bytes + 3)
        return fail("memchr-bounds");
    if (memcmp("a", "b", 1) >= 0 || memcmp("b", "a", 1) <= 0)
        return fail("memcmp-order");

    if (strncpy(padded, "xy", sizeof(padded)) != padded ||
        memcmp(padded, "xy\0\0\0", sizeof(padded)) != 0)
        return fail("strncpy-padding");
    if (strncat(joined, "def", 0) != joined || strcmp(joined, "abc") != 0)
        return fail("strncat-zero");
    if (strlcpy(copied, "abcdef", sizeof(copied)) != 6 ||
        memcmp(copied, "abc\0", sizeof(copied)) != 0)
        return fail("strlcpy-truncate");
    if (strlcpy(NULL, "abcdef", 0) != 6)
        return fail("strlcpy-zero");
    if (strlcat(cat, "cdef", sizeof(cat)) != 6 || strcmp(cat, "abcde") != 0)
        return fail("strlcat-truncate");
    if (strstr(haystack, "aba") != haystack || strstr(haystack, "bab") != haystack + 1)
        return fail("strstr-overlap");

    errno = 0;
    printf("string-memory: errno=%d ok\n", errno);
    return 0;
}

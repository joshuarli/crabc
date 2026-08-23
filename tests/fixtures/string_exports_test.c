#define _GNU_SOURCE 1

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>

extern void explicit_bzero(void *, size_t);
extern void *mempcpy(void *, const void *, size_t);
extern char *strcasestr(const char *, const char *);
extern char *strsep(char **, const char *);
extern void *reallocarray(void *, size_t, size_t);

int main(void) {
    char overlap[8] = "abcdef";
    bcopy(overlap, overlap + 1, 5);
    if (memcmp(overlap, "aabcde", 6)) return 1;
    bzero(overlap, sizeof overlap);
    for (size_t i = 0; i < sizeof overlap; i++) if (overlap[i]) return 2;
    strcpy(overlap, "secret");
    explicit_bzero(overlap, sizeof overlap);
    for (size_t i = 0; i < sizeof overlap; i++) if (overlap[i]) return 3;

    if (index("abc", 'b') != (char *)"abc" + 1) return 4;
    if (rindex("abca", 'a') != (char *)"abca" + 3) return 5;
    {
        char dst[8] = {0};
        if (memccpy(dst, "abcz", 'c', 4) != dst + 3 || memcmp(dst, "abc", 3)) return 6;
        if (memccpy(dst, "ab", 'z', 2) != NULL) return 7;
        if (mempcpy(dst, "xy", 2) != dst + 2 || memcmp(dst, "xy", 2)) return 8;
    }
    {
        char dst[8];
        if (stpcpy(dst, "abc") != dst + 3 || strcmp(dst, "abc")) return 9;
        memset(dst, 'x', sizeof dst);
        if (stpncpy(dst, "ab", 5) != dst + 2 || memcmp(dst, "ab\0\0\0", 5)) return 10;
        if (stpncpy(dst, "abcdef", 3) != dst + 3 || memcmp(dst, "abc", 3)) return 11;
    }
    if (strcasestr("AlphaBeta", "hAb") != (char *)"AlphaBeta" + 3) return 12;
    if (strcasestr("Alpha", "z") != NULL) return 13;
    {
        char *copy = strndup("abcdef", 3);
        if (!copy || strcmp(copy, "abc")) return 14;
        free(copy);
    }
    {
        char values[] = ":a::b";
        char *p = values;
        if (strcmp(strsep(&p, ":"), "")) return 15;
        if (strcmp(strsep(&p, ":"), "a")) return 16;
        if (strcmp(strsep(&p, ":"), "")) return 17;
        if (strcmp(strsep(&p, ":"), "b") || strsep(&p, ":") != NULL) return 18;
    }
    {
        char values[] = ":one::two";
        char *save;
        if (strcmp(strtok_r(values, ":", &save), "one")) return 19;
        if (strcmp(strtok_r(NULL, ":", &save), "two")) return 20;
        if (strtok_r(NULL, ":", &save) != NULL) return 21;
    }
    {
        int *values = reallocarray(NULL, 4, sizeof *values);
        if (!values) return 22;
        values[3] = 42;
        if ((void *)reallocarray(values, (size_t)-1, 2) != NULL) return 23;
        if (values[3] != 42) return 24;
        free(values);
    }
    puts("c-abi string exports ok");
    return 0;
}

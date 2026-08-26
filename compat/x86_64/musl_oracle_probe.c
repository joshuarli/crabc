/*
 * Runtime half of the pinned x86 musl-oracle boundary. The shell gate passes
 * the canonical installed libc path as CRABC_MUSL_ORACLE_LIBC_PATH, then
 * checks that this dynamic executable actually maps that exact object. An ELF
 * interpreter path alone would not exclude a later Alpine-library lookup.
 */
#include <stdio.h>
#include <string.h>

#ifndef CRABC_MUSL_ORACLE_LIBC_PATH
#error "the oracle probe requires its canonical pinned libc path"
#endif

int main(void)
{
    char line[4096];
    int saw_pinned_libc = 0;
    int saw_glibc = 0;
    FILE *maps = fopen("/proc/self/maps", "r");

    if (maps == NULL)
        return 10;

    while (fgets(line, sizeof(line), maps) != NULL) {
        if (strstr(line, CRABC_MUSL_ORACLE_LIBC_PATH) != NULL)
            saw_pinned_libc = 1;
        if (strstr(line, "ld-linux") != NULL || strstr(line, "libc.so.6") != NULL)
            saw_glibc = 1;
    }

    if (fclose(maps) != 0)
        return 11;
    if (!saw_pinned_libc || saw_glibc)
        return 12;

    printf("pinned musl x86_64 runtime: %s\n", CRABC_MUSL_ORACLE_LIBC_PATH);
    return 0;
}

/*
 * The first differential workload intentionally stays within the foundational
 * libc surface: string/memory functions, stdio, and one deterministic errno
 * transition. It emits no process IDs, addresses, timestamps, or paths, so the
 * runner can compare the raw streams without semantic normalization.
 */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char text[16];
    char *end;
    long value;
    int parse_errno;

    memcpy(text, "crabc", 6);
    if (strlen(text) != 5 || strcmp(text, "crabc") != 0) {
        return 10;
    }
    if (memcmp(text, "crabc", 5) != 0) {
        return 11;
    }

    errno = 0;
    value = strtol("999999999999999999999999", &end, 10);
    parse_errno = errno;
    if (value != LONG_MAX || *end != '\0' || parse_errno != ERANGE) {
        return 12;
    }

    printf("foundational: errno=%d len=%d value-ok\n", parse_errno,
           (int)strlen(text));
    if (write(STDERR_FILENO, "foundational: stderr\n",
              sizeof("foundational: stderr\n") - 1) < 0) {
        return 13;
    }
    return 0;
}

/* Static x86-64 permanent-standard-stream __fseterr(stdin) fixture.
 *
 * This project-header source executes first through pinned musl 1.2.6 and
 * then through one true -nostdlib/-static crabc archive. It calls only the
 * fixed process-lifetime stdin record, observing the selected F_ERR marker
 * through existing ferror and clearerr entries. It performs no stream I/O,
 * locking, configuration, or descriptor operation.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio_ext.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

typedef void (*fseterr_fn)(FILE *);

static fseterr_fn volatile fseterr_entry = __fseterr;

int crabc_x86_64_stdio_permanent_fseterr_stdin_probe(void)
{
    if (stdin == NULL)
        return 1;
    if (ferror(stdin) != 0)
        return 2;
    __fseterr(stdin);
    if (ferror(stdin) == 0)
        return 3;
    clearerr(stdin);
    if (ferror(stdin) != 0)
        return 4;
    fseterr_entry(stdin);
    if (ferror(stdin) == 0)
        return 5;
    clearerr(stdin);
    if (ferror(stdin) != 0)
        return 6;
    return 0;
}

#ifndef CRABC_STDIO_PERMANENT_FSETERR_STDIN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_fseterr_stdin_probe();
}
#endif

/* Static x86-64 permanent-standard-stream __fsetlocking(stdin) fixture.
 *
 * This project-header source executes first through pinned musl 1.2.6 and
 * then through one true -nostdlib/-static crabc archive. It makes only direct
 * and function-pointer calls on the fixed process-lifetime stdin record with
 * each named request value. The selected musl implementation is a no-op: this
 * test neither reads, writes, configures, nor locks a stream.
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

typedef int (*fsetlocking_fn)(FILE *, int);

static fsetlocking_fn volatile fsetlocking_entry = __fsetlocking;

int crabc_x86_64_stdio_permanent_fsetlocking_stdin_probe(void)
{
    if (stdin == NULL)
        return 1;
    if (__fsetlocking(stdin, FSETLOCKING_QUERY) != 0)
        return 2;
    if (fsetlocking_entry(stdin, FSETLOCKING_INTERNAL) != 0)
        return 3;
    if (__fsetlocking(stdin, FSETLOCKING_BYCALLER) != 0)
        return 4;
    if (fsetlocking_entry(stdin, FSETLOCKING_QUERY) != 0)
        return 5;
    return 0;
}

#ifndef CRABC_STDIO_PERMANENT_FSETLOCKING_STDIN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_fsetlocking_stdin_probe();
}
#endif

/* Static x86-64 permanent-standard-stream __freading(stdin) fixture.
 *
 * This project-header source executes first through pinned musl 1.2.6 and
 * then through one true -nostdlib/-static crabc archive. It makes only direct
 * and function-pointer observations of the fixed process-lifetime stdin
 * record. The test neither reads nor configures stdin and does not create
 * another FILE object.
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

typedef int (*freading_fn)(FILE *);

static freading_fn volatile freading_entry = __freading;

int crabc_x86_64_stdio_permanent_freading_stdin_probe(void)
{
    if (stdin == NULL)
        return 1;
    if (freading_entry(stdin) != 1)
        return 2;
    if (__freading(stdin) != 1)
        return 3;
    if (freading_entry(stdin) != 1)
        return 4;
    return 0;
}

#ifndef CRABC_STDIO_PERMANENT_FREADING_STDIN_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_freading_stdin_probe();
}
#endif

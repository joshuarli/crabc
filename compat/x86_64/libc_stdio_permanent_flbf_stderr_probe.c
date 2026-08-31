/* Static x86-64 permanent-standard-stream __flbf(stderr) fixture.
 *
 * This project-header source executes first through pinned musl 1.2.6 and
 * then through one true -nostdlib/-static crabc archive. It makes only direct
 * and function-pointer observations of the fixed process-lifetime stderr
 * record. The test neither writes nor configures stderr and does not create
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

typedef int (*flbf_fn)(FILE *);

static flbf_fn volatile flbf_entry = __flbf;

int crabc_x86_64_stdio_permanent_flbf_stderr_probe(void)
{
    if (stderr == NULL)
        return 1;
    if (flbf_entry(stderr) != 0)
        return 2;
    if (__flbf(stderr) != 0)
        return 3;
    if (flbf_entry(stderr) != 0)
        return 4;
    return 0;
}

#ifndef CRABC_STDIO_PERMANENT_FLBF_STDERR_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_flbf_stderr_probe();
}
#endif

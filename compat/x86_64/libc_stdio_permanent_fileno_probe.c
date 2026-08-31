/* Static x86-64 permanent-standard-stream fileno regression fixture.
 *
 * The same project-header source first executes through pinned musl 1.2.6,
 * then through one true -nostdlib/-static crabc archive. It calls `fileno`
 * only on the process-lifetime stdin/stdout/stderr pointers and observes their
 * fixed descriptor-number adapters (0/1/2). It creates no FILE object and
 * performs no stream I/O, descriptor mutation, or pathname operation.
 *
 * Musl's FLOCK/FUNLOCK and its behavior for arbitrary FILE objects remain
 * outside this externally serialized permanent-stream leaf.
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

typedef int (*fileno_fn)(FILE *);

static fileno_fn volatile fileno_entry = fileno;

int crabc_x86_64_stdio_permanent_fileno_probe(void)
{
    if (fileno_entry(stdin) != 0)
        return 1;
    if (fileno_entry(stdout) != 1)
        return 2;
    if (fileno_entry(stderr) != 2)
        return 3;
    return 0;
}

#ifndef CRABC_STDIO_PERMANENT_FILENO_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_fileno_probe();
}
#endif

/* Static x86-64 permanent-standard-stream fileno_unlocked regression fixture.
 *
 * This project-header source first executes through pinned musl 1.2.6 and
 * then through one true -nostdlib/-static crabc archive. It calls only the
 * GNU/BSD `fileno_unlocked` alias and its strong `fileno` target on permanent
 * stdin/stdout/stderr. Equal function-pointer addresses plus fixed 0/1/2
 * results prove the selected weak-alias shape without creating a FILE object,
 * stream I/O, descriptor mutation, or pathname operation.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <stdio.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

typedef int (*fileno_fn)(FILE *);

static fileno_fn volatile fileno_entry = fileno;
static fileno_fn volatile fileno_unlocked_entry = fileno_unlocked;

int crabc_x86_64_stdio_permanent_fileno_unlocked_probe(void)
{
    if (fileno_unlocked_entry != fileno_entry)
        return 1;
    if (fileno_entry(stdin) != 0 || fileno_unlocked_entry(stdin) != 0)
        return 2;
    if (fileno_entry(stdout) != 1 || fileno_unlocked_entry(stdout) != 1)
        return 3;
    if (fileno_entry(stderr) != 2 || fileno_unlocked_entry(stderr) != 2)
        return 4;
    return 0;
}

#ifndef CRABC_STDIO_PERMANENT_FILENO_UNLOCKED_FREESTANDING
int main(void)
{
    return crabc_x86_64_stdio_permanent_fileno_unlocked_probe();
}
#endif

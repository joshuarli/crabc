/* Constructor errno preservation around the native owned mimalloc lifecycle.
 *
 * The first allocation occurs in the executable preinit callback, before
 * libc's same-image automatic allocator callback. The user constructor and
 * main make ordinary allocations after that callback. The sentinel is set
 * only after the first allocation so optional allocator filesystem probes
 * cannot turn this into an assertion about their private errno values.
 */

#include <errno.h>
#include <stdlib.h>

enum { startup_errno_sentinel = 79 };

static int preinit_errno = -1;
static int constructor_errno = -1;

static void allocate_or_exit(void)
{
    void *block = malloc(17);

    if (!block)
        _Exit(97);
    free(block);
}

static void startup_preinit(void)
{
    allocate_or_exit();
    errno = startup_errno_sentinel;
    preinit_errno = errno;
}

static void startup_constructor(void)
{
    allocate_or_exit();
    constructor_errno = errno;
}

#if !defined(CRABC_MIMALLOC_STARTUP_ERRNO_ORACLE)
__attribute__((used, section(".preinit_array")))
static void (*const startup_preinit_entry)(void) = startup_preinit;

__attribute__((constructor))
static void startup_constructor_entry(void)
{
    startup_constructor();
}
#endif

int main(void)
{
#if defined(CRABC_MIMALLOC_STARTUP_ERRNO_ORACLE)
    /* Pinned musl's ordinary dynamic entry does not dispatch this fixture's
     * preinit array. Exercise the identical application callbacks explicitly
     * there; the candidate uses its owned CRT/loader ordering above. */
    startup_preinit();
    startup_constructor();
#endif
    allocate_or_exit();
    return preinit_errno == startup_errno_sentinel &&
        constructor_errno == startup_errno_sentinel && errno == startup_errno_sentinel ? 0 : 1;
}

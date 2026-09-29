/* Constructor errno preservation around the native owned mimalloc lifecycle.
 *
 * Static entry first allocates in executable preinit. Dynamic entry skips
 * executable preinit and first allocates in the user constructor. Both
 * entries check errno after the user constructor and in main.
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
#if defined(CRABC_MIMALLOC_STARTUP_ERRNO_DYNAMIC)
    errno = startup_errno_sentinel;
#endif
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
    /* Exercise the matching application callbacks explicitly for the oracle. */
#if !defined(CRABC_MIMALLOC_STARTUP_ERRNO_DYNAMIC)
    startup_preinit();
#endif
    startup_constructor();
#endif
    allocate_or_exit();
    return preinit_errno == (
#if defined(CRABC_MIMALLOC_STARTUP_ERRNO_DYNAMIC)
        -1
#else
        startup_errno_sentinel
#endif
        ) &&
        constructor_errno == startup_errno_sentinel && errno == startup_errno_sentinel ? 0 : 1;
}

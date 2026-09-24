/* Runtime-loaded plugin of the owned dynamic cross-DSO composition witness.
 *
 * It needs the initial IE-TLS dependency, so loading it reuses that already
 * initial object rather than mapping a new one. Its own general-dynamic TLS is
 * new at load time. The plugin frees and resizes blocks another module
 * allocated, allocates blocks others free, sets thread-specific data under a
 * key whose destructor lives in the initial dependency, raises a signal that
 * the dependency handles, and registers an atexit handler that runs while its
 * retained mapping is still live.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern __thread int cross_ie_value;
extern int *cross_ie_address(void);
extern int *cross_errno_address(void);
extern FILE *cross_stdout(void);
extern void *cross_allocate(size_t size, int fill);
extern pthread_key_t cross_key(void);

static _Thread_local int plugin_gd_value = 61;
static _Thread_local unsigned char plugin_gd_zero[41] __attribute__((aligned(256)));

int plugin_views(void)
{
    /* General-dynamic access to the initial IE object must name the same TLS. */
    return &cross_ie_value == cross_ie_address() && &errno == cross_errno_address()
        && stdout == cross_stdout();
}

int plugin_gd_template(void)
{
    for (size_t index = 0; index < sizeof plugin_gd_zero; ++index)
        if (plugin_gd_zero[index]) return 0;
    return plugin_gd_value == 61 && ((uintptr_t)plugin_gd_zero & 255) == 0;
}

void plugin_gd_set(int value) { plugin_gd_value = value; }
int plugin_gd_get(void) { return plugin_gd_value; }

/* Resize and free a block the initial dependency allocated. */
int plugin_consume(void *block, int fill)
{
    unsigned char *bytes = block;
    for (size_t index = 0; index < 48; ++index)
        if (bytes[index] != fill) return 0;
    bytes = realloc(bytes, 4096);
    if (!bytes) return 0;
    for (size_t index = 0; index < 48; ++index)
        if (bytes[index] != fill) return 0;
    free(bytes);
    return 1;
}

void *plugin_aligned(void) { return aligned_alloc(256, 512); }

int plugin_set_specific(void)
{
    unsigned char *block = malloc(64);
    if (!block) return -1;
    memset(block, 0x5c, 64);
    return pthread_setspecific(cross_key(), block);
}

int plugin_raise(int signal) { return raise(signal); }

int plugin_errno_set(int value)
{
    errno = value;
    return errno;
}

static void plugin_at_exit(void) { fputs("plugin atexit\n", stdout); }

int plugin_register_exit(void) { return atexit(plugin_at_exit); }

__attribute__((constructor)) static void construct(void) { fputs("plugin constructor\n", stdout); }
__attribute__((destructor)) static void finalize(void) { fputs("plugin destructor\n", stdout); }

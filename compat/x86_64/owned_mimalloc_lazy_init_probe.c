/*
 * Lazy allocator process-initialization observation.
 *
 * Every mode starts with no allocation performed by the program. The probe
 * reads the audit-only lifecycle phase and init-count instrumentation before
 * its first allocator call, then requires exactly one initialization and a
 * usable result. The race mode additionally observes that the initial thread
 * claims the one-shot at thread creation, before a worker can allocate, and
 * that concurrent worker allocations do not re-run it. The address-space
 * mode reserves every free address first, so the one initialization runs
 * without memory; malloc must fail with ENOMEM and exit must still finalize
 * the allocator cleanly. This observes the installed C backend, not source
 * shape.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

extern int __crabc_x86_owned_allocator_lifecycle_test_phase(void);
extern unsigned long __crabc_x86_owned_allocator_lifecycle_test_init_count(void);

static void fail(int code)
{
    _Exit(code);
}

static void require_uninitialized(void)
{
    if (__crabc_x86_owned_allocator_lifecycle_test_phase() != 0)
        fail(80);
    if (__crabc_x86_owned_allocator_lifecycle_test_init_count() != 0)
        fail(81);
}

static void require_initialized_once(void)
{
    if (__crabc_x86_owned_allocator_lifecycle_test_phase() != 1)
        fail(82);
    if (__crabc_x86_owned_allocator_lifecycle_test_init_count() != 1)
        fail(83);
}

static void probe_malloc(void)
{
    unsigned char *block = malloc(17);

    if (block == NULL)
        fail(90);
    memset(block, 0x5a, 17);
    if (block[0] != 0x5a || block[16] != 0x5a)
        fail(91);
    free(block);
}

static void probe_calloc(void)
{
    unsigned char *block = calloc(3, 7);

    if (block == NULL)
        fail(92);
    for (size_t index = 0; index < 21; ++index) {
        if (block[index] != 0)
            fail(93);
    }
    free(block);
}

static void probe_realloc(void)
{
    unsigned char *block = realloc(NULL, 17);

    if (block == NULL)
        fail(94);
    memset(block, 0x31, 17);
    block = realloc(block, 65);
    if (block == NULL || block[0] != 0x31 || block[16] != 0x31)
        fail(95);
    free(block);
}

static void probe_aligned_alloc(void)
{
    void *block = aligned_alloc(64, 65);

    if (block == NULL || ((uintptr_t)block & 63) != 0)
        fail(96);
    free(block);
}

static void probe_posix_memalign(void)
{
    void *block = NULL;

    if (posix_memalign(&block, 64, 65) != 0 || block == NULL
        || ((uintptr_t)block & 63) != 0)
        fail(97);
    free(block);
}

static void probe_memalign(void)
{
    void *block = memalign(64, 19);

    if (block == NULL || ((uintptr_t)block & 63) != 0)
        fail(98);
    free(block);
}

static void probe_valloc(void)
{
    void *block = valloc(7);

    if (block == NULL || ((uintptr_t)block & 4095) != 0)
        fail(99);
    free(block);
}

static void probe_reallocarray(void)
{
    unsigned char *block = reallocarray(NULL, 4, 8);

    if (block == NULL)
        fail(100);
    block[31] = 0x44;
    if (block[31] != 0x44)
        fail(101);
    free(block);
}

static void probe_strdup(void)
{
    char *copy = strdup("lazy-init");

    if (copy == NULL || strcmp(copy, "lazy-init") != 0)
        fail(102);
    free(copy);
}

static void probe_strndup(void)
{
    char *copy = strndup("lazy-init", 4);

    if (copy == NULL || strcmp(copy, "lazy") != 0)
        fail(103);
    free(copy);
}

static void reserve_all_address_space(void)
{
    for (size_t length = (size_t)1 << 62; length >= 4096;) {
        if (mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED)
            length >>= 1;
    }
}

static void probe_address_space_exhausted(void)
{
    reserve_all_address_space();
    errno = 0;
    if (malloc(1) != NULL)
        fail(109);
    if (errno != ENOMEM)
        fail(110);
    free(NULL);
}

static _Atomic int race_go;

static void *race_worker(void *argument)
{
    (void)argument;
    while (!atomic_load_explicit(&race_go, memory_order_acquire))
        sched_yield();
    unsigned char *block = malloc(29);
    if (block == NULL)
        fail(104);
    block[28] = 0x33;
    if (block[28] != 0x33)
        fail(105);
    free(block);
    return NULL;
}

static void probe_race(void)
{
    pthread_t first;
    pthread_t second;

    if (pthread_create(&first, NULL, race_worker, NULL) != 0)
        fail(106);
    // The initial thread claims the allocator before the first worker can
    // allocate, so the one-shot completes at thread creation.
    require_initialized_once();
    if (pthread_create(&second, NULL, race_worker, NULL) != 0)
        fail(107);
    atomic_store_explicit(&race_go, 1, memory_order_release);
    if (pthread_join(first, NULL) != 0 || pthread_join(second, NULL) != 0)
        fail(108);
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "malloc";

    if (strcmp(mode, "race") == 0) {
        require_uninitialized();
        probe_race();
        require_initialized_once();
        return 0;
    }

    require_uninitialized();
    if (strcmp(mode, "no-allocation") == 0) {
        free(NULL);
        require_uninitialized();
        return 0;
    }
    else if (strcmp(mode, "malloc") == 0)
        probe_malloc();
    else if (strcmp(mode, "calloc") == 0)
        probe_calloc();
    else if (strcmp(mode, "realloc") == 0)
        probe_realloc();
    else if (strcmp(mode, "aligned_alloc") == 0)
        probe_aligned_alloc();
    else if (strcmp(mode, "posix_memalign") == 0)
        probe_posix_memalign();
    else if (strcmp(mode, "memalign") == 0)
        probe_memalign();
    else if (strcmp(mode, "valloc") == 0)
        probe_valloc();
    else if (strcmp(mode, "reallocarray") == 0)
        probe_reallocarray();
    else if (strcmp(mode, "strdup") == 0)
        probe_strdup();
    else if (strcmp(mode, "strndup") == 0)
        probe_strndup();
    else if (strcmp(mode, "address-space-exhausted") == 0)
        probe_address_space_exhausted();
    else
        fail(79);
    require_initialized_once();
    return 0;
}

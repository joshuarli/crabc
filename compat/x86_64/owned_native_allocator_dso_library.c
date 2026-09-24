/*
 * One allocation client image for owned_native_allocator_dso_probe.c.
 *
 * Built once as an initial DSO (DSO_NAME "initial", a DT_NEEDED of the
 * executable) and once as a runtime-loaded plugin (DSO_NAME "plugin"). Each
 * image allocates, reallocates and frees through its own references to the
 * libc malloc family, holds a constructor-time block until its destructor,
 * and can allocate from a thread it creates.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "owned_native_allocator_dso.h"

#define CONCAT2(a, b) a##b
#define CONCAT(a, b) CONCAT2(a, b)

static unsigned char *constructor_block;
static int constructor_runs;

static void say(const char *text) { (void)!write(1, text, strlen(text)); }

__attribute__((constructor)) static void initialize(void) {
    constructor_runs++;
    constructor_block = malloc(4000);
    if (!constructor_block) _exit(90);
    memset(constructor_block, 0x3c, 4000);
}

__attribute__((destructor)) static void finalize(void) {
    for (int i = 0; i < 4000; i++) if (constructor_block[i] != 0x3c) _exit(91);
    free(constructor_block);
    constructor_block = malloc(100);
    free(constructor_block);
    say(DSO_NAME " fini\n");
}

static void *allocate(size_t size, unsigned char byte) {
    unsigned char *block = malloc(size);
    if (block) memset(block, byte, size);
    return block;
}
static void *grow(void *block, size_t size) { return realloc(block, size); }
static void release(void *block) { free(block); }
static void *zeroed(size_t count, size_t size) { return calloc(count, size); }
static void *aligned(size_t alignment, size_t size) { return aligned_alloc(alignment, size); }
static uintptr_t malloc_address(void) { return (uintptr_t)&malloc; }
static uintptr_t free_address(void) { return (uintptr_t)&free; }

/* errno is preserved by success and set to ENOMEM by refusal in this image. */
static int errno_contract(void) {
    errno = EDOM;
    void *block = malloc(100);
    if (!block || errno != EDOM) return 0;
    free(block);
    if (errno != EDOM) return 0;
    errno = 0;
    if (malloc(SIZE_MAX / 2) || errno != ENOMEM) return 0;
    block = malloc(64);
    errno = 0;
    if (realloc(block, SIZE_MAX / 2) || errno != ENOMEM) return 0;
    free(block);
    return 1;
}

struct thread_request { size_t size; unsigned char *block; };
static void *thread_body(void *argument) {
    struct thread_request *request = argument;
    request->block = allocate(request->size, 0x6b);
    return 0;
}
static void *thread_allocate(size_t size) {
    struct thread_request request = { size, 0 };
    pthread_t thread;
    if (pthread_create(&thread, 0, thread_body, &request) || pthread_join(thread, 0)) return 0;
    return request.block;
}

static int constructor_count(void) { return constructor_runs; }

static const struct dso_api api = {
    allocate, grow, release, zeroed, aligned, malloc_address, free_address,
    errno_contract, thread_allocate, constructor_count,
};

const struct dso_api *CONCAT(dso_api_, DSO_SYMBOL)(void) { return &api; }

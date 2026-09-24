/*
 * Allocation across the executable, an initial DSO and a runtime-loaded
 * plugin, against pinned musl 1.2.6.
 *
 * Every block class is allocated in one image, grown in another and freed in
 * a third, for each ordering of the three images, including zeroed and
 * aligned blocks and a plugin worker's block. All images must see the same
 * `malloc` and `free`, and each image keeps musl's errno contract. musl's
 * dlclose retains the plugin: after it, the plugin's code and blocks stay
 * valid, a second dlopen returns the same handle without rerunning its
 * constructor, and its destructor runs at exit.
 *
 * argv[1] is the plugin's absolute path.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "owned_native_allocator_dso.h"

#define CHECK(c) do { if (!(c)) { dprintf(2, "dso allocator line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)

const struct dso_api *dso_api_initial(void);

static void *exe_allocate(size_t size, unsigned char byte) {
    unsigned char *block = malloc(size);
    if (block) memset(block, byte, size);
    return block;
}
static void *exe_grow(void *block, size_t size) { return realloc(block, size); }
static void exe_release(void *block) { free(block); }
static void *exe_zeroed(size_t count, size_t size) { return calloc(count, size); }
static void *exe_aligned(size_t alignment, size_t size) { return aligned_alloc(alignment, size); }
static uintptr_t exe_malloc_address(void) { return (uintptr_t)&malloc; }
static uintptr_t exe_free_address(void) { return (uintptr_t)&free; }
static int exe_errno_contract(void) {
    errno = EDOM;
    void *block = malloc(100);
    if (!block || errno != EDOM) return 0;
    free(block);
    if (errno != EDOM) return 0;
    errno = 0;
    if (malloc(SIZE_MAX / 2) || errno != ENOMEM) return 0;
    return 1;
}
static const struct dso_api exe_api = {
    exe_allocate, exe_grow, exe_release, exe_zeroed, exe_aligned, exe_malloc_address,
    exe_free_address, exe_errno_contract, 0, 0,
};

static unsigned char *constructor_block;
__attribute__((constructor)) static void initialize(void) {
    constructor_block = exe_allocate(3000, 0x2d);
    CHECK(constructor_block);
}
__attribute__((destructor)) static void finalize(void) {
    for (int i = 0; i < 3000; i++) CHECK(constructor_block[i] == 0x2d);
    free(constructor_block);
    (void)!write(1, "executable fini\n", 16);
}

static const size_t sizes[] = { 48, 3000, 40000, 300000, 3u << 20 };
#define CLASSES (sizeof sizes / sizeof *sizes)

static void intact(const unsigned char *block, size_t size, unsigned char byte) {
    for (size_t i = 0; i < size; i++) CHECK(block[i] == byte);
}

/* Allocate in `a`, grow in `b`, free in `c`, for every size class. */
static void transfer(const struct dso_api *a, const struct dso_api *b, const struct dso_api *c) {
    for (size_t i = 0; i < CLASSES; i++) {
        unsigned char *block = a->allocate(sizes[i], (unsigned char)(0x40 + i));
        CHECK(block);
        unsigned char *grown = b->grow(block, sizes[i] * 2 + 1);
        CHECK(grown);
        intact(grown, sizes[i], (unsigned char)(0x40 + i));
        c->release(grown);
    }
    unsigned char *zeroed = a->zeroed(33, 100);
    CHECK(zeroed);
    intact(zeroed, 3300, 0);
    zeroed = b->grow(zeroed, 9000);
    CHECK(zeroed);
    intact(zeroed, 3300, 0);
    c->release(zeroed);
    unsigned char *aligned = a->aligned(4096, 5000);
    CHECK(aligned && ((uintptr_t)aligned & 4095) == 0);
    c->release(aligned);
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    const struct dso_api *initial = dso_api_initial();
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    CHECK(handle);
    const struct dso_api *(*plugin_entry)(void) = (const struct dso_api *(*)(void))dlsym(handle, "dso_api_plugin");
    CHECK(plugin_entry);
    const struct dso_api *plugin = plugin_entry();
    const struct dso_api *images[] = { &exe_api, initial, plugin };

    /* One malloc family across the images and the default lookup scope. */
    for (int i = 0; i < 3; i++) {
        CHECK(images[i]->malloc_address() == (uintptr_t)dlsym(RTLD_DEFAULT, "malloc"));
        CHECK(images[i]->free_address() == (uintptr_t)dlsym(RTLD_DEFAULT, "free"));
        CHECK(images[i]->errno_contract());
    }
    dprintf(1, "one malloc family and errno contract in every image\n");

    int orders = 0;
    for (int a = 0; a < 3; a++)
        for (int b = 0; b < 3; b++)
            for (int c = 0; c < 3; c++) { transfer(images[a], images[b], images[c]); orders++; }
    dprintf(1, "cross-image transfers: %d orders\n", orders);

    unsigned char *worker_block = plugin->thread_allocate(70000);
    CHECK(worker_block);
    intact(worker_block, 70000, 0x6b);
    free(worker_block);
    worker_block = initial->thread_allocate(500);
    CHECK(worker_block);
    plugin->release(worker_block);
    dprintf(1, "worker blocks cross images\n");

    /* Blocks outlive dlclose; musl retains the plugin image. */
    unsigned char *from_plugin = plugin->allocate(20000, 0x55);
    unsigned char *for_plugin = exe_allocate(600, 0x66);
    CHECK(from_plugin && for_plugin);
    CHECK(dlclose(handle) == 0);
    intact(from_plugin, 20000, 0x55);
    free(from_plugin);
    plugin->release(for_plugin);
    transfer(plugin, initial, &exe_api);
    void *again = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    CHECK(again == handle && plugin->constructor_count() == 1);
    dprintf(1, "plugin retained after dlclose\n");
    CHECK(initial->constructor_count() == 1);
    return 0;
}

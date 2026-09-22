#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { NESTED_STOP = 47, EARLY_STOP = 83 };

struct iterate_state {
    void *closed_handle;
    void *opened_handle;
    const char *retained_name;
    const ElfW(Phdr) *retained_phdr;
    ElfW(Half) retained_phnum;
    uintptr_t retained_address;
    const unsigned char *retained_readonly_image;
    size_t retained_readonly_size;
    unsigned retained_readonly_checksum;
    int mutations;
    int worker_mutation;
    int outer_callbacks;
    int appended_callbacks;
    int nested_callbacks;
    int nested_target_callbacks;
};

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "iterate reentrancy failed line %d: %s\\n", __LINE__, #condition); \
    abort(); \
} } while (0)

static int valid_info(const struct dl_phdr_info *info, size_t size)
{
    return size >= sizeof *info && info->dlpi_name && info->dlpi_phdr
        && info->dlpi_phnum;
}

static unsigned image_checksum(const unsigned char *bytes, size_t size)
{
    unsigned result = 0;
    for (size_t i = 0; i < size; ++i)
        result = result * 33 + bytes[i];
    return result;
}

/* dlclose in the pinned musl profile retains loader mappings. This reads the
 * borrowed name and program-header view after the callback has closed its
 * handle, rather than treating the callback's dl_phdr_info record itself as
 * persistent storage. */
static int retained_mapping_is_live(const struct iterate_state *state)
{
    if (!state->retained_name || !state->retained_phdr || !state->retained_phnum
        || !strstr(state->retained_name, "libscope-first.so"))
        return 0;
    if (!state->retained_readonly_image || !state->retained_readonly_size
        || image_checksum(state->retained_readonly_image, state->retained_readonly_size)
            != state->retained_readonly_checksum)
        return 0;
    for (ElfW(Half) index = 0; index < state->retained_phnum; ++index)
        if (state->retained_phdr[index].p_type == PT_LOAD)
            return 1;
    return 0;
}

static int nested_visit(struct dl_phdr_info *info, size_t size, void *argument)
{
    struct iterate_state *state = argument;
    CHECK(valid_info(info, size));
    ++state->nested_callbacks;
    if (info->dlpi_addr == state->retained_address
        && info->dlpi_phdr == state->retained_phdr
        && strstr(info->dlpi_name, "libscope-first.so")) {
        ++state->nested_target_callbacks;
        return NESTED_STOP;
    }
    return 0;
}

/* Joining here requires enumeration to release loader ownership around the
 * callback. The worker also closes the saved handle while this thread keeps
 * reading the borrowed ELF view after the callback returns. */
static void *mutate_on_worker(void *argument)
{
    struct iterate_state *state = argument;
    CHECK(!dlclose(state->closed_handle));
    state->opened_handle = dlopen("libscope-second.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(state->opened_handle);
    CHECK(dlsym(state->opened_handle, "scope_value"));
    CHECK(!dlclose(state->opened_handle));
    state->opened_handle = dlopen("libscope-second.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(state->opened_handle);
    return 0;
}

static int outer_visit(struct dl_phdr_info *info, size_t size, void *argument)
{
    struct iterate_state *state = argument;
    CHECK(valid_info(info, size));
    ++state->outer_callbacks;

    if (strstr(info->dlpi_name, "libscope-second.so"))
        ++state->appended_callbacks;

    /* One bounded mutation covers both requirements: the former target's
     * borrowed mapping view survives close, and a newly admitted DSO extends
     * this traversal after the callback returns. */
    if (!state->mutations && strstr(info->dlpi_name, "libscope-first.so")) {
        state->mutations = 1;
        state->retained_name = info->dlpi_name;
        state->retained_phdr = info->dlpi_phdr;
        state->retained_phnum = info->dlpi_phnum;
        state->retained_address = info->dlpi_addr;
        for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
            if (info->dlpi_phdr[i].p_type == PT_LOAD
                && !(info->dlpi_phdr[i].p_flags & PF_W)) {
                state->retained_readonly_image = (const unsigned char *)
                    (info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
                state->retained_readonly_size = info->dlpi_phdr[i].p_memsz;
                state->retained_readonly_checksum = image_checksum(
                    state->retained_readonly_image, state->retained_readonly_size);
            }
        }
        CHECK(retained_mapping_is_live(state));
        if (state->worker_mutation) {
            pthread_t worker;
            CHECK(!pthread_create(&worker, 0, mutate_on_worker, state));
            CHECK(!pthread_join(worker, 0));
        } else {
            CHECK(!dlclose(state->closed_handle));
            CHECK(retained_mapping_is_live(state));
            state->opened_handle = dlopen("libscope-second.so", RTLD_NOW | RTLD_LOCAL);
            CHECK(state->opened_handle);
            CHECK(dlsym(state->opened_handle, "scope_value"));
        }
        CHECK(retained_mapping_is_live(state));
        CHECK(dl_iterate_phdr(nested_visit, state) == NESTED_STOP);
        CHECK(state->nested_callbacks && state->nested_target_callbacks == 1);
        CHECK(retained_mapping_is_live(state));
    }
    return 0;
}

static int count_visit(struct dl_phdr_info *info, size_t size, void *argument)
{
    CHECK(valid_info(info, size));
    ++*(int *)argument;
    return 0;
}

static int early_stop(struct dl_phdr_info *info, size_t size, void *argument)
{
    CHECK(valid_info(info, size));
    ++*(int *)argument;
    return EARLY_STOP;
}

int main(int argc, char **argv)
{
    int baseline = 0;
    CHECK(!dl_iterate_phdr(count_visit, &baseline) && baseline > 0);

    struct iterate_state state = {0};
    state.worker_mutation = argc == 2 && !strcmp(argv[1], "worker");
    state.closed_handle = dlopen("libscope-first.so", RTLD_NOW | RTLD_LOCAL);
    CHECK(state.closed_handle);
    CHECK(!dl_iterate_phdr(outer_visit, &state));
    CHECK(state.mutations == 1 && state.opened_handle);
    /* The outer walk observes both the target loaded before it began and the
     * one DSO appended by its callback; the guard above prevents an append
     * loop if the callback reaches the new node. */
    CHECK(state.outer_callbacks == baseline + 2 && state.appended_callbacks == 1);
    CHECK(retained_mapping_is_live(&state));
    CHECK(!dlclose(state.opened_handle));
    CHECK(retained_mapping_is_live(&state));

    int early_callbacks = 0;
    CHECK(dl_iterate_phdr(early_stop, &early_callbacks) == EARLY_STOP);
    CHECK(early_callbacks == 1);
    puts("dl_iterate_phdr: nested callback, retained mapping, bounded append");
    return 0;
}

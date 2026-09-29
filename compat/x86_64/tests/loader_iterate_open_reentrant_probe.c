#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef int (*state_fn)(int *, int *, int *, int *, int *);
typedef void (*set_tls_fn)(int, int);

struct image {
    uintptr_t address;
    uintptr_t headers;
    size_t header_count;
    size_t module;
    uintptr_t tls;
    unsigned long long additions;
    char name[256];
};

struct trace {
    const char *second_path;
    void *second_handle;
    state_fn first_state;
    state_fn second_state;
    set_tls_fn first_set_tls;
    set_tls_fn second_set_tls;
    struct image first;
    struct image second;
    char order[4];
    int order_length;
    int first_calls;
    int second_calls;
    int failure;
};

static int state_is(state_fn state, int tag, int constructors, int destructors,
                    int initialized, int zero)
{
    int actual_tag, actual_constructors, actual_destructors, actual_initialized, actual_zero;
    return state && state(&actual_tag, &actual_constructors, &actual_destructors,
                          &actual_initialized, &actual_zero) == 0x51ab
        && actual_tag == tag && actual_constructors == constructors
        && actual_destructors == destructors
        && actual_initialized == initialized && actual_zero == zero;
}

static int image_name(const struct dl_phdr_info *info, const char *wanted)
{
    const char *name = strrchr(info->dlpi_name, '/');
    return !strcmp(name ? name + 1 : info->dlpi_name, wanted);
}

static int copy_image(struct image *image, const struct dl_phdr_info *info, size_t size)
{
    if (size < sizeof(*info) || !info->dlpi_phdr || !info->dlpi_phnum
        || !info->dlpi_tls_modid || !info->dlpi_tls_data
        || strlen(info->dlpi_name) >= sizeof(image->name)) return 0;
    image->address = info->dlpi_addr;
    image->headers = (uintptr_t)info->dlpi_phdr;
    image->header_count = info->dlpi_phnum;
    image->module = info->dlpi_tls_modid;
    image->tls = (uintptr_t)info->dlpi_tls_data;
    image->additions = info->dlpi_adds;
    strcpy(image->name, info->dlpi_name);
    return 1;
}

static int same_image(const struct image *image, const struct dl_phdr_info *info)
{
    return image->address == info->dlpi_addr
        && image->headers == (uintptr_t)info->dlpi_phdr
        && image->header_count == info->dlpi_phnum
        && image->module == info->dlpi_tls_modid
        && image->tls == (uintptr_t)info->dlpi_tls_data
        && !strcmp(image->name, info->dlpi_name);
}

static int open_during_iteration(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct trace *trace = opaque;
    if (image_name(info, "libloader-iterate-open-first.so")) {
        if (trace->order_length >= (int)sizeof(trace->order) - 1) {
            trace->failure = 8;
            return 1;
        }
        ++trace->first_calls;
        trace->order[trace->order_length++] = 'A';
        if (!copy_image(&trace->first, info, size)
            || !state_is(trace->first_state, 1, 1, 0, 17, 0)) {
            trace->failure = 1;
            return 1;
        }
        trace->first_set_tls(41, 43);
        trace->second_handle = dlopen(trace->second_path, RTLD_NOW | RTLD_LOCAL);
        if (!trace->second_handle) {
            trace->failure = 2;
            return 1;
        }
        trace->second_state = (state_fn)dlsym(trace->second_handle,
                                               "loader_iterate_open_reentrant_state");
        trace->second_set_tls = (set_tls_fn)dlsym(trace->second_handle,
                                                   "loader_iterate_open_reentrant_set_tls");
        if (!trace->second_set_tls || !state_is(trace->second_state, 2, 1, 0, 27, 0)) {
            trace->failure = 3;
            return 1;
        }
        trace->second_set_tls(71, 73);
        if (!same_image(&trace->first, info)
            || trace->first.additions != info->dlpi_adds
            || !state_is(trace->first_state, 1, 1, 0, 41, 43)) {
            trace->failure = 4;
            return 1;
        }
    } else if (image_name(info, "libloader-iterate-open-second.so")) {
        if (trace->order_length >= (int)sizeof(trace->order) - 1) {
            trace->failure = 8;
            return 1;
        }
        ++trace->second_calls;
        trace->order[trace->order_length++] = 'B';
        if (!copy_image(&trace->second, info, size)
            || !state_is(trace->second_state, 2, 1, 0, 71, 73)) {
            trace->failure = 5;
            return 1;
        }
    }
    return 0;
}

static int check_again(struct dl_phdr_info *info, size_t size, void *opaque)
{
    struct trace *trace = opaque;
    (void)size;
    if (image_name(info, "libloader-iterate-open-first.so")) {
        ++trace->first_calls;
        if (!same_image(&trace->first, info)) trace->failure = 6;
    } else if (image_name(info, "libloader-iterate-open-second.so")) {
        ++trace->second_calls;
        if (!same_image(&trace->second, info)) trace->failure = 7;
    }
    return trace->failure != 0;
}

static int count_static(struct dl_phdr_info *info, size_t size, void *opaque)
{
    int *count = opaque;
    if (size < sizeof(*info) || !info->dlpi_phdr || !info->dlpi_phnum) return 1;
    ++*count;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "static")) {
        int count = 0;
        if (dl_iterate_phdr(count_static, &count) || count < 1) return 10;
        printf("static images=%d\n", count);
        return 0;
    }
    if (argc != 4 || strcmp(argv[1], "dynamic")) return 11;
    void *first_handle = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!first_handle) return 12;
    struct trace trace = { .second_path = argv[3] };
    trace.first_state = (state_fn)dlsym(first_handle, "loader_iterate_open_reentrant_state");
    trace.first_set_tls = (set_tls_fn)dlsym(first_handle,
                                            "loader_iterate_open_reentrant_set_tls");
    if (!trace.first_set_tls || !state_is(trace.first_state, 1, 1, 0, 17, 0)) return 13;
    if (dl_iterate_phdr(open_during_iteration, &trace) || trace.failure
        || trace.first_calls != 1 || !trace.second_handle) return 14;
    printf("observed order=%s first=%d second=%d modules=%zu,%zu adds=%llu,%llu\n",
           trace.order, trace.first_calls, trace.second_calls,
           trace.first.module, trace.second.module,
           trace.first.additions, trace.second.additions);
    if (trace.second_calls != 1 || trace.order_length != 2
        || strcmp(trace.order, "AB") || trace.first.module >= trace.second.module
        || trace.second.additions != trace.first.additions + 1) return 15;
    trace.first_calls = trace.second_calls = 0;
    if (dl_iterate_phdr(check_again, &trace) || trace.failure
        || trace.first_calls != 1 || trace.second_calls != 1) return 16;
    if (dlclose(trace.second_handle) || dlclose(first_handle)) return 17;
    void *second_again = dlopen(argv[3], RTLD_NOW | RTLD_LOCAL);
    void *first_again = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (second_again != trace.second_handle || first_again != first_handle
        || !state_is(trace.first_state, 1, 1, 0, 41, 43)
        || !state_is(trace.second_state, 2, 1, 0, 71, 73)) return 18;
    trace.first_calls = trace.second_calls = 0;
    if (dl_iterate_phdr(check_again, &trace) || trace.failure
        || trace.first_calls != 1 || trace.second_calls != 1) return 19;
    if (dlclose(first_again) || dlclose(second_again)) return 20;
    printf("dynamic order=AB callbacks=1,1 reopen=same constructors=1,1 "
           "destructors=0,0 tls=41,43:71,73 modules=%zu,%zu\n",
           trace.first.module, trace.second.module);
    return 0;
}

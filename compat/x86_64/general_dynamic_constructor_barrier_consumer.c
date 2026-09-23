#define _GNU_SOURCE
#include "general_dynamic_constructor_barrier_state.h"
#include <dlfcn.h>
#include <link.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

static int found_constructor_image(struct dl_phdr_info *info, size_t size, void *argument)
{
    (void)size;
    if (info->dlpi_name && strstr(info->dlpi_name, "libconstructor-barrier.so"))
        *(int *)argument = 1;
    return 0;
}

static void *lookup_symbol_while_constructor_runs(void *unused)
{
    (void)unused;
    while (!constructor_barrier_is_entered()) sched_yield();
    constructor_barrier_attempt();
    void *symbol = dlsym(RTLD_DEFAULT, "constructor_barrier_value");
    constructor_barrier_symbol_result(symbol != 0);
    constructor_barrier_complete();
    return 0;
}

static void *iterate_while_constructor_runs(void *unused)
{
    (void)unused;
    while (!constructor_barrier_is_entered()) sched_yield();
    constructor_barrier_attempt();
    int found = 0;
    dl_iterate_phdr(found_constructor_image, &found);
    constructor_barrier_iterate_result(found);
    constructor_barrier_complete();
    return 0;
}

int main(void)
{
    constructor_barrier_reset();
    pthread_t symbol_reader, iterate_reader;
    if (pthread_create(&symbol_reader, 0, lookup_symbol_while_constructor_runs, 0)
        || pthread_create(&iterate_reader, 0, iterate_while_constructor_runs, 0))
        return 2;

    void *handle = dlopen("libconstructor-barrier.so", RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "constructor barrier dlopen: %s\n", dlerror());
        return 3;
    }
    if (pthread_join(symbol_reader, 0) || pthread_join(iterate_reader, 0))
        return 4;
    if (constructor_barrier_early_completions() != 0
        || constructor_barrier_completed() != 2
        || constructor_barrier_symbol_results() != 1
        || constructor_barrier_iterate_results() != 1) {
        fprintf(stderr, "constructor barrier failed: early=%d completed=%d dlsym=%d iterate=%d\n",
            constructor_barrier_early_completions(), constructor_barrier_completed(),
            constructor_barrier_symbol_results(), constructor_barrier_iterate_results());
        return 5;
    }
    if (dlclose(handle)) return 6;
    puts("constructor barrier: same-thread reentry and foreign dlsym/iterate wait");
    return 0;
}

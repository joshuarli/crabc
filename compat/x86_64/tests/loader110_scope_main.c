#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { puts(dlerror()); return 2; }
    int (*probe)(void) = dlsym(handle, "loader110_next_from_caller");
    int *calls = dlsym(handle, "loader110_constructor_calls");
    int *reentry = dlsym(handle, "loader110_constructor_reentry");
    int *through_handle = dlsym(handle, "loader110_next_value");
    if (!probe || !calls || !reentry || !through_handle) return 3;
    int local = probe();
    int hidden = dlsym(RTLD_DEFAULT, "loader110_next_value") == 0;
    dlerror();
    void *promoted = dlopen(argv[1], RTLD_NOW | RTLD_NOLOAD | RTLD_GLOBAL);
    int global_next = probe();
    int *global = dlsym(RTLD_DEFAULT, "loader110_next_value");
    if (local != -1 || !hidden || promoted != handle || global_next != 73
        || global != through_handle || *global != 73 || *calls != 1 || *reentry != 1)
        return 4;
    if (dlclose(handle)) return 5;
    void *retained = dlopen(argv[1], RTLD_NOW | RTLD_NOLOAD);
    if (retained != handle || *calls != 1 || probe() != 73) return 6;
    puts("local graph: handle scope, caller RTLD_NEXT, global promotion, constructor reentry");
    return 0;
}

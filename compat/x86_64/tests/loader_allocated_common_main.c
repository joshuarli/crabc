#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    void *handle = dlopen(argv[1], RTLD_NOW);
    if (!handle) return 2;
    int *value = dlsym(handle, "loader_allocated_common_value");
    int (*read_value)(void) = dlsym(handle, "loader_allocated_common_read");
    if (!value || !read_value || *value != 0 || read_value() != 0) return 3;
    *value = 73;
    if (read_value() != 73) return 4;
    Dl_info info;
    if (!dladdr(value, &info) || !info.dli_sname
        || strcmp(info.dli_sname, "loader_allocated_common_value")
        || info.dli_saddr != value) return 5;
    return dlclose(handle) != 0;
}

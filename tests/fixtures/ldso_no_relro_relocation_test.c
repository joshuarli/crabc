#include <dlfcn.h>
#include <stdio.h>

typedef int (*read_value_fn)(void);

int main(int argc, char **argv)
{
    void *first;
    void *second;
    read_value_fn read_value;

    if (argc != 3)
        return 1;
    first = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (first == NULL)
        return 2;
    read_value = (read_value_fn)dlsym(first, "no_relro_value");
    if (read_value == NULL || read_value() != 41)
        return 3;
    second = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (second == NULL)
        return 4;
    if (read_value() != 41)
        return 5;
    if (dlclose(second) != 0 || dlclose(first) != 0)
        return 6;
    puts("no-relro relocation ok");
    return 0;
}

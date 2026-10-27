#include <dlfcn.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    void *handle = dlopen(argv[1], RTLD_NOW);
    int (*mutate)(void) = handle ? (int (*)(void))dlsym(handle, "symbol_mutate") : 0;
    return !mutate || !mutate() || access("/symbol-mutable-marker", F_OK) != 0 || dlclose(handle) != 0;
}

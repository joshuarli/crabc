#include <dlfcn.h>
int main(void)
{
    if (!dlopen("libgrowth0.so", RTLD_NOW | RTLD_LOCAL)) return 10;
    dlopen("libconstructor-exit.so", RTLD_NOW | RTLD_LOCAL);
    return 11;
}

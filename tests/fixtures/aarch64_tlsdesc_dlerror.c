#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    if (dlopen(argv[1], RTLD_NOW)) return 2;
    const char *error = dlerror();
    if (!error) return 3;
    puts(error);
    return strstr(error, "missing") && strstr(error, "symbol not found") ? 0 : 4;
}

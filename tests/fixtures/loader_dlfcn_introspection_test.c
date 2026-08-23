#include <stdio.h>

extern int crabc_rs_loader_dlfcn_introspection_probe(void);

int main(void)
{
    int result = crabc_rs_loader_dlfcn_introspection_probe();
    if (result != 0) {
        printf("loader loader dlfcn introspection FAIL %d\n", result);
        return 1;
    }
    puts("loader loader dlfcn introspection ok");
    return 0;
}

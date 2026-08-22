#include <stdio.h>

extern int crabc_rs_m11_loader_dlfcn_basic_probe(void);

int main(void)
{
    int result = crabc_rs_m11_loader_dlfcn_basic_probe();
    if (result != 0) {
        printf("m11 loader dlfcn basic FAIL %d\n", result);
        return 1;
    }
    puts("m11 loader dlfcn basic ok");
    return 0;
}

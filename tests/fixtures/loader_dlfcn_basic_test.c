#include <stdio.h>

extern int crabc_rs_loader_dlfcn_basic_probe(void);

int main(void)
{
    int result = crabc_rs_loader_dlfcn_basic_probe();
    if (result != 0) {
        printf("loader loader dlfcn basic FAIL %d\n", result);
        return 1;
    }
    puts("loader loader dlfcn basic ok");
    return 0;
}

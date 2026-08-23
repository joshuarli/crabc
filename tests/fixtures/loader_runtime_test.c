#include <stdio.h>

extern int crabc_rs_loader_runtime_probe(void);

int main(void)
{
    int result = crabc_rs_loader_runtime_probe();
    if (result != 0) {
        printf("runtime loader runtime FAIL %d\n", result);
        return 1;
    }
    puts("runtime loader runtime ok");
    return 0;
}

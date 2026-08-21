#include <stdio.h>

extern int crabc_rs_m7_loader_runtime_probe(void);

int main(void)
{
    int result = crabc_rs_m7_loader_runtime_probe();
    if (result != 0) {
        printf("m7 loader runtime FAIL %d\n", result);
        return 1;
    }
    puts("m7 loader runtime ok");
    return 0;
}

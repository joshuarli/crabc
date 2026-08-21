#include <stdio.h>

extern int crabc_rs_m7_runtime_thread_probe(void);

int main(void)
{
    int result = crabc_rs_m7_runtime_thread_probe();
    if (result != 0) {
        printf("m7 runtime thread FAIL %d\n", result);
        return 1;
    }
    puts("m7 runtime thread ok");
    return 0;
}

#include <stdio.h>

extern int crabc_rs_runtime_thread_probe(void);

int main(void)
{
    int result = crabc_rs_runtime_thread_probe();
    if (result != 0) {
        printf("runtime runtime thread FAIL %d\n", result);
        return 1;
    }
    puts("runtime runtime thread ok");
    return 0;
}

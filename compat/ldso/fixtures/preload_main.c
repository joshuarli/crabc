#include <stdio.h>

extern int preload_value(void);

int main(void)
{
    printf("preload=%d\n", preload_value());
    return 0;
}

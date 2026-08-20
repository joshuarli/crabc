#include <stdio.h>

extern int nested_mid_value(void);

int main(void)
{
    printf("nested=%d\n", nested_mid_value());
    return 0;
}

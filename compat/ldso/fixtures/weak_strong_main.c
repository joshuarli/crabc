#include <stdio.h>

extern int lookup_value(void);

int main(void)
{
    printf("lookup=%d\n", lookup_value());
    return 0;
}

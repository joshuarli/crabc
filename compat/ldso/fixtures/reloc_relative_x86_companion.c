#include <stdio.h>

extern int reloc_sum(void);
extern int reloc_relative_x86_value(void);

int main(void)
{
    int sum = reloc_sum();
    int relative = reloc_relative_x86_value();
    if (sum != 42 || relative != 73)
        return 10;
    printf("reloc=%d relative=%d\n", sum, relative);
    return 0;
}

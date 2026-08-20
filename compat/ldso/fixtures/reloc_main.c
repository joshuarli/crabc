#include <stdio.h>

extern int reloc_sum(void);

int main(void)
{
    printf("reloc=%d\n", reloc_sum());
    return 0;
}

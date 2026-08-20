#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    void *current = sbrk(0);
    if (current == (void *)-1 || brk(current) != 0)
        return 1;
    errno = 0;
    if (sbrk(INTPTR_MAX) != (void *)-1 || errno != ENOMEM)
        return 2;
    errno = 0;
    if (brk(NULL) != -1 || errno != ENOMEM)
        return 3;
    puts("m4 break exports ok");
    return 0;
}

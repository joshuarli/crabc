#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    void *current = sbrk(0);
    if (current == (void *)-1)
        return 1;
    errno = 0;
    if (brk(current) != -1 || errno != ENOMEM)
        return 2;
    errno = 0;
    if (sbrk(INTPTR_MAX) != (void *)-1 || errno != ENOMEM)
        return 3;
    errno = 0;
    if (sbrk(-1) != (void *)-1 || errno != ENOMEM)
        return 4;
    errno = 0;
    if (brk(NULL) != -1 || errno != ENOMEM)
        return 5;
    puts("m4 break exports ok");
    return 0;
}

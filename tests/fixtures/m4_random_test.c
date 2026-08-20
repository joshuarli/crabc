#include <errno.h>
#include <stdio.h>
#include <string.h>

extern long getrandom(void *, unsigned long, unsigned int);
extern int getentropy(void *, unsigned long);

int main(void)
{
    unsigned char first[32] = {0};
    unsigned char second[32] = {0};
    unsigned char oversized[257];

    if (getrandom(first, sizeof first, 0) != (long)sizeof first)
        return 1;
    if (getentropy(second, sizeof second) != 0)
        return 2;
    if (!memcmp(first, "\0\0\0\0\0\0\0\0", 8) &&
        !memcmp(second, "\0\0\0\0\0\0\0\0", 8))
        return 3;

    errno = 0;
    if (getentropy(oversized, sizeof oversized) != -1 || errno != EIO)
        return 4;
    errno = 0;
    if (getrandom(NULL, 1, 0) != -1 || errno != EFAULT)
        return 5;

    puts("m4 random exports ok");
    return 0;
}

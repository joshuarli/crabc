#define _GNU_SOURCE
#include <stdio.h>
#include <sys/time.h>

static int check_sample(void)
{
    struct timeval value = {0};

    if (gettimeofday(&value, NULL) != 0)
        return 1;
    if (value.tv_usec < 0 || value.tv_usec >= 1000000)
        return 2;
    return 0;
}

int main(void)
{
    if (gettimeofday(NULL, NULL) != 0)
        return 1;
    for (int index = 0; index < 4096; ++index) {
        int result = check_sample();
        if (result != 0)
            return result + 1;
    }
    puts("gettimeofday contract ok");
    return 0;
}

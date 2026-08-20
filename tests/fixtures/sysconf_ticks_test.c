#include <stdio.h>
#include <unistd.h>

int main(void)
{
    long ticks_per_second = sysconf(_SC_CLK_TCK);
    if (ticks_per_second <= 0) {
        printf("ticks unavailable: %ld\n", ticks_per_second);
        return 1;
    }
    printf("ticks %ld\n", ticks_per_second);
    return ticks_per_second == 100 ? 0 : 2;
}

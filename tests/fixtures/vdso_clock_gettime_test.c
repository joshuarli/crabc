#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static int hot_clock_loop(void)
{
    struct timespec value;
    volatile long sink = 0;

    for (int index = 0; index < 1 << 12; ++index) {
        if (clock_gettime(CLOCK_MONOTONIC, &value) != 0)
            return 10;
        if (value.tv_nsec < 0 || value.tv_nsec >= 1000000000L)
            return 11;
        sink += value.tv_nsec;
    }

    return sink == 0 ? 12 : 0;
}

int main(int argc, char **argv)
{
    int result = hot_clock_loop();

    if (result != 0)
        return result;
    if (argc == 2 && strcmp(argv[1], "--hot") == 0)
        return 0;

    errno = 0;
    if (clock_gettime(-1, &(struct timespec){0}) != -1 || errno != EINVAL)
        return 13;

    puts("vdso clock route ok");
    return 0;
}

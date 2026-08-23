#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int rand_r(unsigned *);

static int expected_rand_r(unsigned *seed)
{
    unsigned value = *seed * 1103515245u + 12345u;
    value ^= value >> 11;
    value ^= (value << 7) & 0x9d2c5680u;
    value ^= (value << 15) & 0xefc60000u;
    value ^= value >> 18;
    *seed = *seed * 1103515245u + 12345u;
    return (int)(value >> 1);
}

int main(void)
{
    char *end;
    imaxdiv_t divided;
    unsigned actual_seed = 7;
    unsigned expected_seed = 7;

    if (imaxabs(-42) != 42 || imaxabs(42) != 42)
        return 1;
    divided = imaxdiv(-17, 5);
    if (divided.quot != -3 || divided.rem != -2)
        return 2;

    errno = 0;
    if (strtoimax("-0x2a!", &end, 0) != -42 || strcmp(end, "!") || errno)
        return 3;
    errno = 0;
    if (strtoumax("18446744073709551616", &end, 10) != UINTMAX_MAX ||
        errno != ERANGE || *end)
        return 4;

    if (!isnan(nan("payload")) || !isnan(nanf("payload")) ||
        !isnan(nanl("payload")))
        return 5;
    if (rand_r(&actual_seed) != expected_rand_r(&expected_seed) ||
        actual_seed != expected_seed)
        return 6;

    puts("c-abi integer numeric exports ok");
    return 0;
}

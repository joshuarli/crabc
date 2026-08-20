#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int check_value(const char *text, long double want) {
    char *end;
    long double got = strtold(text, &end);
    if (*end != '\0' || got != want) return 1;
    return 0;
}

int main(void) {
    if (check_value("12.345", 12.345L)) return 1;
    if (check_value("1.2345e1", 12.345L)) return 2;
    if (check_value("0x1.111111111111111111111111111281",
                    0x1.1111111111111111111111111113p0L)) return 3;
    if (check_value("0x1.11111111111111111111111111111",
                    0x1.1111111111111111111111111111p0L)) return 4;

#if defined(__aarch64__) || defined(__riscv)
    /* Detect the old f64 -> f128 implementation even if arithmetic changes. */
    unsigned long long expected[2] = {
        0x0a3d70a3d70a3d71ULL,
        0x40028b0a3d70a3d7ULL,
    };
    long double value = strtold("12.345", NULL);
    if (sizeof(value) != sizeof(expected) || memcmp(&value, expected, sizeof expected) != 0)
        return 5;
#endif

    puts("strtold ok");
    return 0;
}

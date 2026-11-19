#include <fenv.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void run(const char *name, long double (*fn)(long double), long double input) {
    uint64_t words[2];
    feclearexcept(FE_ALL_EXCEPT);
    volatile long double value = fn(input);
    int flags = fetestexcept(FE_ALL_EXCEPT);
    memcpy(words, (const void *)&value, sizeof words);
    printf("%s %016llx%016llx %x\n", name,
        (unsigned long long)words[1], (unsigned long long)words[0], flags);
}

int main(void) {
    int modes[] = {FE_TONEAREST, FE_UPWARD, FE_DOWNWARD, FE_TOWARDZERO};
    for (unsigned i = 0; i < sizeof modes / sizeof *modes; i++) {
        fesetround(modes[i]);
        run("rintl", rintl, 2.5L);
        run("rintl-small", rintl, 0.5L);
        run("rintl-negative", rintl, -2.5L);
        run("rintl-large", rintl, 0x1.0000000000000000000000000001p111L);
        run("nearbyintl", nearbyintl, -2.5L);
        run("nearbyintl-small", nearbyintl, -0.5L);
        run("sqrtl", sqrtl, 2.0L);
        run("sqrtl-neighbor", sqrtl, 0x1.0000000000000000000000000001p0L);
        run("sqrtl-subnormal", sqrtl, 0x1p-16494L);
        run("sqrtl-exact", sqrtl, 4.0L);
        run("sqrtl-negative", sqrtl, -1.0L);
        run("sqrtl-zero", sqrtl, -0.0L);
        run("sqrtl-infinity", sqrtl, INFINITY);
    }
}

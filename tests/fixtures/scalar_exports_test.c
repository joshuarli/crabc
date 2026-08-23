#include <math.h>
#include <stdio.h>
#include <strings.h>

extern int finite(double);
extern int finitef(float);
extern double significand(double);
extern float significandf(float);
extern int ffsl(long);
extern int ffsll(long long);

int main(void) {
    if (!finite(1.0) || !finitef(-1.0f)) return 1;
    if (finite(0.0 / 0.0) || finitef(1.0f / 0.0f)) return 2;
    if (significand(6.0) != 1.5 || significand(-0.75) != -1.5) return 3;
    if (significandf(3.0f) != 1.5f || significand(0.0) != 0.0) return 4;
    if (ffs(0) != 0 || ffs(1) != 1 || ffs(0x40) != 7) return 5;
    if (ffsl(0x100L) != 9 || ffsll(1LL << 42) != 43) return 6;
    puts("c-abi scalar exports ok");
    return 0;
}

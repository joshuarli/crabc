#include <fenv.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
typedef union { long double f; struct { uint64_t lo, hi; } u; } quad;
int main(void) {
    const int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    const char *formats[] = {"%.0f", "%.1f", "%.6g", "%.6e", "%a"};
    const char *long_formats[] = {"%.0Lf", "%.1Lf", "%.6Lg", "%.6Le", "%La"};
    const char *strings[] = {"-0.5", "0.5", "1.0000000000000000000000000000000001", "-1.0000000000000000000000000000000001", "3.3621031431120935062626778173217526e-4932", "1e-5000", "1e5000"};
    volatile double d=-0.5; volatile long double l=-0.5L;
    for (unsigned m=0;m<4;m++) {
        if (fesetround(modes[m])) return 2;
        printf("mode %u\n",m);
        for (unsigned i=0;i<5;i++) {
            char a[128], b[128];
            int na=snprintf(a,sizeof a,formats[i],d);
            int nb=snprintf(b,sizeof b,long_formats[i],l);
            printf("format %d %s %d %s\n",na,a,nb,b);
        }
        for (unsigned i=0;i<sizeof strings/sizeof *strings;i++) {
            char *end; feclearexcept(FE_ALL_EXCEPT); quad v={.f=strtold(strings[i],&end)};
            int flags=fetestexcept(FE_ALL_EXCEPT);
            printf("parse %zu %016" PRIx64 "%016" PRIx64 " %x\n",(size_t)(end-strings[i]),v.u.hi,v.u.lo,flags);
        }
    }
    return ferror(stdout) ? 1 : 0;
}

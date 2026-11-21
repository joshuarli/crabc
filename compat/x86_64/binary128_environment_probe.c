#include <fenv.h>
#include <stdint.h>
#include <stdio.h>
typedef union {long double f; struct {uint64_t lo,hi;} u;} quad;
extern long double __addtf3(long double,long double);
extern long double __divtf3(long double,long double);
int main(void) {
    const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    quad one={.u={0,UINT64_C(0x3fff000000000000)}}, three={.u={0,UINT64_C(0x4000800000000000)}};
    quad zero={.u={0,0}}, snan={.u={1,UINT64_C(0x7fff000000000000)}};
    for(unsigned i=0;i<4;i++) {
        if(fesetround(modes[i])) return 2;
        feclearexcept(FE_ALL_EXCEPT); feraiseexcept(FE_OVERFLOW);
        volatile quad q={.f=__divtf3(one.f,three.f)};
        int flags=fetestexcept(FE_ALL_EXCEPT), mode=fegetround();
        printf("%u div %016llx%016llx %x %x\n",i,(unsigned long long)q.u.hi,(unsigned long long)q.u.lo,flags,mode);
        feclearexcept(FE_ALL_EXCEPT); feraiseexcept(FE_DIVBYZERO);
        q.f=__addtf3(snan.f,zero.f); flags=fetestexcept(FE_ALL_EXCEPT); mode=fegetround();
        printf("%u add %016llx%016llx %x %x\n",i,(unsigned long long)q.u.hi,(unsigned long long)q.u.lo,flags,mode);
    }
    return ferror(stdout) ? 1 : 0;
}

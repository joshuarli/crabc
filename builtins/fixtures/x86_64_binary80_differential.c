#include <fenv.h>
#include <float.h>
#include <stdint.h>
#include <stdio.h>
_Static_assert(LDBL_MANT_DIG==64 && LDBL_MAX_EXP==16384, "binary80 required");
typedef __int128 i128;
typedef unsigned __int128 u128;
typedef long double _Complex complex80;
extern long double __floattixf(i128), __floatuntixf(u128);
extern i128 __fixxfti(long double);
extern u128 __fixunsxfti(long double);
extern complex80 __mulxc3(long double,long double,long double,long double);
extern complex80 __divxc3(long double,long double,long double,long double);
extern long double reference_floattixf(i128), reference_floatuntixf(u128);
extern i128 reference_fixxfti(long double);
extern u128 reference_fixunsxfti(long double);
extern complex80 reference_mulxc3(long double,long double,long double,long double);
extern complex80 reference_divxc3(long double,long double,long double,long double);
union word80 { long double f; struct { uint64_t m; uint16_t se; } bits; };
static int equal80(long double a,long double b) {
    union word80 x={.f=a},y={.f=b};
    int xn=(x.bits.se&0x7fff)==0x7fff && (x.bits.m<<1)!=0;
    int yn=(y.bits.se&0x7fff)==0x7fff && (y.bits.m<<1)!=0;
    return (x.bits.m==y.bits.m && x.bits.se==y.bits.se) || (xn && yn);
}
static int conversions(void) {
    const u128 unsigned_cases[]={0,1,((u128)1<<63)-1,(u128)1<<64,
        ((u128)1<<100)+((u128)1<<36),((u128)1<<100)+((u128)1<<36)+1,
        ((u128)1<<127)-1,(u128)1<<127,~(u128)0};
    const i128 signed_cases[]={0,1,-1,(i128)1<<100,-((i128)1<<100),
        ((i128)1<<126)+((i128)1<<62),-(((i128)1<<126)+((i128)1<<62)),
        (i128)(((u128)1<<127)-1),-((i128)1<<126)-((i128)1<<126)};
    const long double signed_floats[]={0.0L,-0.0L,0.25L,-0.25L,1.75L,-1.75L,
        0x1p100L,-0x1p100L,0x1p126L,-0x1p127L,0x1.fffffffffffffffep126L};
    const long double unsigned_floats[]={0.0L,0.25L,1.75L,0x1p100L,0x1.fffffffffffffffep127L};
    for (unsigned i=0;i<sizeof unsigned_cases/sizeof *unsigned_cases;i++) {
        feclearexcept(FE_ALL_EXCEPT);
        long double a=__floatuntixf(unsigned_cases[i]); int af=fetestexcept(FE_ALL_EXCEPT);
        feclearexcept(FE_ALL_EXCEPT);
        long double b=reference_floatuntixf(unsigned_cases[i]); int bf=fetestexcept(FE_ALL_EXCEPT);
        if (!equal80(a,b) || af!=bf) return 1;
    }
    for (unsigned i=0;i<sizeof signed_cases/sizeof *signed_cases;i++) {
        feclearexcept(FE_ALL_EXCEPT);
        long double a=__floattixf(signed_cases[i]); int af=fetestexcept(FE_ALL_EXCEPT);
        feclearexcept(FE_ALL_EXCEPT);
        long double b=reference_floattixf(signed_cases[i]); int bf=fetestexcept(FE_ALL_EXCEPT);
        if (!equal80(a,b) || af!=bf) return 2;
    }
    /* Every float-to-integer input is finite and within its destination range. */
    for (unsigned i=0;i<sizeof signed_floats/sizeof *signed_floats;i++) {
        feclearexcept(FE_ALL_EXCEPT);
        i128 a=__fixxfti(signed_floats[i]); int af=fetestexcept(FE_ALL_EXCEPT);
        feclearexcept(FE_ALL_EXCEPT);
        i128 b=reference_fixxfti(signed_floats[i]); int bf=fetestexcept(FE_ALL_EXCEPT);
        if (a!=b || af!=bf) return 3;
    }
    for (unsigned i=0;i<sizeof unsigned_floats/sizeof *unsigned_floats;i++) {
        feclearexcept(FE_ALL_EXCEPT);
        u128 a=__fixunsxfti(unsigned_floats[i]); int af=fetestexcept(FE_ALL_EXCEPT);
        feclearexcept(FE_ALL_EXCEPT);
        u128 b=reference_fixunsxfti(unsigned_floats[i]); int bf=fetestexcept(FE_ALL_EXCEPT);
        if (a!=b || af!=bf) return 4;
    }
    return 0;
}
static int complex_case(long double a,long double b,long double c,long double d,int divide) {
    feclearexcept(FE_ALL_EXCEPT);
    complex80 x=divide?__divxc3(a,b,c,d):__mulxc3(a,b,c,d);
    int xf=fetestexcept(FE_ALL_EXCEPT);
    feclearexcept(FE_ALL_EXCEPT);
    complex80 y=divide?reference_divxc3(a,b,c,d):reference_mulxc3(a,b,c,d);
    int yf=fetestexcept(FE_ALL_EXCEPT);
    if (!equal80(__real__ x,__real__ y) || !equal80(__imag__ x,__imag__ y) || xf!=yf) {
        fprintf(stderr,"binary80 %s inputs %La %La %La %La flags %x/%x results %La,%La/%La,%La\n",
            divide?"division":"multiplication",a,b,c,d,xf,yf,__real__ x,__imag__ x,__real__ y,__imag__ y);
        return 1;
    }
    return 0;
}
int main(void) {
    static const long double values[]={0.0L,-0.0L,1.0L,-1.0L,2.0L,-2.0L,
        0x1p-16445L,-0x1p-16445L,0x1p-16382L,0x1.fffffffffffffffep16383L,
        __builtin_infl(),-__builtin_infl(),__builtin_nanl(""),__builtin_nansl(""),
        0x1p8000L,0x1p-8000L};
    static const int modes[]={FE_TONEAREST,FE_DOWNWARD,FE_UPWARD,FE_TOWARDZERO};
    unsigned long cases=0;
    for (unsigned m=0;m<sizeof modes/sizeof *modes;m++) {
        if (fesetround(modes[m])) return 10;
        int status=conversions(); if (status) return 10+status;
        for (unsigned a=0;a<sizeof values/sizeof *values;a++)
        for (unsigned b=0;b<sizeof values/sizeof *values;b++)
        for (unsigned c=0;c<sizeof values/sizeof *values;c++)
        for (unsigned d=0;d<sizeof values/sizeof *values;d++)
        for (int divide=0;divide<2;divide++) {
            if (complex_case(values[a],values[b],values[c],values[d],divide)) return 20;
            ++cases;
        }
    }
    printf("binary80 differential: PASS (%lu complex cases; four rounding modes; defined conversions)\n",cases);
    return 0;
}

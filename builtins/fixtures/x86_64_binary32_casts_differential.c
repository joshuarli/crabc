/* Direct helper calls test total source behavior beyond the C cast domain. */
typedef unsigned __int128 u128;
typedef __int128 i128;
typedef unsigned int u32;
typedef unsigned long long u64;
extern i128 __fixsfti(float);
extern u128 __fixunssfti(float);
extern float __floattisf(i128);
extern float __floatuntisf(u128);
extern i128 reference_fixsfti(float);
extern u128 reference_fixunssfti(float);
extern float reference_floattisf(i128);
extern float reference_floatuntisf(u128);
static u64 samples;
static u64 state=0xd1b54a32d192ed03ULL;
static u64 next(void) {
    state^=state<<13;state^=state>>7;state^=state<<17;
    return state;
}
static u32 repr(float value) { union { float f;u32 u; } v={.f=value};return v.u; }
static float floating(u32 value) { union { float f;u32 u; } v={.u=value};return v.f; }
static u32 status(void) { u32 value;__asm__ volatile("stmxcsr %0":"=m"(value));return value; }
static void control(u32 value) { __asm__ volatile("ldmxcsr %0"::"m"(value)); }
static int check(u128 integer,u32 bits,u32 round) {
    float input=floating(bits);
    control(round);
    u128 a=__fixunssfti(input);u32 af=status()&63;
    control(round);
    u128 b=reference_fixunssfti(input);u32 bf=status()&63;
    if (a!=b || af!=bf || af) return 1;
    control(round);
    a=(u128)__fixsfti(input);af=status()&63;
    control(round);
    b=(u128)reference_fixsfti(input);bf=status()&63;
    if (a!=b || af!=bf || af) return 2;
    control(round);
    u32 x=repr(__floatuntisf(integer));af=status()&63;
    control(round);
    u32 y=repr(reference_floatuntisf(integer));bf=status()&63;
    if (x!=y || af!=bf || af) return 3;
    control(round);
    x=repr(__floattisf((i128)integer));af=status()&63;
    control(round);
    y=repr(reference_floattisf((i128)integer));bf=status()&63;
    if (x!=y || af!=bf || af) return 4;
    ++samples;return 0;
}
int main(void) {
    static const u32 mantissas[]={0,1,2,0x3fffff,0x400000,0x400001,0x7ffffd,0x7ffffe,0x7fffff};
    u32 saved=status();
    for (u32 mode=0;mode<4;++mode) {
        u32 round=0x1f80|(mode<<13);
        for (u32 exponent=0;exponent<256;++exponent)
            for (u32 sign=0;sign<2;++sign)
                for (u32 j=0;j<sizeof mantissas/sizeof *mantissas;++j) {
                    u32 bits=(sign<<31)|(exponent<<23)|mantissas[j];
                    u128 integer=((u128)next()<<64)|next();
                    int result=check(integer,bits,round);if (result) return result;
                }
        for (u32 bit=0;bit<128;++bit) {
            u128 power=(u128)1<<bit;
            for (int delta=-1;delta<=1;++delta) {
                u128 value=power+(u128)(i128)delta;
                int result=check(value,0x7fc12345,round);if (result) return result;
                result=check(-value,0xff812345,round);if (result) return result;
            }
            if (bit>=24) {
                u128 half=(u128)1<<(bit-24),ulp=half<<1;
                for (int delta=-1;delta<=1;++delta) {
                    u128 value=power+half+(u128)(i128)delta;
                    int result=check(value,0x7f800000,round);if (result) return result;
                    result=check(value+ulp,0xff800000,round);if (result) return result;
                    result=check(-value,0x80000000,round);if (result) return result;
                }
            }
        }
        u128 overflow_midpoint=~(u128)0-((u128)1<<103)+1;
        for (int delta=-1;delta<=1;++delta) {
            int result=check(overflow_midpoint+(u128)(i128)delta,0x7f7fffff,round);
            if (result) return result;
        }
        int result=check(~(u128)0,0xff000000,round);
        if (result) return result;
        for (u32 j=0;j<250000;++j) {
            u128 integer=((u128)next()<<64)|next();
            int result=check(integer,(u32)next(),round);if (result) return result;
        }
    }
    control(saved);
    const char text[]="binary32 exact-source differential: PASS; four rounding modes; cases=";
    __asm__ volatile("syscall"::"a"(1L),"D"(1L),"S"(text),"d"(sizeof text-1):"rcx","r11","memory");
    char digits[32];unsigned length=0;
    do { digits[length++]='0'+samples%10;samples/=10; } while (samples);
    for (unsigned j=0;j<length/2;++j) {
        char t=digits[j];digits[j]=digits[length-j-1];digits[length-j-1]=t;
    }
    digits[length++]='\n';
    __asm__ volatile("syscall"::"a"(1L),"D"(1L),"S"(digits),"d"((u64)length):"rcx","r11","memory");
    return 0;
}

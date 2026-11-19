#include <fenv.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#pragma STDC FENV_ACCESS ON

typedef union { long double f; struct { uint64_t lo, hi; } u; } quad;
static uint64_t rng = UINT64_C(0x3d9c4a7b5e12f681);
static uint64_t next(void) { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
static const quad edges[] = {
    {.u={0,0}}, {.u={0,UINT64_C(0x8000000000000000)}},
    {.u={1,0}}, {.u={UINT64_MAX,UINT64_C(0x0000ffffffffffff)}},
    {.u={0,UINT64_C(0x0001000000000000)}},
    {.u={0,UINT64_C(0x3fff000000000000)}},
    {.u={0,UINT64_C(0xbffe000000000000)}},
    {.u={UINT64_MAX,UINT64_C(0x7ffeffffffffffff)}},
    {.u={0,UINT64_C(0x7fff000000000000)}},
    {.u={0,UINT64_C(0xffff000000000000)}},
    {.u={0x1234,UINT64_C(0x7fff800000000000)}},
    {.u={0x5678,UINT64_C(0x7fff000000000000)}},
    {.u={0x9999,UINT64_C(0xffff800000000000)}},
    {.u={0x9999,UINT64_C(0x7fff800000000000)}},
    {.u={0x7777,UINT64_C(0xffff000000000000)}},
    {.u={UINT64_MAX,UINT64_C(0x0000ffffffffffff)}},
    {.u={UINT64_MAX,UINT64_C(0x3ffeffffffffffff)}},
    {.u={1,UINT64_C(0x3fff000000000000)}},
    {.u={UINT64_MAX,UINT64_C(0x3f80ffffffffffff)}},
    {.u={UINT64_MAX,UINT64_C(0x3c00ffffffffffff)}}
};
static void result(const char *name, quad q) {
    int flags = fetestexcept(FE_ALL_EXCEPT);
    printf("%s %016" PRIx64 "%016" PRIx64 " %02x\n", name, q.u.hi, q.u.lo, flags);
}
#define QUAD_OP(name, expression) do { feclearexcept(FE_ALL_EXCEPT); volatile long double z = (expression); quad out = {.f=z}; result(name, out); } while (0)
#define INT_OP(name, type, expression) do { feclearexcept(FE_ALL_EXCEPT); volatile type z = (expression); int flags = fetestexcept(FE_ALL_EXCEPT); unsigned __int128 u = (unsigned __int128)z; printf("%s %016" PRIx64 "%016" PRIx64 " %02x\n", name, (uint64_t)(u >> 64), (uint64_t)u, flags); } while (0)
#define NARROW(name, type, bits, expression) do { feclearexcept(FE_ALL_EXCEPT); volatile type z = (expression); int flags = fetestexcept(FE_ALL_EXCEPT); bits u; type tmp = z; memcpy(&u, &tmp, sizeof u); printf("%s %016" PRIx64 " %02x\n", name, (uint64_t)u, flags); } while (0)
static void run(quad x, quad y) {
    volatile long double a=x.f, b=y.f;
    QUAD_OP("add", a+b); QUAD_OP("sub", a-b); QUAD_OP("mul", a*b); QUAD_OP("div", a/b);
    NARROW("f32", float, uint32_t, (float)a); NARROW("f64", double, uint64_t, (double)a);
    INT_OP("eq", int, a==b); INT_OP("ne", int, a!=b); INT_OP("lt", int, a<b);
    INT_OP("le", int, a<=b); INT_OP("gt", int, a>b); INT_OP("ge", int, a>=b);
}
int main(void) {
    const int modes[] = {FE_TONEAREST, FE_DOWNWARD, FE_UPWARD, FE_TOWARDZERO};
    for (unsigned m=0; m<4; ++m) {
        if (fesetround(modes[m])) return 2;
        printf("mode %u\n", m);
        const uint32_t fbits[] = {0, 0x80000000, 1, 0x007fffff, 0x00800000, 0x7f800000, 0xff800000, 0x7fc01234, 0x7f801234};
        const uint64_t dbits[] = {0, UINT64_C(0x8000000000000000), 1, UINT64_C(0x000fffffffffffff), UINT64_C(0x0010000000000000), UINT64_C(0x7ff0000000000000), UINT64_C(0xfff0000000000000), UINT64_C(0x7ff8000000001234), UINT64_C(0x7ff0000000001234)};
        for (unsigned i=0; i<sizeof fbits/sizeof *fbits; ++i) {
            float fv; double dv; memcpy(&fv, &fbits[i], sizeof fv); memcpy(&dv, &dbits[i], sizeof dv);
            volatile float f=fv; volatile double d=dv;
            QUAD_OP("fromf32", (long double)f); QUAD_OP("fromf64", (long double)d);
        }
        for (unsigned i=0; i<sizeof edges/sizeof *edges; ++i)
            for (unsigned j=0; j<sizeof edges/sizeof *edges; ++j) run(edges[i],edges[j]);
        for (unsigned i=0; i<4096; ++i) {
            uint64_t high = next();
            quad a={.u={next(),high}}, b={.u={next(),(high & UINT64_C(0xffff000000000000)) | (next() & UINT64_C(0x0000ffffffffffff))}};
            run(a,b);
        }
        for (unsigned i=1; i<=115; ++i) {
            quad a={.u={0,UINT64_C(0x3fff000000000000)}};
            quad b={.u={0,((uint64_t)(0x3fff-i)) << 48}};
            run(a,b);
            b.u.hi |= UINT64_C(0x8000000000000000);
            run(a,b);
        }
        for (unsigned i=0; i<4096; ++i) {
            quad a={.u={next(),next()}}, b={.u={next(),next()}};
            run(a,b);
            volatile int32_t si=(int32_t)next(); volatile uint32_t ui=(uint32_t)next();
            volatile int64_t sl=(int64_t)next(); volatile uint64_t ul=next();
            volatile unsigned __int128 uw=((unsigned __int128)next()<<64)|next();
            volatile __int128 sw=(__int128)uw;
            QUAD_OP("i32", (long double)si); QUAD_OP("u32", (long double)ui);
            QUAD_OP("i64", (long double)sl); QUAD_OP("u64", (long double)ul);
            QUAD_OP("i128", (long double)sw); QUAD_OP("u128", (long double)uw);
            volatile double d=(double)sl; volatile float f=(float)si;
            QUAD_OP("fromf32", (long double)f); QUAD_OP("fromf64", (long double)d);
            volatile long double v=(long double)(int32_t)next() / 16.0L;
            INT_OP("toi32", int32_t, (int32_t)v); INT_OP("tou32", uint32_t, (uint32_t)(v < 0 ? -v : v));
            INT_OP("toi64", int64_t, (int64_t)v); INT_OP("tou64", uint64_t, (uint64_t)(v < 0 ? -v : v));
            INT_OP("toi128", __int128, (__int128)v); INT_OP("tou128", unsigned __int128, (unsigned __int128)(v < 0 ? -v : v));
        }
    }
    return ferror(stdout) ? 1 : 0;
}

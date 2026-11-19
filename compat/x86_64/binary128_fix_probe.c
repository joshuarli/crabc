#include <stdint.h>
#include <stdio.h>
#include <fenv.h>
typedef union {long double f; struct {uint64_t lo,hi;} u;} quad;
extern int32_t __fixtfsi(long double); extern uint32_t __fixunstfsi(long double);
extern int64_t __fixtfdi(long double); extern uint64_t __fixunstfdi(long double);
extern __int128 __fixtfti(long double); extern unsigned __int128 __fixunstfti(long double);
#define CASE(name,type) do {feclearexcept(FE_ALL_EXCEPT); type z=name(q.f); int f=fetestexcept(FE_ALL_EXCEPT); unsigned __int128 u=(unsigned __int128)z; printf(#name " %016llx%016llx %x\n",(unsigned long long)(u>>64),(unsigned long long)u,f);} while(0)
int main(void) {
 quad v[]={ {.u={0,0}}, {.u={0,0xbffe000000000000}}, {.u={0,0x3ffe000000000000}}, {.u={0,0x401f000000000000}}, {.u={0,0xc01f000000000000}}, {.u={0,0x407f000000000000}}, {.u={0,0xc07e000000000000}}, {.u={0,0x7fff000000000000}}, {.u={0,0xffff000000000000}}, {.u={0x1234,0x7fff800000000000}}, {.u={0x1234,0x7fff000000000000}} };
 for(unsigned i=0;i<sizeof v/sizeof *v;i++){quad q=v[i];printf("%u\n",i);CASE(__fixtfsi,int32_t);CASE(__fixunstfsi,uint32_t);CASE(__fixtfdi,int64_t);CASE(__fixunstfdi,uint64_t);CASE(__fixtfti,__int128);CASE(__fixunstfti,unsigned __int128);}
}

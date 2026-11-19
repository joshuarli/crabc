#include <stdint.h>
#include <fenv.h>
#include <stdio.h>
typedef union { long double f; struct { uint64_t lo,hi; } u; } quad;
#define DECL(name) extern int name(long double,long double);
DECL(__eqtf2) DECL(__netf2) DECL(__letf2) DECL(__lttf2) DECL(__getf2) DECL(__gttf2) DECL(__unordtf2)
#define TEST(name) do { feclearexcept(FE_ALL_EXCEPT); int r=name(a.f,b.f); int f=fetestexcept(FE_ALL_EXCEPT); printf(#name " %d %x\n",r,f); } while(0)
int main(void) {
  quad v[]={ {.u={0,0}}, {.u={0,0x3fff000000000000}}, {.u={2,0x7fff800000000000}}, {.u={3,0x7fff000000000000}} };
  for(unsigned i=0;i<4;i++) for(unsigned j=0;j<4;j++) {quad a=v[i],b=v[j]; printf("%u %u\n",i,j); TEST(__eqtf2); TEST(__netf2); TEST(__letf2); TEST(__lttf2); TEST(__getf2); TEST(__gttf2); TEST(__unordtf2);}
}

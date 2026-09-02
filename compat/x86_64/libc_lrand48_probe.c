/* Pinned-musl/x86 static legacy rand48 differential fixture. */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "requires native Linux/x86-64 LP64"
#endif
#ifndef CRABC_LRAND48_FREESTANDING
#include <errno.h>
#endif
#include <lrand48.h>
#include <stdint.h>

typedef long (*long0)(void); typedef long (*long1)(unsigned short *);
typedef double (*double0)(void); typedef double (*double1)(unsigned short *);
typedef void (*void1s)(unsigned short *); typedef void (*void1l)(long);
_Static_assert(__builtin_types_compatible_p(__typeof__(&lrand48), long0), "lrand48 ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&erand48), double1), "erand48 ABI");
_Static_assert(sizeof(long) == 8, "LP64 long");
static uint64_t next(unsigned short x[3], const unsigned short p[4]) { uint64_t v=x[0]|((uint64_t)x[1]<<16)|((uint64_t)x[2]<<32); uint64_t a=p[0]|((uint64_t)p[1]<<16)|((uint64_t)p[2]<<32); v=a*v+p[3]; x[0]=v; x[1]=v>>16; x[2]=v>>32; return v&0xffffffffffffULL; }
static int same3(const unsigned short a[3], const unsigned short b[3]) { return a[0]==b[0]&&a[1]==b[1]&&a[2]==b[2]; }
int crabc_x86_64_lrand48_probe(void) {
 unsigned short model[7]={0,0,0,0xe66d,0xdeec,5,0xb}, caller[3]={0,0,0}, caller_model[3]={0,0,0}, custom[7]={7,8,9,3,0,0,1}, fresh[3]={0x1234,0x5678,0x9abc}, second[3]={4,5,6}, before[3]; uint64_t v; unsigned short *old, *again;
#ifndef CRABC_LRAND48_FREESTANDING
 errno=E2BIG;
#endif
 srand48(1); model[0]=0x330e; model[1]=1; model[2]=0;
 v=next(model,model+3); if(lrand48()!=(long)(v>>17)) return 1;
 v=next(model,model+3); if(mrand48()!=(long)(int32_t)(v>>16)) return 2;
 v=next(model,model+3); if(drand48()!=((union {uint64_t u; double d;}){.u=0x3ff0000000000000ULL|(v<<4)}).d-1.0) return 3;
 v=next(caller_model,model+3); if(nrand48(caller)!=(long)(v>>17) || !same3(caller,caller_model)) return 4;
 v=next(caller_model,model+3); if(jrand48(caller)!=(long)(int32_t)(v>>16) || !same3(caller,caller_model)) return 5;
 v=next(caller_model,model+3); if(erand48(caller)!=((union {uint64_t u; double d;}){.u=0x3ff0000000000000ULL|(v<<4)}).d-1.0 || !same3(caller,caller_model)) return 6;
 before[0]=model[0]; before[1]=model[1]; before[2]=model[2]; old=seed48(fresh); if(!same3(old,before)) return 7; model[0]=fresh[0];model[1]=fresh[1];model[2]=fresh[2];
 again=seed48(second); if(again!=old || !same3(again,fresh)) return 8; model[0]=4;model[1]=5;model[2]=6;
 lcong48(custom); for(int i=0;i<7;i++) model[i]=custom[i]; v=next(model,model+3); if(lrand48()!=(long)(v>>17)) return 9;
 srand48(-1); model[0]=0x330e;model[1]=0xffff;model[2]=0xffff; v=next(model,model+3); if(lrand48()!=(long)(v>>17)) return 10;
#ifndef CRABC_LRAND48_FREESTANDING
 if(errno!=E2BIG) return 11;
#endif
 return 0;
}
#ifndef CRABC_LRAND48_FREESTANDING
int main(void) { return crabc_x86_64_lrand48_probe(); }
#endif

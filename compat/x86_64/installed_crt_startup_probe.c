#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

/* The same installed-header object is linked in every mode. Musl's omission
 * of main preinit is observed separately; it is not normalized away. */
static __thread int initial __attribute__((tls_model("initial-exec"))) = 17;
static __thread int zero __attribute__((tls_model("initial-exec")));
static int phase, preinitialized;
/* Addressable compiler protocol data selects musl's real guard initializer.
 * The pinned freestanding GCC specs disable generated stack protectors. */
extern uintptr_t __stack_chk_guard;
static void emit(char c) { if (write(1,&c,1)!=1) _Exit(90); }
static void state(void) {
    const unsigned char *random=(const unsigned char *)getauxval(AT_RANDOM);
    uintptr_t guard, expected=0;
    if (!random || !getenv("CRABC_STARTUP") || strcmp(getenv("CRABC_STARTUP"),"yes")) _Exit(91);
    for (unsigned i=0;i<sizeof expected;i++) expected|=(uintptr_t)random[i]<<(8*i);
    expected&=~(uintptr_t)0xff00;
    __asm__ volatile("mov %%fs:40,%0":"=r"(guard));
    if (!guard || guard!=expected || __stack_chk_guard!=expected || initial!=17 || zero!=0 || errno!=0) _Exit(92);
}
#ifndef EMPTY_ARRAYS
static void preinit(void) { state(); if (phase) _Exit(93); preinitialized=1; emit('P'); }
static void init(void) { state(); if (phase!=1) _Exit(94); phase=2; emit('C'); }
static void fini(void) { if (phase!=4) _Exit(95); phase=5; emit('F'); }
__attribute__((used,section(".preinit_array"))) static void (*const p)(void)=preinit;
__attribute__((used,section(".init_array"))) static void (*const i)(void)=init;
__attribute__((used,section(".fini_array"))) static void (*const f)(void)=fini;
#endif
__attribute__((used,noinline)) static void legacy_init(void) { state(); if (phase) _Exit(96); phase=1; emit('I'); }
__attribute__((used,noinline)) static void legacy_fini(void) {
    if (phase!=
#ifdef EMPTY_ARRAYS
        4
#else
        5
#endif
    ) _Exit(97);
    emit('L'); emit('\n');
}
__asm__(".pushsection .init,\"ax\",@progbits\ncall legacy_init\n.popsection\n"
        ".pushsection .fini,\"ax\",@progbits\ncall legacy_fini\n.popsection\n");
static void handler(void) { if (phase!=3) _Exit(98); phase=4; emit('A'); }

/* This observation reads only the exact initial graph's public ELF metadata.
 * It does not publish a loader pointer or call private loader callbacks. The
 * retained executable/relocation reader independently authenticates these
 * names, table shapes, and object identities. */
struct wire_state { unsigned handoffs, conventional; uintptr_t handoff, snapshot; };
static int wires(struct dl_phdr_info *info,size_t size,void *opaque) {
    (void)size;
    struct wire_state *s=opaque;
    const Elf64_Dyn *dyn=0;
    for (unsigned i=0;i<info->dlpi_phnum;i++) if (info->dlpi_phdr[i].p_type==PT_DYNAMIC)
        dyn=(const Elf64_Dyn *)(info->dlpi_addr+info->dlpi_phdr[i].p_vaddr);
    if (!dyn) return 0;
    const Elf64_Sym *syms=0; const char *strings=0; const Elf64_Rela *rela=0; size_t count=0;
    for (unsigned n=0;n<1024 && dyn[n].d_tag!=DT_NULL;n++) {
        uintptr_t p=info->dlpi_addr+dyn[n].d_un.d_ptr;
        if (dyn[n].d_tag==DT_SYMTAB) syms=(const Elf64_Sym *)p;
        if (dyn[n].d_tag==DT_STRTAB) strings=(const char *)p;
        if (dyn[n].d_tag==DT_RELA) rela=(const Elf64_Rela *)p;
        if (dyn[n].d_tag==DT_RELASZ) count=dyn[n].d_un.d_val/sizeof *rela;
    }
    if (!syms || !strings || !rela) return 0;
    if (count>32768) _Exit(99);
    for (size_t n=0;n<count;n++) {
        unsigned si=ELF64_R_SYM(rela[n].r_info);
        if (!si) continue;
        const char *name=strings+syms[si].st_name;
        int h=!strcmp(name,"__crabc_x86_64_owned_crt_handoff");
        int c=!strcmp(name,"__crabc_x86_64_loader_conventional_startup_v1");
        if (!h && !c) continue;
        if (ELF64_R_TYPE(rela[n].r_info)!=R_X86_64_GLOB_DAT || rela[n].r_addend
            || syms[si].st_info!=ELF64_ST_INFO(STB_WEAK,STT_OBJECT) || syms[si].st_shndx!=SHN_UNDEF) _Exit(100);
        uintptr_t value=*(const uintptr_t *)(info->dlpi_addr+rela[n].r_offset);
        if (h) { s->handoffs++; s->handoff=value; }
        else { s->conventional++; s->snapshot=value; }
    }
    return 0;
}
static void observe(const char *mode) {
    struct wire_state s={0};
    if (dl_iterate_phdr(wires,&s)) _Exit(101);
    if (!strcmp(mode,"owned")) {
        if (s.handoffs!=1 || !s.handoff || s.conventional!=1 || s.snapshot) _Exit(102);
        const uint64_t *q=(const uint64_t *)s.handoff;
        if (q[0]!=UINT64_C(0x43524142435f4831) || ((const uint32_t *)q)[2]!=1
            || ((const uint32_t *)q)[3]!=32 || !q[2] || !q[3]) _Exit(103);
        emit('O');
    } else if (!strcmp(mode,"conventional")) {
        if (s.handoffs || s.conventional!=1 || !s.snapshot) _Exit(104);
        const uint64_t *q=(const uint64_t *)s.snapshot; uintptr_t tp;
        __asm__ volatile("mov %%fs:0,%0":"=r"(tp));
        if (q[0]!=UINT64_C(0x43524142435f4331) || ((const uint32_t *)q)[2]!=1
            || ((const uint32_t *)q)[3]!=88 || ((const uint32_t *)q)[4]!=2
            || ((const uint32_t *)q)[5]!=1 || ((const unsigned char *)q)[24]!=2
            || q[4]!=tp || q[8]!=1 || !q[9] || !q[10]) _Exit(105);
        emit('V');
    } else if (!strcmp(mode,"default")) {
        if (s.handoffs!=1 || s.handoff || s.conventional) _Exit(106);
        emit('N');
    } else { if (s.handoffs || s.conventional) _Exit(107); emit('R'); }
}
int main(int argc,char **argv) {
    state();
    if (argc!=2 || phase!=
#ifdef EMPTY_ARRAYS
        1
#else
        2
#endif
    ) _Exit(108);
    void *allocation=malloc(31); if (!allocation) _Exit(109); free(allocation);
    if (strcmp(argv[1],"static")) observe(argv[1]); else emit('S');
    if (atexit(handler)) _Exit(110);
    phase=3; emit('M'); return 0;
}

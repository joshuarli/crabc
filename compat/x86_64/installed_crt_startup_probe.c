#define _GNU_SOURCE
#include <elf.h>
#include <errno.h>
#include <link.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>
#ifdef CRABC_HARDENED_PROBE
#include <pthread.h>
#include <signal.h>
#include <sys/wait.h>
#endif

/* The same installed-header object is linked in every mode. Dynamic entry
 * leaves main preinit uncalled; owned static entry still dispatches it. */
static __thread int initial __attribute__((tls_model("initial-exec"))) = 17;
static __thread int zero __attribute__((tls_model("initial-exec")));
static int phase, preinitialized;
/* Addressable compiler protocol data selects musl's real guard initializer.
 * The pinned freestanding GCC specs disable generated stack protectors. */
extern uintptr_t __stack_chk_guard;
static void emit(char c) { if (write(1,&c,1)!=1) _Exit(90); }
#ifdef CRABC_HARDENED_PROBE
static int stack_is_nonexecutable(void) {
    volatile unsigned char code[]={0xc3};
    pid_t child=fork();
    if (!child) { ((void (*)(void))(uintptr_t)code)(); _Exit(0); }
    int status=0;
    return child>0 && waitpid(child,&status,0)==child && WIFSIGNALED(status) && WTERMSIG(status)==SIGSEGV;
}
#endif
static void state(void) {
    const unsigned char *random=(const unsigned char *)getauxval(AT_RANDOM);
    uintptr_t guard, expected=0;
    if (!random || !getenv("CRABC_STARTUP") || strcmp(getenv("CRABC_STARTUP"),"yes")) _Exit(91);
    for (unsigned i=0;i<sizeof expected;i++) expected|=(uintptr_t)random[i]<<(8*i);
    expected&=~(uintptr_t)0xff00;
    __asm__ volatile("mov %%fs:40,%0":"=r"(guard));
    if (!guard || guard!=expected || __stack_chk_guard!=expected || initial!=17 || zero!=0 || errno!=0) _Exit(92);
#ifdef CRABC_HARDENED_PROBE
    if (!stack_is_nonexecutable()) _Exit(114);
#endif
}
#ifdef CRABC_HARDENED_PROBE
static void *worker(void *argument) { state(); return argument; }
#endif
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
/* The wire-parser source fixture includes this translation unit to exercise a
 * malformed in-memory main ELF. It deliberately omits only process-startup
 * sections; installed probes never define this harness-only macro. */
#ifndef CRABC_STARTUP_PROBE_WIRE_HARNESS
__asm__(".pushsection .init,\"ax\",@progbits\ncall legacy_init\n.popsection\n"
        ".pushsection .fini,\"ax\",@progbits\ncall legacy_fini\n.popsection\n");
#endif
static void handler(void) { if (phase!=3) _Exit(98); phase=4; emit('A'); }

/* This observation reads only the exact initial graph's public ELF metadata.
 * It does not publish a loader pointer or call private loader callbacks. The
 * retained executable/relocation reader independently authenticates these
 * names, table shapes, and object identities. */
struct loader_tls_descriptor {
    uint64_t magic;
    uint32_t version, abi_size, process_mode, owner;
    _Atomic unsigned char state;
    unsigned char reserved[7];
    const unsigned char *thread_pointer;
    const uintptr_t *dtv;
    size_t dtv_words, module_count;
    uint64_t generation;
};
_Static_assert(sizeof(struct loader_tls_descriptor)==72,"descriptor size");
_Static_assert(_Alignof(struct loader_tls_descriptor)==8,"descriptor alignment");

/* The merged link binds the conventional record in-image. Its 88-byte
 * payload is the private loader contract; validate every field rather than
 * accepting a transcript as proof that select() did not fall back. */
struct conventional_snapshot {
    uint64_t magic;
    uint32_t version, abi_size, process_mode, owner;
    _Atomic unsigned char state;
    unsigned char reserved[7];
    const unsigned char *thread_pointer;
    const uintptr_t *dtv;
    size_t dtv_words, module_count;
    uint64_t generation;
    uintptr_t run_initial, process_fini;
};
_Static_assert(sizeof(struct conventional_snapshot)==88,"conventional size");
_Static_assert(_Alignof(struct conventional_snapshot)==8,"conventional alignment");

static int conventional_record_valid(const struct conventional_snapshot *q,
                                     uintptr_t thread_pointer, uintptr_t dtv, int owned) {
    if (!q || (uintptr_t)q%_Alignof(struct conventional_snapshot)) return 0;
    unsigned char state=atomic_load_explicit(&q->state,memory_order_acquire);
    if (q->magic!=UINT64_C(0x43524142435f4331) || q->version!=1 || q->abi_size!=88
        || q->owner!=1 || memcmp(q->reserved,(unsigned char[7]){0},7) || q->generation!=1) return 0;
    /* An owned main publishes only the decision, so the conventional
     * coordinates legitimately stay zero until select() takes that path. */
    if (owned) return q->process_mode==3 && state==3;
    if (q->process_mode!=2 || state!=2 || !q->run_initial || !q->process_fini
        || !q->thread_pointer || (uintptr_t)q->thread_pointer%sizeof(uintptr_t)
        || !q->dtv || (uintptr_t)q->dtv%sizeof(uintptr_t)
        || !q->module_count || q->module_count==SIZE_MAX
        || q->dtv_words<q->module_count+1 || q->dtv[0]!=q->module_count) return 0;
    return (uintptr_t)q->thread_pointer==thread_pointer && (uintptr_t)q->dtv==dtv;
}

static int conventional_record_base(struct dl_phdr_info *info,size_t size,void *opaque) {
    (void)size;
    uintptr_t *base=opaque;
    if (!info->dlpi_name || !info->dlpi_name[0]) return 0;
    size_t length=strlen(info->dlpi_name);
    if (length<7 || strcmp(info->dlpi_name+length-7,"libc.so")) return 0;
    if (*base && *base!=(uintptr_t)info->dlpi_addr) _Exit(115);
    *base=(uintptr_t)info->dlpi_addr;
    return 0;
}

static const struct conventional_snapshot *conventional_record(void) {
    const char *text=getenv("CRABC_CONVENTIONAL_RECORD_OFFSET");
    if (!text || !*text) return 0;
    uintptr_t offset=0;
    for (const char *p=text;*p;++p) {
        int digit=*p>='0' && *p<='9' ? *p-'0' : *p>='a' && *p<='f' ? *p-'a'+10 : -1;
        if (digit<0) _Exit(115);
        offset=(offset<<4)|(uintptr_t)digit;
    }
    uintptr_t base=0;
    if (dl_iterate_phdr(conventional_record_base,&base) || !base) _Exit(115);
    const struct conventional_snapshot *record=(const void *)(base+offset);
    if ((uintptr_t)record % _Alignof(struct conventional_snapshot)) _Exit(115);
    return record;
}

struct wire_state {
    unsigned main_images, handoffs, conventional, descriptors;
    uintptr_t handoff, snapshot, descriptor;
};
static int wires(struct dl_phdr_info *info,size_t size,void *opaque) {
    (void)size;
    struct wire_state *s=opaque;
    /* Every final application is linked from this translation unit. Exactly
     * its executable PT_LOAD contains the local `wires` function, whether it
     * began through the kernel or a direct loader. This physical anchor does
     * not depend on a callback display name or loader-specific auxv rewriting.
     * The private resolver writes handoff and descriptor slots only there.
     * The conventional record is bound in-image by the merged link, so a
     * conventional main selects its READY record without an executable slot.
     * Reaching the conventional transcript proves that record and lifecycle
     * were accepted; an owned transcript proves the owned state was published
     * and no executable conventional slot remained. */
    if (!info->dlpi_phdr) _Exit(99);
    uintptr_t observer=(uintptr_t)(void *)&wires; unsigned observer_segments=0;
    for (unsigned i=0;i<info->dlpi_phnum;i++) {
        const Elf64_Phdr *program=&info->dlpi_phdr[i];
        if (program->p_type!=PT_LOAD || !(program->p_flags&PF_X)) continue;
        uintptr_t base=(uintptr_t)info->dlpi_addr,offset=(uintptr_t)program->p_vaddr,size=(uintptr_t)program->p_memsz;
        if (offset>UINTPTR_MAX-base) _Exit(99); uintptr_t start=base+offset;
        if (size>UINTPTR_MAX-start) _Exit(99);
        if (observer>=start && observer-start<size && ++observer_segments!=1) _Exit(99);
    }
    int main_image=observer_segments==1;
    if (main_image && ++s->main_images!=1) _Exit(99);
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
    if (count>32768) _Exit(100);
    for (size_t n=0;n<count;n++) {
        unsigned si=ELF64_R_SYM(rela[n].r_info);
        if (!si) continue;
        const char *name=strings+syms[si].st_name;
        int h=main_image && !strcmp(name,"__crabc_x86_64_owned_crt_handoff");
        int c=!strcmp(name,"__crabc_x86_64_loader_conventional_startup_v1");
        int d=main_image && !strcmp(name,"__crabc_x86_64_loader_tls_runtime_v1");
        if (!h && !c && !d) continue;
        if (ELF64_R_TYPE(rela[n].r_info)!=R_X86_64_GLOB_DAT || rela[n].r_addend
            || syms[si].st_shndx!=SHN_UNDEF) _Exit(101);
        uintptr_t value=*(const uintptr_t *)(info->dlpi_addr+rela[n].r_offset);
        if (h) {
            if (syms[si].st_info!=ELF64_ST_INFO(STB_WEAK,STT_OBJECT)
                || ELF64_ST_VISIBILITY(syms[si].st_other)!=STV_DEFAULT) _Exit(102);
            s->handoffs++; s->handoff=value;
        }
        else if (c) {
            if (syms[si].st_info!=ELF64_ST_INFO(STB_WEAK,STT_OBJECT)) _Exit(103);
            s->conventional++; s->snapshot=value;
        } else {
            if (syms[si].st_info!=ELF64_ST_INFO(STB_WEAK,STT_NOTYPE)
                || ELF64_ST_VISIBILITY(syms[si].st_other)!=STV_DEFAULT) _Exit(104);
            s->descriptors++; s->descriptor=value;
        }
    }
    return 0;
}
static void observe(const char *mode) {
    struct wire_state s={0};
    if (dl_iterate_phdr(wires,&s) || s.main_images!=1) _Exit(104);
    if (!strcmp(mode,"owned")) {
        if (s.handoffs!=1 || !s.handoff || s.conventional!=0 || s.snapshot
            || s.descriptors!=1 || !s.descriptor) _Exit(105);
        const uint64_t *q=(const uint64_t *)s.handoff;
        if (q[0]!=UINT64_C(0x43524142435f4831) || ((const uint32_t *)q)[2]!=
#ifdef CRABC_HARDENED_PROBE
            2
#else
            1
#endif
            || ((const uint32_t *)q)[3]!=32 || !q[2] || !q[3]) _Exit(106);
        const struct loader_tls_descriptor *d=(const struct loader_tls_descriptor *)s.descriptor;
        uintptr_t tp,dtv;
        __asm__ volatile("mov %%fs:0,%0":"=r"(tp));
        __asm__ volatile("mov %%fs:8,%0":"=r"(dtv));
        if ((uintptr_t)d%_Alignof(struct loader_tls_descriptor)
            || d->magic!=UINT64_C(0x43524142435f5451) || d->version!=1 || d->abi_size!=72
            || d->process_mode!=2 || d->owner!=1 || atomic_load_explicit(&d->state,memory_order_acquire)!=2
            || memcmp(d->reserved,(unsigned char[7]){0},7) || d->generation!=1
            || !d->thread_pointer || !d->dtv || (uintptr_t)d->thread_pointer%sizeof(uintptr_t)
            || (uintptr_t)d->dtv%sizeof(uintptr_t) || !d->module_count
            || d->module_count==SIZE_MAX || d->dtv_words<d->module_count+1
            || (uintptr_t)d->thread_pointer!=tp || (uintptr_t)d->dtv!=dtv
            || d->dtv[0]!=d->module_count) _Exit(107);
        if (!conventional_record_valid(conventional_record(),tp,dtv,1)) _Exit(116);
        emit('O');
    } else if (!strcmp(mode,"conventional")) {
        if (s.handoffs || s.conventional || s.descriptors) _Exit(108);
        uintptr_t tp,dtv;
        __asm__ volatile("mov %%fs:0,%0":"=r"(tp));
        __asm__ volatile("mov %%fs:8,%0":"=r"(dtv));
        if (!conventional_record_valid(conventional_record(),tp,dtv,0)) _Exit(117);
        emit('V');
    } else if (!strcmp(mode,"default")) {
        if (s.handoffs!=1 || s.handoff || s.conventional || s.descriptors) _Exit(110);
        emit('N');
    } else { if (s.handoffs || s.conventional || s.descriptors) _Exit(111); emit('R'); }
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
    volatile unsigned __int128 numerator=((unsigned __int128)1<<100)|7;
    volatile unsigned __int128 denominator=3;
    if (numerator/denominator!=((((unsigned __int128)1<<100)|7)/3)) _Exit(112);
    void *allocation=malloc(31); if (!allocation) _Exit(109); free(allocation);
#ifdef CRABC_HARDENED_PROBE
    pthread_t thread; void *result=0; int token=7;
    if (pthread_create(&thread,0,worker,&token) || pthread_join(thread,&result) || result!=&token) _Exit(113);
#endif
    if (strcmp(argv[1],"static")) observe(argv[1]); else emit('S');
    if (atexit(handler)) _Exit(110);
    phase=3; emit('M'); return 0;
}

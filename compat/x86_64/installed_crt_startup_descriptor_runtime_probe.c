/*
 * Freestanding selected-attachment observer for RuntimeV1 descriptor admission.
 *
 * This source supplies only controlled record/TCB/DTV storage.  Each final
 * static test links the admitted crabc-dynamic-attach.o directly; it neither
 * rebuilds that object nor models a selected main image or loader transport.
 * The raw ARCH_SET_FS and exit calls keep the controlled prefix independent of
 * host libc or musl TLS layout.  The process exits immediately after changing
 * FS, so no host TLS code observes that test-only base.
 */
typedef unsigned long usize;

enum {
    RUNTIME_V1_READY = 2,
    RUNTIME_V1_VALUE_CASES = 21,
};

struct runtime_v1 {
    unsigned long magic;
    unsigned version;
    unsigned abi_size;
    unsigned process_mode;
    unsigned owner;
    unsigned char state;
    unsigned char reserved[7];
    void *thread_pointer;
    usize *dtv;
    usize dtv_words;
    usize module_count;
    usize generation;
};

_Static_assert(sizeof(struct runtime_v1) == 72, "RuntimeV1 size");
_Static_assert(_Alignof(struct runtime_v1) == 8, "RuntimeV1 alignment");

extern int __crabc_x86_loader_tls_runtime_v1_attach(void);

#if !defined(CRABC_RUNTIME_CASE_ABSENT) && !defined(CRABC_RUNTIME_CASE_UNALIGNED_RECORD)
struct runtime_v1 __crabc_x86_64_loader_tls_runtime_v1;
static usize runtime_dtv[2];
static usize runtime_tcb[2];
#endif

#if defined(CRABC_RUNTIME_CASE_UNALIGNED_RECORD)
/* Keep the backing storage through -O2 so the alias remains a defined record. */
static unsigned char runtime_unaligned_record[73] __attribute__((used, aligned(8)));
__asm__(
    ".globl __crabc_x86_64_loader_tls_runtime_v1\n"
    ".set __crabc_x86_64_loader_tls_runtime_v1, runtime_unaligned_record + 1\n"
);
#endif

static long install_fs(void *address) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(158L), "D"(0x1002L), "S"(address)
                     : "rcx", "r11", "memory");
    return result;
}

#if defined(CRABC_RUNTIME_CASE_ABSENT)
int main(void) {
    return __crabc_x86_loader_tls_runtime_v1_attach() == -1 ? 0 : 1;
}
#elif defined(CRABC_RUNTIME_CASE_UNALIGNED_RECORD)
int main(void) {
    return __crabc_x86_loader_tls_runtime_v1_attach() == -1 ? 0 : 1;
}
#else
static struct runtime_v1 *record(void) {
    return &__crabc_x86_64_loader_tls_runtime_v1;
}

static int set_valid_record(void) {
    struct runtime_v1 *value = record();
    value->magic = 0x43524142435f5451UL;
    value->version = 1;
    value->abi_size = 72;
    value->process_mode = 2;
    value->owner = 1;
    value->reserved[0] = 0;
    value->thread_pointer = runtime_tcb;
    value->dtv = runtime_dtv;
    value->dtv_words = 2;
    value->module_count = 1;
    value->generation = 1;
    runtime_tcb[0] = (usize)runtime_tcb;
    runtime_tcb[1] = (usize)runtime_dtv;
    runtime_dtv[0] = 1;
    __atomic_store_n(&value->state, RUNTIME_V1_READY, __ATOMIC_RELEASE);
    return __crabc_x86_loader_tls_runtime_v1_attach() == 0 ? 0 : 1;
}

static void apply_value_case(unsigned test) {
    struct runtime_v1 *value = record();
    switch (test) {
    case 0: value->magic = 0; break;                         /* bad-magic */
    case 1: value->version = 0; break;                       /* bad-version */
    case 2: value->abi_size = 0; break;                      /* bad-abi-size */
    case 3: value->process_mode = 0; break;                  /* bad-mode */
    case 4: value->owner = 0; break;                         /* bad-owner */
    case 5: __atomic_store_n(&value->state, 0, __ATOMIC_RELEASE); break; /* unpublished */
    case 6: __atomic_store_n(&value->state, 1, __ATOMIC_RELEASE); break; /* publishing */
    case 7: __atomic_store_n(&value->state, 3, __ATOMIC_RELEASE); break; /* unexpected-state */
    case 8: value->reserved[0] = 1; break;                   /* nonzero-reserved */
    case 9: value->generation = 0; break;                    /* bad-generation */
    case 10: value->thread_pointer = 0; break;               /* null-tp */
    case 11: value->dtv = 0; break;                          /* null-dtv */
    case 12: value->thread_pointer = (void *)((usize)runtime_tcb + 1); break; /* unaligned-tp */
    case 13: value->dtv = (usize *)((usize)runtime_dtv + 1); break; /* unaligned-dtv */
    case 14: value->module_count = 0; runtime_dtv[0] = 0; break; /* zero-module-count */
    case 15: value->dtv_words = 1; break;                    /* short-dtv-words */
    case 16:                                                       /* module-count-overflow */
        value->module_count = ~(usize)0;
        value->dtv_words = ~(usize)0;
        runtime_dtv[0] = ~(usize)0;
        break;
    case 17: value->thread_pointer = runtime_dtv; break;     /* fs-mismatch */
    case 18: runtime_tcb[0] = 0; break;                      /* self-word-mismatch */
    case 19: runtime_tcb[1] = 0; break;                      /* dtv-slot-mismatch */
    case 20: runtime_dtv[0] = 0; break;                      /* dtv-count-mismatch */
    }
}

int main(void) {
    if (install_fs(runtime_tcb) != 0) {
        return 10;
    }
    for (unsigned test = 0; test < RUNTIME_V1_VALUE_CASES; ++test) {
        if (set_valid_record() != 0) {
            return 20 + (int)test;
        }
        apply_value_case(test);
        if (__crabc_x86_loader_tls_runtime_v1_attach() != -1) {
            return 50 + (int)test;
        }
    }
    return 0;
}
#endif

__asm__(
    ".text\n"
    ".global _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "xor %ebp,%ebp\n"
    "and $-16,%rsp\n"
    "call main\n"
    "mov %eax,%edi\n"
    "mov $60,%eax\n"
    "syscall\n"
    "ud2\n"
    ".size _start,.-_start\n"
);

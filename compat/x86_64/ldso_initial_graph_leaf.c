int leaf_data = 40;
int leaf_initializer_state;
static int leaf_private = 1;
static int *leaf_private_pointer = &leaf_private;

#if defined(CRABC_RELR_RECORD_OVER_CAP)
/*
 * This runner-only negative fixture spreads 513 relative-pointer words 512
 * bytes apart. Each word therefore needs a direct RELR record rather than a
 * bitmap bit. It proves that the private interpreter rejects an over-cap
 * table before it can turn a bounded test artifact into a general loader.
 *
 * The range initializer is a GNU C fixture convenience only; this file is
 * compiled by the native GCC evidence runner, never installed as a header or
 * selected as a public C source surface.
 */
enum { LEAF_RELR_SLOT_COUNT = 513 };
struct leaf_sparse_relative_slot {
    int *volatile pointer;
    unsigned char spacing[504];
};
static struct leaf_sparse_relative_slot leaf_relative_slots[LEAF_RELR_SLOT_COUNT] = {
    [0 ... LEAF_RELR_SLOT_COUNT - 1] = { .pointer = &leaf_private },
};
#elif defined(CRABC_RELR_TARGET_OVER_CAP)
/*
 * This separate runner-only negative fixture keeps 513 pointer words
 * adjacent, forcing the linker to exercise the compact direct-plus-bitmap
 * encoding while exceeding only the destination cap. Pinned musl accepts the
 * graph; this private interpreter deliberately rejects it before writes.
 */
enum { LEAF_RELR_SLOT_COUNT = 513 };
static int *volatile leaf_relative_slots[LEAF_RELR_SLOT_COUNT] = {
    [0 ... LEAF_RELR_SLOT_COUNT - 1] = &leaf_private,
};
#else
/*
 * The packed-RELR fixture needs a direct entry followed by a bitmap run, not
 * merely one table tag. Keep these adjacent volatile pointer slots observable
 * at runtime so the linker retains their relative relocations.
 */
enum { LEAF_RELR_SLOT_COUNT = 8 };
static int *volatile leaf_relative_slots[] = {
    &leaf_private,
    &leaf_private,
    &leaf_private,
    &leaf_private,
    &leaf_private,
    &leaf_private,
    &leaf_private,
    &leaf_private,
};
#endif

/* This dependency object must be sealed by PT_GNU_RELRO after relocation. */
static int *leaf_relro_pointer __attribute__((section(".data.rel.ro"))) = &leaf_private;

__attribute__((constructor)) static void leaf_initializer(void) {
    leaf_initializer_state = 1;
}

int leaf_value(void) {
    int relative_sum = 0;
#if defined(CRABC_RELR_RECORD_OVER_CAP)
    for (unsigned index = 0; index < LEAF_RELR_SLOT_COUNT; ++index) {
        relative_sum += *leaf_relative_slots[index].pointer;
    }
#else
    for (unsigned index = 0; index < sizeof(leaf_relative_slots) / sizeof(leaf_relative_slots[0]); ++index) {
        relative_sum += *leaf_relative_slots[index];
    }
#endif
    return leaf_data + *leaf_private_pointer - 1 + relative_sum - LEAF_RELR_SLOT_COUNT;
}

static long syscall1(long number, long argument) {
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(argument) : "rcx", "r11", "memory");
    return result;
}

static long syscall4(long number, long one, long two, long three, long four) {
    long result;
    register long r10 __asm__("r10") = four;
    __asm__ volatile("syscall" : "=a"(result) : "a"(number), "D"(one), "S"(two), "d"(three), "r"(r10) : "rcx", "r11", "memory");
    return result;
}

int leaf_relro_write_signal(void) {
    long child = syscall1(57, 0); /* fork */
    if (child == 0) {
        int *volatile *slot = (int *volatile *)(void *)&leaf_relro_pointer;
        *slot = &leaf_private;
        return 1;
    }
    if (child < 0) return 0;
    int status = 0;
    if (syscall4(61, child, (long)&status, 0, 0) != child) return 0; /* wait4 */
    return status & 0x7f;
}

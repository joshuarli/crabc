#include <stdint.h>
#include <sys/mman.h>

struct crabc_unwind_exception {
    uint64_t exception_class;
    void (*exception_cleanup)(int, struct crabc_unwind_exception *);
    uintptr_t private_words[8];
};

extern int crabc_guarded_cfi_call(void *guard, int malformed,
                                  struct crabc_unwind_exception *exception);

/* The saved instruction pointer is read through DW_CFA_expression. RBX names
 * the ordinary stack slot in the control and an unreadable page in the bad
 * case. Both cases use the same real DSO FDE and call site. */
__asm__(
    ".text\n"
    ".globl crabc_guarded_cfi_call\n"
    ".type crabc_guarded_cfi_call,@function\n"
    "crabc_guarded_cfi_call:\n"
    ".cfi_startproc\n"
    "pushq %rbx\n"
    ".cfi_def_cfa_offset 16\n"
    ".cfi_offset %rbx, -16\n"
    "leaq 8(%rsp), %rbx\n"
    "testl %esi, %esi\n"
    "je 1f\n"
    "movq %rdi, %rbx\n"
    "1:\n"
    ".cfi_escape 0x10, 0x10, 0x02, 0x73, 0x00\n"
    "movq %rdx, %rdi\n"
    "call _Unwind_RaiseException@PLT\n"
    "popq %rbx\n"
    ".cfi_def_cfa_offset 8\n"
    "ret\n"
    ".cfi_endproc\n"
);

int crabc_guarded_dso_cfi(int malformed) {
    struct crabc_unwind_exception exception = {0};
    void *guard = mmap(0, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard == MAP_FAILED) return -1;
    int reason = crabc_guarded_cfi_call(guard, malformed, &exception);
    if (munmap(guard, 4096) != 0) return -2;
    return reason;
}

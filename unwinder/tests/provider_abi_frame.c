/* The opaque context pointer and integer reason codes use the System V
 * x86-64 unwind ABI. No compiler unwinder header or runtime is required. */
#include <stdint.h>

struct unwind_context;
typedef int (*trace_callback)(struct unwind_context *, void *);
extern int _Unwind_Backtrace(trace_callback, void *);
extern uintptr_t _Unwind_GetIP(struct unwind_context *);

static int count_frame(struct unwind_context *context, void *data)
{
    if (_Unwind_GetIP(context)) ++*(unsigned *)data;
    return 0; /* _URC_NO_REASON: continue walking ordinary compiler frames. */
}

__attribute__((noinline)) int crabc_provider_abi_walk(void)
{
    /* Keep actual SysV callee-saved registers live across the provider's
     * capture trampoline. The empty asm operands prevent constant folding
     * of the post-call comparisons without introducing another runtime. */
    register uintptr_t saved_rbx __asm__("rbx") = UINT64_C(0x1122334455667788);
    register uintptr_t saved_r12 __asm__("r12") = UINT64_C(0x2233445566778899);
    register uintptr_t saved_r13 __asm__("r13") = UINT64_C(0x33445566778899aa);
    register uintptr_t saved_r14 __asm__("r14") = UINT64_C(0x445566778899aabb);
    register uintptr_t saved_r15 __asm__("r15") = UINT64_C(0x5566778899aabbcc);
    __asm__ volatile ("" : "+r"(saved_rbx), "+r"(saved_r12), "+r"(saved_r13),
                          "+r"(saved_r14), "+r"(saved_r15));
    unsigned frames = 0;
    int reason = _Unwind_Backtrace(count_frame, &frames);
    __asm__ volatile ("" : "+r"(saved_rbx), "+r"(saved_r12), "+r"(saved_r13),
                          "+r"(saved_r14), "+r"(saved_r15));
    return reason == 5 && frames >= 3
        && saved_rbx == UINT64_C(0x1122334455667788)
        && saved_r12 == UINT64_C(0x2233445566778899)
        && saved_r13 == UINT64_C(0x33445566778899aa)
        && saved_r14 == UINT64_C(0x445566778899aabb)
        && saved_r15 == UINT64_C(0x5566778899aabbcc) ? 0 : 1; /* _URC_END_OF_STACK */
}

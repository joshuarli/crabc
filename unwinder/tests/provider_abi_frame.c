/* The opaque context pointer and integer reason codes use the System V
 * x86-64 and AArch64 unwind ABIs. No compiler unwinder header or runtime is required. */
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
    /* Keep actual ABI callee-saved registers live across the provider's
     * capture trampoline. The empty asm operands prevent constant folding
     * of the post-call comparisons without introducing another runtime. */
#if defined(__aarch64__)
    register uintptr_t saved_rbx __asm__("x19") = UINT64_C(0x1122334455667788);
    register uintptr_t saved_r12 __asm__("x20") = UINT64_C(0x2233445566778899);
    register uintptr_t saved_r13 __asm__("x21") = UINT64_C(0x33445566778899aa);
    register uintptr_t saved_r14 __asm__("x22") = UINT64_C(0x445566778899aabb);
    register uintptr_t saved_r15 __asm__("x23") = UINT64_C(0x5566778899aabbcc);
    register uintptr_t saved_x24 __asm__("x24") = 24;
    register uintptr_t saved_x25 __asm__("x25") = 25;
    register uintptr_t saved_x26 __asm__("x26") = 26;
    register uintptr_t saved_x27 __asm__("x27") = 27;
    register uintptr_t saved_x28 __asm__("x28") = 28;
    register double saved_d8 __asm__("d8") = 8.0;
    register double saved_d9 __asm__("d9") = 9.0;
    register double saved_d10 __asm__("d10") = 10.0;
    register double saved_d11 __asm__("d11") = 11.0;
    register double saved_d12 __asm__("d12") = 12.0;
    register double saved_d13 __asm__("d13") = 13.0;
    register double saved_d14 __asm__("d14") = 14.0;
    register double saved_d15 __asm__("d15") = 15.0;
#else
    register uintptr_t saved_rbx __asm__("rbx") = UINT64_C(0x1122334455667788);
    register uintptr_t saved_r12 __asm__("r12") = UINT64_C(0x2233445566778899);
    register uintptr_t saved_r13 __asm__("r13") = UINT64_C(0x33445566778899aa);
    register uintptr_t saved_r14 __asm__("r14") = UINT64_C(0x445566778899aabb);
    register uintptr_t saved_r15 __asm__("r15") = UINT64_C(0x5566778899aabbcc);
#endif
#if defined(__aarch64__)
    __asm__ volatile ("" : "+r"(saved_x24), "+r"(saved_x25), "+r"(saved_x26), "+r"(saved_x27), "+r"(saved_x28),
                          "+w"(saved_d8), "+w"(saved_d9), "+w"(saved_d10), "+w"(saved_d11), "+w"(saved_d12), "+w"(saved_d13), "+w"(saved_d14), "+w"(saved_d15));
#endif
    __asm__ volatile ("" : "+r"(saved_rbx), "+r"(saved_r12), "+r"(saved_r13),
                          "+r"(saved_r14), "+r"(saved_r15));
    unsigned frames = 0;
    int reason = _Unwind_Backtrace(count_frame, &frames);
#if defined(__aarch64__)
    __asm__ volatile ("" : "+r"(saved_x24), "+r"(saved_x25), "+r"(saved_x26), "+r"(saved_x27), "+r"(saved_x28),
                          "+w"(saved_d8), "+w"(saved_d9), "+w"(saved_d10), "+w"(saved_d11), "+w"(saved_d12), "+w"(saved_d13), "+w"(saved_d14), "+w"(saved_d15));
#endif
    __asm__ volatile ("" : "+r"(saved_rbx), "+r"(saved_r12), "+r"(saved_r13),
                          "+r"(saved_r14), "+r"(saved_r15));
#if defined(__aarch64__)
    if (saved_x24 != 24 || saved_x25 != 25 || saved_x26 != 26 || saved_x27 != 27 || saved_x28 != 28 || saved_d8 != 8.0 || saved_d9 != 9.0 || saved_d10 != 10.0 || saved_d11 != 11.0 || saved_d12 != 12.0 || saved_d13 != 13.0 || saved_d14 != 14.0 || saved_d15 != 15.0) return 1;
#endif
    return reason == 5 && frames >= 3
        && saved_rbx == UINT64_C(0x1122334455667788)
        && saved_r12 == UINT64_C(0x2233445566778899)
        && saved_r13 == UINT64_C(0x33445566778899aa)
        && saved_r14 == UINT64_C(0x445566778899aabb)
        && saved_r15 == UINT64_C(0x5566778899aabbcc) ? 0 : 1; /* _URC_END_OF_STACK */
}

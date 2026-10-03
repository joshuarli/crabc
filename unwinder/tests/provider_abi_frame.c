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
    unsigned frames = 0;
    int reason = _Unwind_Backtrace(count_frame, &frames);
    return reason == 5 && frames >= 3 ? 0 : 1; /* _URC_END_OF_STACK */
}

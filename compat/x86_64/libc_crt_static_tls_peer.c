/* Second translation-unit TLS input for the rcrt1 -> libc composition fixture. */

#include <stdint.h>

enum { tls_alignment = 4096 };

__thread int crabc_crt_peer_initial = 0x2468ace0;
__thread int crabc_crt_peer_tbss;
__thread unsigned char crabc_crt_peer_alignment __attribute__((aligned(tls_alignment))) = 0x6b;

uintptr_t crabc_crt_peer_alignment_address(void)
{
    return (uintptr_t)&crabc_crt_peer_alignment;
}

#ifdef CRABC_STATIC_STACK_GUARD
/* GCC's per-function setting exercises real compiler-generated checks even
 * when the surrounding bootstrap fixture intentionally disables them. */
__attribute__((noinline, optimize("stack-protector-all")))
int crabc_crt_guarded_call(int corrupt)
{
    volatile unsigned char bytes[32];
    bytes[0] = 42;
    if (corrupt)
        __asm__ volatile("xorq $1, %%fs:40" ::: "memory");
    return bytes[0];
}
#endif

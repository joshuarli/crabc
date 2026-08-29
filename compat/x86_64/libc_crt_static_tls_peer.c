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

/* Peer translation unit for Static Initial TLS v1 evidence.
 *
 * Keeping these TLS definitions outside the primary probe proves that the
 * retained final-executable PT_TLS template is not a hard-coded errno layout
 * or one-object approximation. The candidate is a static non-PIE executable,
 * so these use direct x86 local-exec accesses rather than a resolver.
 */

#include <stdint.h>

__thread int peer_initial_tls_value = 0x2a4b6c7d;
__thread int peer_tbss;
__thread unsigned char peer_high_alignment_tbss[32]
    __attribute__((aligned(4096)));

int *peer_initial_tls_value_location(void)
{
    return &peer_initial_tls_value;
}

int *peer_tbss_location(void)
{
    return &peer_tbss;
}

unsigned char *peer_high_alignment_tbss_location(void)
{
    return peer_high_alignment_tbss;
}

uintptr_t peer_high_alignment_address(void)
{
    return (uintptr_t)peer_high_alignment_tbss;
}

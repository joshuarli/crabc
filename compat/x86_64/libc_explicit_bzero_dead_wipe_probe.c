/* Optimized dead-local explicit_bzero retention witness.
 *
 * No later C read observes secret. The selected wipe must still remain in the
 * optimized final code; the runner audits its disassembly rather than treating
 * this zero exit status as proof of non-elision.
 */

#define _GNU_SOURCE 1

#include <string.h>

__attribute__((noinline, used))
void crabc_x86_64_explicit_bzero_dead_wipe(void)
{
    unsigned char secret[64];
    size_t index;

    for (index = 0; index < sizeof(secret); ++index)
        secret[index] = (unsigned char)(0x31U + index * 17U);
    explicit_bzero(secret, sizeof(secret));
}

#ifndef CRABC_EXPLICIT_BZERO_DEAD_WIPE_FREESTANDING
int main(void)
{
    crabc_x86_64_explicit_bzero_dead_wipe();
    return 0;
}
#endif

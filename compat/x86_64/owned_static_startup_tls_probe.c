/* Static TLS v1 process-main installation fixture.
 *
 * The ordinary static product links this tiny TLS program only to prove that
 * the initial thread's block is part of the executable image: installing it
 * must not map memory, its `%fs` base must lie in a writable PT_LOAD, and the
 * linked alignment must survive the in-image placement. Selected workers and
 * templates too large for the in-image storage keep their private mappings
 * and are covered by the sibling TLS probe.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "this fixture requires native Linux/x86-64 LP64"
#endif

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

enum { tls_alignment = 64 };

__thread unsigned long initial_tls_probe;
__thread unsigned char initial_tls_alignment_probe[8]
    __attribute__((aligned(tls_alignment)));

int main(void)
{
    if (errno != 0 || initial_tls_probe != 0 || initial_tls_alignment_probe[0] != 0)
        return 1;
    initial_tls_probe = 1;
    initial_tls_alignment_probe[0] = 0x5a;
    if (initial_tls_probe != 1 || initial_tls_alignment_probe[0] != 0x5a)
        return 2;
    if (((uintptr_t)&initial_tls_alignment_probe & (tls_alignment - 1)) != 0)
        return 3;
    return write(1, "hi\n", 3) == 3 ? 0 : 3;
}

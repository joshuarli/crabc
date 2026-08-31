/* Static Linux/x86-64 selected umask C ABI and behavior fixture.
 *
 * One project-header C body first executes through pinned musl 1.2.6 and then
 * through a `--gc-sections` true-static crabc archive candidate. It observes
 * only the direct process-local mask exchange from musl's `src/stat/umask.c`:
 * each call returns the prior unsigned 32-bit mode and changes the inherited
 * mask for this fixture process only. The fixture restores its initial mask
 * before return. It does not create files, observe kernel-applied creation
 * modes, add an errno/TLS seam, or select process lifecycle policy.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/stat.h>
#include <sys/syscall.h>

typedef mode_t (*umask_signature)(mode_t);

_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4 &&
    (mode_t)-1 > (mode_t)0, "x86 unsigned 32-bit mode_t");
_Static_assert(SYS_umask == 95, "x86 umask syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&umask),
    umask_signature), "umask declaration");

static int check_mask_exchange(void)
{
    const umask_signature indirect = umask;
    const mode_t original = umask(0);

    if (original > 0777)
        return 1;
    if (umask(0027) != 0)
        return 2;
    if (indirect(0042) != 0027)
        return 3;
    if (umask(original) != 0042)
        return 4;
    return 0;
}

int crabc_x86_64_umask_probe(void)
{
    return check_mask_exchange();
}

#ifndef CRABC_UMASK_FREESTANDING
int main(void)
{
    return crabc_x86_64_umask_probe();
}
#endif

/* Static x86-64 sync C ABI fixture.
 *
 * Musl's Linux implementation has one void, zero-argument raw sync syscall.
 * This fixture only proves the direct and function-pointer C call boundary
 * returns normally; the adjacent pinned-musl/raw reference owns the dirty-file
 * and raw-zero observation. It makes no timing or durability assertion.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

_Static_assert(sizeof(void *) == 8, "Linux/x86-64 LP64 pointer");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sync),
    void (*)(void)), "sync declaration");

typedef void (*sync_signature)(void);

int crabc_x86_64_sync_probe(void)
{
    const sync_signature function = sync;

    sync();
    return function == sync ? 0 : 1;
}

#ifndef CRABC_SYNC_FREESTANDING
int main(void)
{
    return crabc_x86_64_sync_probe();
}
#endif

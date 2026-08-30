/* Linux/x86-64 selected <sys/mman.h> per-range locking profile probe.
 *
 * Pinned musl 1.2.6 owns the declaration and feature-visibility contract.
 * This source proves only mlock/munlock and GNU mlock2(MLOCK_ONFAULT), not a
 * runtime implementation, a complete mapping header, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

#define CRABC_MEMORY_LOCK_TYPE int (*)(const void *, size_t)
#define CRABC_MEMORY_LOCK2_TYPE int (*)(const void *, size_t, unsigned)

_Static_assert(__builtin_types_compatible_p(__typeof__(&mlock),
    CRABC_MEMORY_LOCK_TYPE), "mlock declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&munlock),
    CRABC_MEMORY_LOCK_TYPE), "munlock declaration");

#if defined(CRABC_MEMORY_LOCKING_GNU)
#ifndef _GNU_SOURCE
#error "GNU profile must define _GNU_SOURCE"
#endif
_Static_assert(__builtin_types_compatible_p(__typeof__(&mlock2),
    CRABC_MEMORY_LOCK2_TYPE), "GNU mlock2 declaration");
_Static_assert(MLOCK_ONFAULT == 0x01U, "GNU MLOCK_ONFAULT value");
#else
#ifdef MLOCK_ONFAULT
#error "MLOCK_ONFAULT must remain hidden outside the GNU profile"
#endif
#ifdef CRABC_MEMORY_LOCKING_REQUIRE_GNU_HIDDEN
static CRABC_MEMORY_LOCK2_TYPE crabc_memory_locking_mlock2_must_be_hidden =
    mlock2;
#endif
#endif

int crabc_x86_64_memory_locking_header_abi_probe(void)
{
    return 0;
}

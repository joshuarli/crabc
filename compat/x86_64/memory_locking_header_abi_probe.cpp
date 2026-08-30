/* Linux/x86-64 selected <sys/mman.h> per-range locking C++17 profile probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/mman.h>

using memory_lock_type = int (*)(const void *, size_t);
using memory_lock2_type = int (*)(const void *, size_t, unsigned);

static_assert(__is_same(decltype(&mlock), memory_lock_type),
    "C++ mlock declaration");
static_assert(__is_same(decltype(&munlock), memory_lock_type),
    "C++ munlock declaration");

__attribute__((used)) static memory_lock_type crabc_memory_locking_cxx_mlock =
    mlock;
__attribute__((used)) static memory_lock_type crabc_memory_locking_cxx_munlock =
    munlock;

#if defined(CRABC_MEMORY_LOCKING_GNU)
#ifndef _GNU_SOURCE
#error "GNU profile must define _GNU_SOURCE"
#endif
static_assert(__is_same(decltype(&mlock2), memory_lock2_type),
    "C++ GNU mlock2 declaration");
static_assert(MLOCK_ONFAULT == 0x01U, "C++ GNU MLOCK_ONFAULT value");
__attribute__((used)) static memory_lock2_type crabc_memory_locking_cxx_mlock2 =
    mlock2;
#else
#ifdef MLOCK_ONFAULT
#error "MLOCK_ONFAULT must remain hidden outside the GNU profile"
#endif
#ifdef CRABC_MEMORY_LOCKING_REQUIRE_GNU_HIDDEN
static memory_lock2_type crabc_memory_locking_mlock2_must_be_hidden = mlock2;
#endif
#endif

int crabc_x86_64_memory_locking_header_abi_probe_cpp()
{
    return 0;
}

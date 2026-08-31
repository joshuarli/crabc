/* Native Linux/x86-64 GNU C++17 <sched.h> sched_getcpu linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sched.h>
#include <sys/syscall.h>

using sched_getcpu_signature = int (*)(void);

static_assert(SYS_getcpu == 309, "x86 getcpu syscall number");
static_assert(__is_same(decltype(&sched_getcpu), sched_getcpu_signature),
    "sched_getcpu declaration");

/* Retain one undefined external-C reference for the linkage check. */
static volatile sched_getcpu_signature sched_getcpu_function = sched_getcpu;

int crabc_x86_64_sched_getcpu_header_abi_probe_cpp()
{
    return sched_getcpu_function != nullptr ? 0 : 1;
}

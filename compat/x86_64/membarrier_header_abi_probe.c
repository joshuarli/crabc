/* Pinned-musl/project Linux/x86-64 <sys/membarrier.h> declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/membarrier.h>

typedef int (*membarrier_signature)(int, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&membarrier),
    membarrier_signature), "membarrier declaration");
_Static_assert(MEMBARRIER_CMD_QUERY == 0, "membarrier query command");
_Static_assert(MEMBARRIER_CMD_GLOBAL == 1, "membarrier global command");
_Static_assert(MEMBARRIER_CMD_FLAG_CPU == 1, "membarrier CPU flag");

static membarrier_signature membarrier_function __attribute__((used)) = membarrier;

int crabc_x86_64_membarrier_header_abi_probe(void)
{
    return membarrier_function(MEMBARRIER_CMD_QUERY, 0);
}

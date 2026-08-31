/* Pinned-musl/project Linux/x86-64 <sys/membarrier.h> C++ declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/membarrier.h>

using membarrier_signature = int (*)(int, int);

static_assert(__is_same(decltype(&membarrier), membarrier_signature),
    "C++ membarrier declaration");
static_assert(MEMBARRIER_CMD_QUERY == 0, "membarrier query command");
static_assert(MEMBARRIER_CMD_GLOBAL == 1, "membarrier global command");
static_assert(MEMBARRIER_CMD_FLAG_CPU == 1, "membarrier CPU flag");

static membarrier_signature membarrier_function __attribute__((used)) = membarrier;

int crabc_x86_64_membarrier_header_abi_probe_cpp()
{
    return membarrier_function(MEMBARRIER_CMD_QUERY, 0);
}

/* C++ companion for the native x86-64 GNU <fcntl.h> tee declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/types.h>
#include <fcntl.h>

extern "C" ssize_t tee(int, int, size_t, unsigned);

using tee_signature = ssize_t (*)(int, int, size_t, unsigned);

#if defined(CRABC_EXPECT_TEE)
static_assert(__is_same(decltype(&tee), tee_signature),
              "tee declaration");
#endif

int crabc_x86_64_tee_header_abi_probe_cpp()
{
    return 0;
}

/* C++17 companion for the Linux/x86-64 umask declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/stat.h>

using umask_signature = mode_t (*)(mode_t);

static_assert(sizeof(mode_t) == 4 && alignof(mode_t) == 4 &&
    static_cast<mode_t>(-1) > static_cast<mode_t>(0),
    "x86 unsigned 32-bit mode_t");
static_assert(__is_same(decltype(&umask), umask_signature),
              "C++ umask declaration");
static umask_signature umask_signature_value __attribute__((used)) = umask;

int crabc_x86_64_umask_header_abi_probe_cpp()
{
    return umask_signature_value != nullptr ? 0 : 1;
}

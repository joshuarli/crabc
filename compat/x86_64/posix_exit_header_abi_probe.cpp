/* C++ companion for the Linux/x86-64 POSIX _exit declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using posix_exit_signature = void (*)(int);

static posix_exit_signature posix_exit_function = _exit;

int crabc_x86_64_posix_exit_header_abi_probe_cpp()
{
    return posix_exit_function != nullptr ? 0 : 1;
}

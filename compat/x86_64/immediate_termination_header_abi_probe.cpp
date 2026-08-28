/* C++ companion for the Linux/x86-64 C11 immediate-termination probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stdlib.h>

using immediate_exit_signature = void (*)(int);

static immediate_exit_signature immediate_exit_function = _Exit;

int crabc_x86_64_immediate_termination_header_abi_probe_cpp()
{
    return immediate_exit_function != nullptr ? 0 : 1;
}

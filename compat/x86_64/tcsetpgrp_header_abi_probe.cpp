/* C++17 companion for the Linux/x86-64 tcsetpgrp declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using tcsetpgrp_signature = int (*)(int, pid_t);

static_assert(__is_same(decltype(&tcsetpgrp), tcsetpgrp_signature),
    "C++ tcsetpgrp declaration");

static tcsetpgrp_signature tcsetpgrp_function = tcsetpgrp;

int crabc_x86_64_tcsetpgrp_header_abi_probe_cpp()
{
    return tcsetpgrp_function != nullptr ? 0 : 1;
}

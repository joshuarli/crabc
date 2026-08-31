/* C++17 companion for the Linux/x86-64 tcgetpgrp declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using tcgetpgrp_signature = pid_t (*)(int);

static_assert(__is_same(decltype(&tcgetpgrp), tcgetpgrp_signature),
    "C++ tcgetpgrp declaration");

static tcgetpgrp_signature tcgetpgrp_function = tcgetpgrp;

int crabc_x86_64_tcgetpgrp_header_abi_probe_cpp()
{
    return tcgetpgrp_function != nullptr ? 0 : 1;
}

/* Pinned-musl/project Linux/x86-64 tcgetpgrp declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef pid_t (*tcgetpgrp_signature)(int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&tcgetpgrp),
    tcgetpgrp_signature), "tcgetpgrp declaration");

static tcgetpgrp_signature tcgetpgrp_function = tcgetpgrp;

int crabc_x86_64_tcgetpgrp_header_abi_probe(void)
{
    return tcgetpgrp_function != (tcgetpgrp_signature)0 ? 0 : 1;
}

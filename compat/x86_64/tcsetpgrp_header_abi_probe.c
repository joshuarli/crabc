/* Pinned-musl/project Linux/x86-64 tcsetpgrp declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*tcsetpgrp_signature)(int, pid_t);

_Static_assert(__builtin_types_compatible_p(__typeof__(&tcsetpgrp),
    tcsetpgrp_signature), "tcsetpgrp declaration");

static tcsetpgrp_signature tcsetpgrp_function = tcsetpgrp;

int crabc_x86_64_tcsetpgrp_header_abi_probe(void)
{
    return tcsetpgrp_function != (tcsetpgrp_signature)0 ? 0 : 1;
}

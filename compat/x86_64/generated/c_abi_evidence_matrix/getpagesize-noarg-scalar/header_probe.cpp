/* Generated from c_abi_evidence_matrix.toml; do not edit. */
#include <unistd.h>

using crabc_getpagesize_noarg_scalar_signature = int (*)(void);
static_assert(__is_same(decltype(&getpagesize), crabc_getpagesize_noarg_scalar_signature),
    "getpagesize C++ declaration");
static crabc_getpagesize_noarg_scalar_signature crabc_getpagesize_noarg_scalar_function = getpagesize;

int crabc_getpagesize_noarg_scalar_prototype_probe_cpp()
{
    return crabc_getpagesize_noarg_scalar_function != nullptr ? 0 : 1;
}

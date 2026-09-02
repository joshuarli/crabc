/* Generated from c_abi_evidence_matrix.toml and family fragments; do not edit. */
#include <unistd.h>

using crabc_gethostid_noarg_scalar_signature = long (*)(void);
static_assert(__is_same(decltype(&gethostid), crabc_gethostid_noarg_scalar_signature),
    "gethostid C++ declaration");
static crabc_gethostid_noarg_scalar_signature crabc_gethostid_noarg_scalar_function = gethostid;

int crabc_gethostid_noarg_scalar_prototype_probe_cpp()
{
    return crabc_gethostid_noarg_scalar_function != nullptr ? 0 : 1;
}

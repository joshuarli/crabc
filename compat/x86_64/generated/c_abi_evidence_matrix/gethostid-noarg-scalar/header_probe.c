/* Generated from c_abi_evidence_matrix.toml; do not edit. */
#include <unistd.h>

typedef long (*crabc_gethostid_noarg_scalar_signature)(void);
_Static_assert(__builtin_types_compatible_p(__typeof__(&gethostid),
    crabc_gethostid_noarg_scalar_signature), "gethostid C declaration");
static long (*crabc_gethostid_noarg_scalar_function)(void) = gethostid;

int crabc_gethostid_noarg_scalar_prototype_probe(void)
{
    return crabc_gethostid_noarg_scalar_function != (crabc_gethostid_noarg_scalar_signature)0 ? 0 : 1;
}

/* Generated from c_abi_evidence_matrix.toml and family fragments; do not edit. */
#include <unistd.h>

typedef int (*crabc_getpagesize_noarg_scalar_signature)(void);
_Static_assert(__builtin_types_compatible_p(__typeof__(&getpagesize),
    crabc_getpagesize_noarg_scalar_signature), "getpagesize C declaration");
static int (*crabc_getpagesize_noarg_scalar_function)(void) = getpagesize;

int crabc_getpagesize_noarg_scalar_prototype_probe(void)
{
    return crabc_getpagesize_noarg_scalar_function != (crabc_getpagesize_noarg_scalar_signature)0 ? 0 : 1;
}

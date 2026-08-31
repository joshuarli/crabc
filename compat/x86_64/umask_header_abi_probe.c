/* Pinned-musl/project Linux/x86-64 umask declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/stat.h>

typedef mode_t (*umask_signature)(mode_t);

_Static_assert(sizeof(mode_t) == 4 && _Alignof(mode_t) == 4 &&
    (mode_t)-1 > (mode_t)0, "x86 unsigned 32-bit mode_t");
_Static_assert(__builtin_types_compatible_p(__typeof__(&umask),
    umask_signature), "umask declaration");
static umask_signature umask_signature_value __attribute__((used)) = umask;

int crabc_x86_64_umask_header_abi_probe(void)
{
    return umask_signature_value != (umask_signature)0 ? 0 : 1;
}

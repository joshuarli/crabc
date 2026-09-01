/* Pinned-musl/project Linux/x86-64 <crypt.h> declaration and record ABI. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <crypt.h>
#include <stddef.h>

typedef char *(*crypt_signature)(const char *, const char *);
typedef char *(*crypt_r_signature)(const char *, const char *, struct crypt_data *);

_Static_assert(sizeof(struct crypt_data) == 260, "crypt_data size");
_Static_assert(_Alignof(struct crypt_data) == _Alignof(int), "crypt_data alignment");
_Static_assert(offsetof(struct crypt_data, initialized) == 0, "crypt_data initialized");
_Static_assert(offsetof(struct crypt_data, __buf) == sizeof(int), "crypt_data buffer");
_Static_assert(sizeof(((struct crypt_data *)0)->__buf) == 256, "crypt_data buffer size");
_Static_assert(__builtin_types_compatible_p(__typeof__(&crypt), crypt_signature),
    "crypt declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&crypt_r), crypt_r_signature),
    "crypt_r declaration");

static crypt_signature crypt_function __attribute__((used)) = crypt;
static crypt_r_signature crypt_r_function __attribute__((used)) = crypt_r;

int crabc_x86_64_crypt_header_abi_probe(void)
{
    return crypt_function != (crypt_signature)0 &&
        crypt_r_function != (crypt_r_signature)0 ? 0 : 1;
}

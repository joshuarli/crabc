/* C++17 companion for the Linux/x86-64 <crypt.h> ABI gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <crypt.h>
#include <stddef.h>

using crypt_signature = char *(*)(const char *, const char *);
using crypt_r_signature = char *(*)(const char *, const char *, crypt_data *);

static_assert(sizeof(crypt_data) == 260, "crypt_data size");
static_assert(alignof(crypt_data) == alignof(int), "crypt_data alignment");
static_assert(offsetof(crypt_data, initialized) == 0, "crypt_data initialized");
static_assert(offsetof(crypt_data, __buf) == sizeof(int), "crypt_data buffer");
static_assert(sizeof(((crypt_data *)0)->__buf) == 256, "crypt_data buffer size");
static_assert(__is_same(decltype(&crypt), crypt_signature), "crypt declaration");
static_assert(__is_same(decltype(&crypt_r), crypt_r_signature), "crypt_r declaration");

static crypt_signature crypt_function __attribute__((used)) = crypt;
static crypt_r_signature crypt_r_function __attribute__((used)) = crypt_r;

int crabc_x86_64_crypt_header_abi_probe_cpp()
{
    return crypt_function != nullptr && crypt_r_function != nullptr ? 0 : 1;
}

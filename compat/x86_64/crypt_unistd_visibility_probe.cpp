/* Linux/x86-64 C++ <unistd.h> crypt visibility by feature-test profile. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using crypt_signature = char *(*)(const char *, const char *);

#if defined(CRABC_EXPECT_UNISTD_CRYPT)
static_assert(__is_same(decltype(&crypt), crypt_signature),
    "unistd crypt declaration");
static crypt_signature unistd_crypt_function __attribute__((used)) = crypt;

int crabc_x86_64_crypt_unistd_visibility_probe_cpp()
{
    return unistd_crypt_function != nullptr ? 0 : 1;
}
#else
/* This reference must fail to compile when <unistd.h> correctly hides crypt. */
static crypt_signature unistd_crypt_must_not_be_declared __attribute__((used)) = crypt;
#endif

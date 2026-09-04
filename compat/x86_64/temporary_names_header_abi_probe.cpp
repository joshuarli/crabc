/* C++17 companion for the Linux/x86-64 <stdio.h> temporary-name probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86_64 little-endian LP64"
#endif

#include <stdio.h>

using tmpnam_signature = char *(*)(char *);
using tempnam_signature = char *(*)(const char *, const char *);

static_assert(L_tmpnam == 20, "L_tmpnam value");
static_assert(__is_same(decltype(&tmpnam), tmpnam_signature),
              "C++ tmpnam declaration");
__attribute__((used)) static tmpnam_signature tmpnam_function = tmpnam;

#if defined(CRABC_EXPECT_TEMPNAM)
static_assert(__is_same(decltype(&tempnam), tempnam_signature),
              "C++ tempnam declaration");
static_assert(sizeof(P_tmpdir) == sizeof("/tmp"), "P_tmpdir extent");
__attribute__((used)) static tempnam_signature tempnam_function = tempnam;
__attribute__((used)) static const char *const p_tmpdir_value = P_tmpdir;
#endif

int crabc_x86_64_temporary_names_header_abi_probe_cpp()
{
    return tmpnam_function == nullptr;
}

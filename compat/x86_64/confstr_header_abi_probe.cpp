/* C++17 companion for the Linux/x86-64 confstr declaration gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using confstr_signature = size_t (*)(int, char *, size_t);

static_assert(__is_same(decltype(&confstr), confstr_signature),
              "C++ confstr declaration");
static confstr_signature confstr_signature_value __attribute__((used)) = confstr;

int crabc_x86_64_confstr_header_abi_probe_cpp()
{
    return confstr_signature_value != nullptr ? 0 : 1;
}

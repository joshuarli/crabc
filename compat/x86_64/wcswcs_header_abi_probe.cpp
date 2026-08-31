/* C++17 companion for the Linux/x86-64 wchar.h wcswcs declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <wchar.h>

using wcswcs_signature = wchar_t *(*)(const wchar_t *, const wchar_t *);

static_assert(__is_same(decltype(&wcswcs), wcswcs_signature),
    "C++ wcswcs declaration");

static wcswcs_signature wcswcs_function __attribute__((used)) = wcswcs;

int crabc_x86_64_wcswcs_header_abi_probe_cpp()
{
    return wcswcs_function != nullptr ? 0 : 1;
}

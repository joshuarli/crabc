/* C++17 linkage probe for the sealed literal-percent scanf artifact.
 *
 * `used` references let the runner prove that project <stdio.h> requests
 * unmangled C spellings for only the existing `sscanf`/`vsscanf` declarations.
 * This is not runtime or general stdio evidence.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_FIXED_PERCENT_SCAN_HEADER_CXX17)
#error "the C++17 literal-percent scanf header profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdarg.h>
#include <stdio.h>

using crabc_sscanf_signature = int (*)(const char *, const char *, ...);
using crabc_vsscanf_signature = int (*)(const char *, const char *, va_list);

static_assert(__is_same(decltype(&sscanf), crabc_sscanf_signature),
    "sscanf C++ declaration");
static_assert(__is_same(decltype(&vsscanf), crabc_vsscanf_signature),
    "vsscanf C++ declaration");

__attribute__((used)) static crabc_sscanf_signature crabc_sscanf_reference =
    &sscanf;
__attribute__((used)) static crabc_vsscanf_signature crabc_vsscanf_reference =
    &vsscanf;

int crabc_x86_64_stdio_fixed_percent_scan_header_abi_probe_cpp()
{
    return 0;
}

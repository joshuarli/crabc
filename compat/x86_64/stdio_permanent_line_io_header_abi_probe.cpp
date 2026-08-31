/* C++17 companion to the Linux/x86-64 permanent-line-I/O declaration probe.
 *
 * `used` references let the runner prove that <stdio.h> requests the C ABI
 * spellings. This remains declaration-only evidence for fgets/fputs/puts.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#if !defined(CRABC_STDIO_PERMANENT_LINE_IO_CXX17)
#error "the C++17 permanent-line-I/O profile must be selected"
#endif

#if __cplusplus != 201703L
#error "this probe requires C++17"
#endif

#include <stdio.h>

using crabc_stdio_fgets_signature = char *(*)(char *, int, FILE *);
using crabc_stdio_fputs_signature = int (*)(const char *, FILE *);
using crabc_stdio_puts_signature = int (*)(const char *);

static_assert(__is_same(decltype(&fgets), crabc_stdio_fgets_signature),
    "fgets C++ declaration");
static_assert(__is_same(decltype(&fputs), crabc_stdio_fputs_signature),
    "fputs C++ declaration");
static_assert(__is_same(decltype(&puts), crabc_stdio_puts_signature),
    "puts C++ declaration");

__attribute__((used)) static crabc_stdio_fgets_signature
    crabc_stdio_fgets_reference = &fgets;
__attribute__((used)) static crabc_stdio_fputs_signature
    crabc_stdio_fputs_reference = &fputs;
__attribute__((used)) static crabc_stdio_puts_signature
    crabc_stdio_puts_reference = &puts;

int crabc_x86_64_stdio_permanent_line_io_header_abi_probe_cpp()
{
    return 0;
}

/* x86 Linux port-I/O header declarations and inline-codegen companion.
 *
 * This source is never executed: direct port I/O is privilege-bearing kernel
 * administration.  The paired runner compiles it through both the pinned musl
 * and project header roots, then inspects the named wrapper's object code.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/io.h>

typedef int (*iopl_signature)(int);
typedef int (*ioperm_signature)(unsigned long, unsigned long, int);
typedef void (*outb_signature)(unsigned char, unsigned short);
typedef void (*outw_signature)(unsigned short, unsigned short);
typedef void (*outl_signature)(unsigned int, unsigned short);
typedef unsigned char (*inb_signature)(unsigned short);
typedef unsigned short (*inw_signature)(unsigned short);
typedef unsigned int (*inl_signature)(unsigned short);
typedef void (*outs_signature)(unsigned short, const void *, unsigned long);
typedef void (*ins_signature)(unsigned short, void *, unsigned long);

_Static_assert(__builtin_types_compatible_p(__typeof__(&iopl), iopl_signature),
               "iopl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&ioperm), ioperm_signature),
               "ioperm declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&outb), outb_signature),
               "outb inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&outw), outw_signature),
               "outw inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&outl), outl_signature),
               "outl inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inb), inb_signature),
               "inb inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inw), inw_signature),
               "inw inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&inl), inl_signature),
               "inl inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&outsb), outs_signature),
               "outsb inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&outsw), outs_signature),
               "outsw inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&outsl), outs_signature),
               "outsl inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&insb), ins_signature),
               "insb inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&insw), ins_signature),
               "insw inline declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&insl), ins_signature),
               "insl inline declaration");

static iopl_signature crabc_x86_iopl_reference __attribute__((used)) = iopl;
static ioperm_signature crabc_x86_ioperm_reference __attribute__((used)) = ioperm;
static volatile unsigned char crabc_x86_inb_result;
static volatile unsigned short crabc_x86_inw_result;
static volatile unsigned int crabc_x86_inl_result;

__attribute__((noinline, used))
void crabc_x86_sys_io_header_abi_codegen(
    unsigned short port,
    unsigned char byte_value,
    unsigned short word_value,
    unsigned int long_value,
    const void *output_buffer,
    void *input_buffer,
    unsigned long count)
{
    outb(byte_value, port);
    outw(word_value, port);
    outl(long_value, port);
    crabc_x86_inb_result = inb(port);
    crabc_x86_inw_result = inw(port);
    crabc_x86_inl_result = inl(port);
    outsb(port, output_buffer, count);
    outsw(port, output_buffer, count);
    outsl(port, output_buffer, count);
    insb(port, input_buffer, count);
    insw(port, input_buffer, count);
    insl(port, input_buffer, count);
}

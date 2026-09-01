/* C++17 companion for the x86 Linux port-I/O header declaration/codegen gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/io.h>

using iopl_signature = int (*)(int);
using ioperm_signature = int (*)(unsigned long, unsigned long, int);
using outb_signature = void (*)(unsigned char, unsigned short);
using outw_signature = void (*)(unsigned short, unsigned short);
using outl_signature = void (*)(unsigned int, unsigned short);
using inb_signature = unsigned char (*)(unsigned short);
using inw_signature = unsigned short (*)(unsigned short);
using inl_signature = unsigned int (*)(unsigned short);
using outs_signature = void (*)(unsigned short, const void *, unsigned long);
using ins_signature = void (*)(unsigned short, void *, unsigned long);

static_assert(__is_same(decltype(&iopl), iopl_signature), "iopl C++ declaration");
static_assert(__is_same(decltype(&ioperm), ioperm_signature), "ioperm C++ declaration");
static_assert(__is_same(decltype(&outb), outb_signature), "outb C++ declaration");
static_assert(__is_same(decltype(&outw), outw_signature), "outw C++ declaration");
static_assert(__is_same(decltype(&outl), outl_signature), "outl C++ declaration");
static_assert(__is_same(decltype(&inb), inb_signature), "inb C++ declaration");
static_assert(__is_same(decltype(&inw), inw_signature), "inw C++ declaration");
static_assert(__is_same(decltype(&inl), inl_signature), "inl C++ declaration");
static_assert(__is_same(decltype(&outsb), outs_signature), "outsb C++ declaration");
static_assert(__is_same(decltype(&outsw), outs_signature), "outsw C++ declaration");
static_assert(__is_same(decltype(&outsl), outs_signature), "outsl C++ declaration");
static_assert(__is_same(decltype(&insb), ins_signature), "insb C++ declaration");
static_assert(__is_same(decltype(&insw), ins_signature), "insw C++ declaration");
static_assert(__is_same(decltype(&insl), ins_signature), "insl C++ declaration");

__attribute__((used)) static iopl_signature crabc_x86_iopl_reference = iopl;
__attribute__((used)) static ioperm_signature crabc_x86_ioperm_reference = ioperm;
static volatile unsigned char crabc_x86_inb_result;
static volatile unsigned short crabc_x86_inw_result;
static volatile unsigned int crabc_x86_inl_result;

extern "C" __attribute__((noinline, used))
void crabc_x86_sys_io_header_abi_codegen_cpp(
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

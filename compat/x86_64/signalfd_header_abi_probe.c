/* Selected Linux/x86-64 <sys/signalfd.h> declaration and record contract. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/signalfd.h>

typedef int (*crabc_signalfd_signature)(int, const sigset_t *, int);

_Static_assert(SFD_NONBLOCK == O_NONBLOCK && SFD_NONBLOCK == 0x800,
               "x86 signalfd nonblocking flag");
_Static_assert(SFD_CLOEXEC == O_CLOEXEC && SFD_CLOEXEC == 0x80000,
               "x86 signalfd close-on-exec flag");
_Static_assert(sizeof(sigset_t) == 128 && _Alignof(sigset_t) == 8,
               "x86 sigset_t ABI");
_Static_assert(sizeof(struct signalfd_siginfo) == 128 &&
                   _Alignof(struct signalfd_siginfo) == 8 &&
                   offsetof(struct signalfd_siginfo, ssi_signo) == 0 &&
                   offsetof(struct signalfd_siginfo, ssi_ptr) == 48 &&
                   offsetof(struct signalfd_siginfo, ssi_addr) == 72 &&
                   offsetof(struct signalfd_siginfo, ssi_call_addr) == 88 &&
                   offsetof(struct signalfd_siginfo, ssi_arch) == 96,
               "x86 signalfd_siginfo ABI");
_Static_assert(__builtin_types_compatible_p(__typeof__(&signalfd),
                                             crabc_signalfd_signature),
               "signalfd declaration");

int crabc_x86_64_signalfd_header_abi_probe(void)
{
    return (int)sizeof(struct signalfd_siginfo);
}

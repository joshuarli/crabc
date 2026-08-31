/* C++17 companion for the selected Linux/x86-64 <sys/signalfd.h> ABI. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <stddef.h>
#include <sys/signalfd.h>

using signalfd_signature = int (*)(int, const sigset_t *, int);

static_assert(SFD_NONBLOCK == O_NONBLOCK && SFD_NONBLOCK == 0x800,
              "C++ x86 signalfd nonblocking flag");
static_assert(SFD_CLOEXEC == O_CLOEXEC && SFD_CLOEXEC == 0x80000,
              "C++ x86 signalfd close-on-exec flag");
static_assert(sizeof(sigset_t) == 128 && alignof(sigset_t) == 8,
              "C++ x86 sigset_t ABI");
static_assert(sizeof(struct signalfd_siginfo) == 128 &&
                  alignof(struct signalfd_siginfo) == 8 &&
                  __builtin_offsetof(struct signalfd_siginfo, ssi_signo) == 0 &&
                  __builtin_offsetof(struct signalfd_siginfo, ssi_ptr) == 48 &&
                  __builtin_offsetof(struct signalfd_siginfo, ssi_addr) == 72 &&
                  __builtin_offsetof(struct signalfd_siginfo, ssi_call_addr) == 88 &&
                  __builtin_offsetof(struct signalfd_siginfo, ssi_arch) == 96,
              "C++ x86 signalfd_siginfo ABI");
static_assert(__is_same(decltype(&signalfd), signalfd_signature),
              "C++ signalfd declaration");

__attribute__((used)) static signalfd_signature signalfd_cxx_reference =
    signalfd;

int crabc_x86_64_signalfd_header_abi_probe_cpp()
{
    return (int)sizeof(struct signalfd_siginfo);
}

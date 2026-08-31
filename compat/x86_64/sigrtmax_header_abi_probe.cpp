/*
 * Pinned-musl Linux/x86-64 __libc_current_sigrtmax C++ declaration probe.
 * The runner compiles this under POSIX and GNU feature profiles
 * against both pinned musl and project-first headers. Retained references
 * prove the bridge has the exact unmangled C function type where musl exposes
 * this POSIX-family signal vocabulary.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_SIGRTMAX)
using sigrtmax_signature = int (*)(void);

static_assert(__is_same(decltype(&__libc_current_sigrtmax),
    sigrtmax_signature), "__libc_current_sigrtmax pointer signature");

/* Retain both direct and macro-mediated references for ELF linkage evidence. */
__attribute__((used)) static sigrtmax_signature sigrtmax_cxx_reference =
    __libc_current_sigrtmax;
__attribute__((used)) static int sigrtmax_macro_reference(void)
{
    return SIGRTMAX;
}
#endif

int crabc_x86_64_sigrtmax_header_abi_probe_cpp()
{
    return 0;
}

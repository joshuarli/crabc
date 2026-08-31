/*
 * Pinned-musl Linux/x86-64 __libc_current_sigrtmin C++ declaration probe.
 * The runner compiles this under POSIX and GNU feature profiles against both
 * pinned musl and project-first headers. Retained direct references prove the
 * bridge has the exact unmangled C function type where musl exposes this
 * POSIX-family signal vocabulary.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_SIGRTMIN)
using sigrtmin_signature = int (*)(void);

static_assert(__is_same(decltype(&__libc_current_sigrtmin),
    sigrtmin_signature), "__libc_current_sigrtmin pointer signature");

/* Retain both the direct bridge reference and the public macro expression. */
__attribute__((used)) static sigrtmin_signature sigrtmin_cxx_reference =
    __libc_current_sigrtmin;
__attribute__((used)) static int sigrtmin_macro_reference(void)
{
    return SIGRTMIN;
}
#endif

int crabc_x86_64_sigrtmin_header_abi_probe_cpp()
{
    return 0;
}

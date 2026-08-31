/*
 * Pinned-musl Linux/x86-64 POSIX signal-set mutation C++ declaration probe.
 *
 * The runner compiles this once with `_POSIX_C_SOURCE=200809L` and once with
 * `_GNU_SOURCE`, against both pinned musl and project-first headers. The
 * retained calls prove that all three POSIX spellings keep C linkage in C++.
 */

/* C++17 companion for the Linux/x86-64 POSIX signal-set mutation gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_POSIX_SIGNAL_SET_MUTATION)
using sigset_mutation_binary_signature = int (*)(sigset_t *, int);
using sigset_mutation_unary_signature = int (*)(sigset_t *);

static_assert(__is_same(decltype(&sigaddset), sigset_mutation_binary_signature),
    "POSIX sigaddset pointer signature");
static_assert(__is_same(decltype(&sigdelset), sigset_mutation_binary_signature),
    "POSIX sigdelset pointer signature");
static_assert(__is_same(decltype(&sigfillset), sigset_mutation_unary_signature),
    "POSIX sigfillset pointer signature");

/* Retain all names so the object proof observes their unmangled C linkage. */
__attribute__((used)) static sigset_mutation_binary_signature sigaddset_cxx_reference =
    sigaddset;
__attribute__((used)) static sigset_mutation_binary_signature sigdelset_cxx_reference =
    sigdelset;
__attribute__((used)) static sigset_mutation_unary_signature sigfillset_cxx_reference =
    sigfillset;
#endif

int crabc_x86_64_signal_set_mutation_header_abi_probe_cpp()
{
    return 0;
}

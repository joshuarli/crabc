/* Linux/x86-64 <signal.h> psignal/psiginfo C++ linkage probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_PSIGNAL)
using psignal_signature = void (*)(int, const char *);
using psiginfo_signature = void (*)(const siginfo_t *, const char *);

static_assert(__is_same(decltype(&psignal), psignal_signature),
              "psignal declaration");
static_assert(__is_same(decltype(&psiginfo), psiginfo_signature),
              "psiginfo declaration");

static psignal_signature psignal_function __attribute__((used)) = psignal;
static psiginfo_signature psiginfo_function __attribute__((used)) = psiginfo;
#endif

#if defined(CRABC_REQUIRE_PSIGNAL_HIDDEN)
static auto required_psignal_function = &psignal;
static auto required_psiginfo_function = &psiginfo;
#endif

int crabc_x86_64_psignal_header_abi_probe_cpp()
{
#if defined(CRABC_EXPECT_PSIGNAL)
    return psignal_function == nullptr || psiginfo_function == nullptr;
#else
    return 0;
#endif
}

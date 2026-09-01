/* Linux/x86-64 <signal.h> psignal/psiginfo declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>

#if defined(CRABC_EXPECT_PSIGNAL)
typedef void (*psignal_signature)(int, const char *);
typedef void (*psiginfo_signature)(const siginfo_t *, const char *);

_Static_assert(
    __builtin_types_compatible_p(__typeof__(&psignal), psignal_signature),
    "psignal declaration");
_Static_assert(
    __builtin_types_compatible_p(__typeof__(&psiginfo), psiginfo_signature),
    "psiginfo declaration");

static psignal_signature psignal_function __attribute__((used)) = psignal;
static psiginfo_signature psiginfo_function __attribute__((used)) = psiginfo;
#endif

/* This branch is compiled only for strict-feature negative checks. */
#if defined(CRABC_REQUIRE_PSIGNAL_HIDDEN)
static void *required_psignal_function = (void *)&psignal;
static void *required_psiginfo_function = (void *)&psiginfo;
#endif

int crabc_x86_64_psignal_header_abi_probe(void)
{
#if defined(CRABC_EXPECT_PSIGNAL)
    return psignal_function == 0 || psiginfo_function == 0;
#else
    return 0;
#endif
}

/* C++17 companion to feature_profile_control_plane_probe.c. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <features.h>

#if defined(CRABC_FEATURE_PROFILE_STRICT)
#if defined(_POSIX_SOURCE) || defined(_POSIX_C_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#error "strict C++17 must not select a public extension profile"
#endif
#elif defined(CRABC_FEATURE_PROFILE_POSIX_2008)
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE != 200809L || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#error "POSIX.1-2008 must retain only its explicit feature selector"
#endif
#elif defined(CRABC_FEATURE_PROFILE_XOPEN_700)
#if !defined(_XOPEN_SOURCE) || _XOPEN_SOURCE != 700 || \
    defined(_POSIX_C_SOURCE) || defined(_GNU_SOURCE) || defined(_BSD_SOURCE)
#error "X/Open Issue 7 must retain only its explicit feature selector"
#endif
#elif defined(CRABC_FEATURE_PROFILE_GNU)
#if !defined(_GNU_SOURCE) || defined(_XOPEN_SOURCE) || defined(_BSD_SOURCE)
#error "_GNU_SOURCE must not synthesize BSD or X/Open selection"
#endif
#elif defined(CRABC_FEATURE_PROFILE_BSD)
#if !defined(_BSD_SOURCE) || defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE)
#error "_BSD_SOURCE must not synthesize GNU or X/Open selection"
#endif
#elif defined(CRABC_FEATURE_PROFILE_DEFAULT_SOURCE)
#if !defined(_DEFAULT_SOURCE) || !defined(_BSD_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_GNU_SOURCE)
#error "_DEFAULT_SOURCE must imply only musl's BSD selector"
#endif
#elif defined(CRABC_FEATURE_PROFILE_ALL_SOURCE)
#if !defined(_ALL_SOURCE) || !defined(_GNU_SOURCE) || \
    defined(_XOPEN_SOURCE) || defined(_BSD_SOURCE)
#error "_ALL_SOURCE must imply only musl's GNU selector"
#endif
#elif defined(CRABC_FEATURE_PROFILE_IMPLICIT_DEFAULT)
#if !defined(_BSD_SOURCE) || !defined(_XOPEN_SOURCE) || \
    _XOPEN_SOURCE != 700 || defined(_GNU_SOURCE)
#error "an unselected non-strict mode must receive musl's default profile"
#endif
#else
#error "select exactly one feature-profile regression case"
#endif

#if defined(CRABC_FEATURE_HEADER_FCNTL_BSD)
#include <fcntl.h>
using crabc_lockf_signature = int (*)(int, int, off_t);
static_assert(__is_same(decltype(&lockf), crabc_lockf_signature),
    "BSD lockf C++ declaration");
__attribute__((used)) static crabc_lockf_signature crabc_bsd_lockf = &lockf;
#elif defined(CRABC_FEATURE_HEADER_MATH_GNU)
#include <math.h>
using crabc_sincos_signature = void (*)(double, double *, double *);
using crabc_exp10_signature = double (*)(double);
using crabc_exp10f_signature = float (*)(float);
using crabc_exp10l_signature = long double (*)(long double);
using crabc_pow10_signature = double (*)(double);
using crabc_pow10f_signature = float (*)(float);
using crabc_pow10l_signature = long double (*)(long double);
using crabc_lgammal_r_signature = long double (*)(long double, int *);
static_assert(__is_same(decltype(&sincos), crabc_sincos_signature),
    "GNU sincos C++ declaration");
static_assert(__is_same(decltype(&exp10), crabc_exp10_signature),
    "GNU exp10 C++ declaration");
static_assert(__is_same(decltype(&exp10f), crabc_exp10f_signature),
    "GNU exp10f C++ declaration");
static_assert(__is_same(decltype(&exp10l), crabc_exp10l_signature),
    "GNU exp10l C++ declaration");
static_assert(__is_same(decltype(&pow10), crabc_pow10_signature),
    "GNU pow10 C++ declaration");
static_assert(__is_same(decltype(&pow10f), crabc_pow10f_signature),
    "GNU pow10f C++ declaration");
static_assert(__is_same(decltype(&pow10l), crabc_pow10l_signature),
    "GNU pow10l C++ declaration");
static_assert(__is_same(decltype(&lgammal_r), crabc_lgammal_r_signature),
    "GNU lgammal_r C++ declaration");
__attribute__((used)) static crabc_sincos_signature crabc_gnu_sincos = &sincos;
__attribute__((used)) static crabc_exp10_signature crabc_gnu_exp10 = &exp10;
__attribute__((used)) static crabc_exp10f_signature crabc_gnu_exp10f = &exp10f;
__attribute__((used)) static crabc_exp10l_signature crabc_gnu_exp10l = &exp10l;
__attribute__((used)) static crabc_pow10_signature crabc_gnu_pow10 = &pow10;
__attribute__((used)) static crabc_pow10f_signature crabc_gnu_pow10f = &pow10f;
__attribute__((used)) static crabc_pow10l_signature crabc_gnu_pow10l = &pow10l;
__attribute__((used)) static crabc_lgammal_r_signature crabc_gnu_lgammal_r = &lgammal_r;
#elif defined(CRABC_FEATURE_HEADER_MATH_BSD_HIDDEN)
#include <math.h>
/* This mode is a deliberate expected-failure witness. */
__attribute__((used)) static auto crabc_bsd_must_hide_sincos = &sincos;
__attribute__((used)) static auto crabc_bsd_must_hide_exp10 = &exp10;
__attribute__((used)) static auto crabc_bsd_must_hide_exp10f = &exp10f;
__attribute__((used)) static auto crabc_bsd_must_hide_exp10l = &exp10l;
__attribute__((used)) static auto crabc_bsd_must_hide_pow10 = &pow10;
__attribute__((used)) static auto crabc_bsd_must_hide_pow10f = &pow10f;
__attribute__((used)) static auto crabc_bsd_must_hide_pow10l = &pow10l;
__attribute__((used)) static auto crabc_bsd_must_hide_lgammal_r = &lgammal_r;
#elif defined(CRABC_FEATURE_HEADER_PTHREAD_HIDDEN)
#include <pthread.h>
/* These declarations belong to musl's direct <signal.h> surface, not here. */
__attribute__((used)) static auto crabc_pthread_must_hide_kill = &pthread_kill;
__attribute__((used)) static auto crabc_pthread_must_hide_sigmask = &pthread_sigmask;
#endif

extern "C" int crabc_x86_64_feature_profile_control_plane_probe_cpp(void)
{
    return 0;
}

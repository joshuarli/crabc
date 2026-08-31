/* C++17 companion for the Linux/x86-64 <time.h> clock_getcpuclockid gate. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <time.h>

#if defined(CRABC_EXPECT_CLOCK_GETCPUCLOCKID)
static_assert(sizeof(pid_t) == 4, "x86 pid_t width");
static_assert(sizeof(clockid_t) == 4, "x86 clockid_t width");
static_assert(sizeof(struct timespec) == 16, "x86 timespec size");
static_assert(alignof(struct timespec) == 8, "x86 timespec alignment");
static_assert(CLOCK_PROCESS_CPUTIME_ID == 2, "Linux process CPU-clock ID");

using clock_getcpuclockid_signature = int (*)(pid_t, clockid_t *);

static_assert(__is_same(decltype(&clock_getcpuclockid),
    clock_getcpuclockid_signature), "C++ clock_getcpuclockid declaration");

static clock_getcpuclockid_signature clock_getcpuclockid_function =
    clock_getcpuclockid;

extern "C" int crabc_x86_64_clock_getcpuclockid_header_abi_probe_cpp()
{
    return clock_getcpuclockid_function != nullptr ? 0 : 1;
}
#else
/* The runner requires this reference to be rejected in strict profiles. */
int crabc_x86_64_clock_getcpuclockid_hidden_probe_cpp()
{
    return clock_getcpuclockid != nullptr;
}
#endif

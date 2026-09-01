/* C++ companion for the Linux/x86-64 GNU/BSD wait3/wait4 header probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/wait.h>

#if defined(CRABC_WAIT_EXTENSIONS_VISIBLE)

using wait3_signature = pid_t (*)(int *, int, struct rusage *);
using wait4_signature = pid_t (*)(pid_t, int *, int, struct rusage *);

static_assert(__is_same(decltype(&wait3), wait3_signature),
    "wait3 declaration");
static_assert(__is_same(decltype(&wait4), wait4_signature),
    "wait4 declaration");
static_assert(sizeof(pid_t) == 4 && alignof(pid_t) == 4, "x86 pid_t ABI");
static_assert(sizeof(struct rusage) == 272 && alignof(struct rusage) == 8,
    "x86 public rusage ABI");
static_assert(__builtin_offsetof(struct rusage, ru_utime) == 0 &&
    __builtin_offsetof(struct rusage, ru_stime) == 16 &&
    __builtin_offsetof(struct rusage, ru_maxrss) == 32 &&
    __builtin_offsetof(struct rusage, ru_nivcsw) == 136 &&
    __builtin_offsetof(struct rusage, __reserved) == 144 &&
    sizeof(((struct rusage *)0)->__reserved) == 128,
    "x86 wait4 rusage prefix and caller tail");
static_assert(WNOHANG == 1 && WUNTRACED == 2 && WCONTINUED == 8,
    "wait4 option values");

static wait3_signature wait3_function = wait3;
static wait4_signature wait4_function = wait4;

int crabc_x86_64_wait_extensions_header_abi_probe_cpp()
{
    return wait3_function(static_cast<int *>(nullptr), WNOHANG,
               static_cast<struct rusage *>(nullptr)) == -1 &&
        wait4_function(static_cast<pid_t>(-1), static_cast<int *>(nullptr),
            WNOHANG, static_cast<struct rusage *>(nullptr)) == -1
        ? 0 : 1;
}

#elif defined(CRABC_WAIT_EXTENSIONS_EXPECT_HIDDEN)

/* Strict and POSIX C++ must not see these GNU/BSD extension declarations. */
int crabc_x86_64_wait_extensions_header_hidden_probe_cpp()
{
    return wait3(static_cast<int *>(nullptr), WNOHANG,
               static_cast<struct rusage *>(nullptr)) +
        wait4(static_cast<pid_t>(-1), static_cast<int *>(nullptr), WNOHANG,
            static_cast<struct rusage *>(nullptr));
}

#else
#error "the runner must select visible or hidden wait-extension coverage"
#endif

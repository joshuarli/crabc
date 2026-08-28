/* Source-only Linux/x86-64 <sys/wait.h> child-reaping declaration probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/wait.h>

typedef pid_t (*wait_signature)(int *);
typedef pid_t (*waitpid_signature)(pid_t, int *, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&wait), wait_signature),
    "wait declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&waitpid),
    waitpid_signature), "waitpid declaration");

static wait_signature wait_function = wait;
static waitpid_signature waitpid_function = waitpid;

#if defined(CRABC_CHILD_REAPING_POSIX)
typedef int (*waitid_signature)(idtype_t, id_t, siginfo_t *, int);

_Static_assert(__builtin_types_compatible_p(__typeof__(&waitid),
    waitid_signature), "waitid declaration");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(siginfo_t) == 128 && _Alignof(siginfo_t) == 8,
    "x86 siginfo_t ABI");
_Static_assert(__builtin_offsetof(siginfo_t, si_signo) == 0 &&
    __builtin_offsetof(siginfo_t, si_errno) == 4 &&
    __builtin_offsetof(siginfo_t, si_code) == 8 &&
    __builtin_offsetof(siginfo_t, si_pid) == 16 &&
    __builtin_offsetof(siginfo_t, si_uid) == 20 &&
    __builtin_offsetof(siginfo_t, si_status) == 24,
    "x86 child siginfo fields");
_Static_assert(P_ALL == 0 && P_PID == 1 && P_PGID == 2,
    "wait id-type values");
_Static_assert(WNOHANG == 1 && WEXITED == 4 && WNOWAIT == 0x01000000,
    "wait option values");
_Static_assert(CLD_EXITED == 1, "child-exit code");

static waitid_signature waitid_function = waitid;
#endif

int crabc_x86_64_child_reaping_header_abi_probe(void)
{
    int status = 0;

    return wait_function(&status) == -1 &&
        waitpid_function((pid_t)-1, &status, WNOHANG) == -1
#if defined(CRABC_CHILD_REAPING_POSIX)
        && waitid_function(P_ALL, 0, (siginfo_t *)0, WEXITED | WNOHANG) == -1
#endif
        ? 0 : 1;
}

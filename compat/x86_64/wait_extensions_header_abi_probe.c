/* Source-only Linux/x86-64 GNU/BSD <sys/wait.h> wait3/wait4 ABI probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <sys/wait.h>

#if defined(CRABC_WAIT_EXTENSIONS_VISIBLE)

typedef pid_t (*wait3_signature)(int *, int, struct rusage *);
typedef pid_t (*wait4_signature)(pid_t, int *, int, struct rusage *);

_Static_assert(__builtin_types_compatible_p(__typeof__(&wait3),
    wait3_signature), "wait3 declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&wait4),
    wait4_signature), "wait4 declaration");
_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(struct rusage) == 272 && _Alignof(struct rusage) == 8,
    "x86 public rusage ABI");
_Static_assert(__builtin_offsetof(struct rusage, ru_utime) == 0 &&
    __builtin_offsetof(struct rusage, ru_stime) == 16 &&
    __builtin_offsetof(struct rusage, ru_maxrss) == 32 &&
    __builtin_offsetof(struct rusage, ru_nivcsw) == 136 &&
    __builtin_offsetof(struct rusage, __reserved) == 144 &&
    sizeof(((struct rusage *)0)->__reserved) == 128,
    "x86 wait4 rusage prefix and caller tail");
_Static_assert(WNOHANG == 1 && WUNTRACED == 2 && WCONTINUED == 8,
    "wait4 option values");

static wait3_signature wait3_function = wait3;
static wait4_signature wait4_function = wait4;

int crabc_x86_64_wait_extensions_header_abi_probe(void)
{
    return wait3_function((int *)0, WNOHANG, (struct rusage *)0) == -1 &&
        wait4_function((pid_t)-1, (int *)0, WNOHANG,
            (struct rusage *)0) == -1
        ? 0 : 1;
}

#elif defined(CRABC_WAIT_EXTENSIONS_EXPECT_HIDDEN)

/* The runner expects this translation unit to fail in strict/POSIX profiles.
 * A declaration leak makes either reference compile, which is precisely the
 * feature-test regression this branch catches. */
int crabc_x86_64_wait_extensions_header_hidden_probe(void)
{
    return wait3((int *)0, WNOHANG, (struct rusage *)0) +
        wait4((pid_t)-1, (int *)0, WNOHANG, (struct rusage *)0);
}

#else
#error "the runner must select visible or hidden wait-extension coverage"
#endif

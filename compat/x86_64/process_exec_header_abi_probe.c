/* Linux/x86-64 <unistd.h> process-exec declaration profile probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

typedef int (*exec_path_variadic_signature)(const char *, const char *, ...);
typedef int (*exec_vector_signature)(const char *, char *const []);
typedef int (*exec_environment_signature)(const char *, char *const [],
    char *const []);
typedef int (*fexecve_signature)(int, char *const [], char *const []);

/* These seven POSIX/XSI forms are unconditional musl public surface. */
_Static_assert(__builtin_types_compatible_p(__typeof__(&execl),
    exec_path_variadic_signature), "execl declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execle),
    exec_path_variadic_signature), "execle declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execlp),
    exec_path_variadic_signature), "execlp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execv),
    exec_vector_signature), "execv declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execve),
    exec_environment_signature), "execve declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&execvp),
    exec_vector_signature), "execvp declaration");
_Static_assert(__builtin_types_compatible_p(__typeof__(&fexecve),
    fexecve_signature), "fexecve declaration");

__attribute__((used)) static exec_path_variadic_signature execl_function = execl;
__attribute__((used)) static exec_path_variadic_signature execle_function = execle;
__attribute__((used)) static exec_path_variadic_signature execlp_function = execlp;
__attribute__((used)) static exec_vector_signature execv_function = execv;
__attribute__((used)) static exec_environment_signature execve_function = execve;
__attribute__((used)) static exec_vector_signature execvp_function = execvp;
__attribute__((used)) static fexecve_signature fexecve_function = fexecve;

/* musl publishes execvpe only through its GNU/BSD extension profile. */
#if defined(CRABC_EXPECT_EXECVPE)
_Static_assert(__builtin_types_compatible_p(__typeof__(&execvpe),
    exec_environment_signature), "execvpe declaration");
__attribute__((used)) static exec_environment_signature execvpe_function = execvpe;
#endif

/* This branch is compiled only by the negative profile checks below. */
#if defined(CRABC_REQUIRE_EXECVPE_HIDDEN)
__attribute__((used)) static exec_environment_signature execvpe_must_be_hidden =
    execvpe;
#endif

int crabc_x86_64_process_exec_header_abi_probe(void)
{
    (void)execl_function;
    (void)execle_function;
    (void)execlp_function;
    (void)execv_function;
    (void)execve_function;
    (void)execvp_function;
    (void)fexecve_function;
#if defined(CRABC_EXPECT_EXECVPE)
    (void)execvpe_function;
#endif
#if defined(CRABC_REQUIRE_EXECVPE_HIDDEN)
    (void)execvpe_must_be_hidden;
#endif
    return 0;
}

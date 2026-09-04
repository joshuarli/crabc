/* C++17 companion for the Linux/x86-64 <unistd.h> process-exec probe. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this probe requires native Linux/x86-64 little-endian LP64"
#endif

#include <unistd.h>

using exec_path_variadic_signature = int (*)(const char *, const char *, ...);
using exec_vector_signature = int (*)(const char *, char *const []);
using exec_environment_signature = int (*)(const char *, char *const [],
                                          char *const []);
using fexecve_signature = int (*)(int, char *const [], char *const []);

static_assert(__is_same(decltype(&execl), exec_path_variadic_signature),
              "C++ execl declaration");
static_assert(__is_same(decltype(&execle), exec_path_variadic_signature),
              "C++ execle declaration");
static_assert(__is_same(decltype(&execlp), exec_path_variadic_signature),
              "C++ execlp declaration");
static_assert(__is_same(decltype(&execv), exec_vector_signature),
              "C++ execv declaration");
static_assert(__is_same(decltype(&execve), exec_environment_signature),
              "C++ execve declaration");
static_assert(__is_same(decltype(&execvp), exec_vector_signature),
              "C++ execvp declaration");
static_assert(__is_same(decltype(&fexecve), fexecve_signature),
              "C++ fexecve declaration");

__attribute__((used)) static exec_path_variadic_signature execl_function = execl;
__attribute__((used)) static exec_path_variadic_signature execle_function = execle;
__attribute__((used)) static exec_path_variadic_signature execlp_function = execlp;
__attribute__((used)) static exec_vector_signature execv_function = execv;
__attribute__((used)) static exec_environment_signature execve_function = execve;
__attribute__((used)) static exec_vector_signature execvp_function = execvp;
__attribute__((used)) static fexecve_signature fexecve_function = fexecve;

#if defined(CRABC_EXPECT_EXECVPE)
static_assert(__is_same(decltype(&execvpe), exec_environment_signature),
              "C++ execvpe declaration");
__attribute__((used)) static exec_environment_signature execvpe_function = execvpe;
#endif

#if defined(CRABC_REQUIRE_EXECVPE_HIDDEN)
__attribute__((used)) static exec_environment_signature execvpe_must_be_hidden =
    execvpe;
#endif

int crabc_x86_64_process_exec_header_abi_probe_cpp()
{
    return execl_function == nullptr || execle_function == nullptr ||
           execlp_function == nullptr || execv_function == nullptr ||
           execve_function == nullptr || execvp_function == nullptr ||
           fexecve_function == nullptr;
}

/* Static crabc-libc x86-64 C11 immediate-termination compatibility fixture. */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <signal.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

_Static_assert(SYS_clone == 56 && SYS_exit == 60 && SYS_exit_group == 231 &&
    SYS_wait4 == 61, "x86 immediate-termination syscall numbers");

static long raw_syscall4(long number, long argument1, long argument2,
                         long argument3, long argument4)
{
    long result;
    register long register4 __asm__("r10") = argument4;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4)
        : "rcx", "r11", "memory");
    return result;
}

static long raw_syscall5(long number, long argument1, long argument2,
                         long argument3, long argument4, long argument5)
{
    long result;
    register long register4 __asm__("r10") = argument4;
    register long register5 __asm__("r8") = argument5;

    __asm__ volatile(
        "syscall"
        : "=a"(result)
        : "a"(number), "D"(argument1), "S"(argument2), "d"(argument3),
          "r"(register4), "r"(register5)
        : "rcx", "r11", "memory");
    return result;
}

/* clone can resume in an independent child execution context. */
static __attribute__((noinline, returns_twice)) long raw_clone_sigchld(void)
{
    return raw_syscall5(SYS_clone, SIGCHLD, 0, 0, 0, 0);
}

/* Fixture cleanup/observation deliberately avoids the selected _Exit symbol. */
static int wait_for_child(pid_t child, int expected_status)
{
    int status;
    long result;

    do {
        result = raw_syscall4(SYS_wait4, child, (long)&status, 0, 0);
    } while (result == -4);
    return result == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == expected_status;
}

static int immediate_termination_case(void)
{
    long child = raw_clone_sigchld();

    if (child == 0)
        _Exit(37);
    if (child < 0)
        return 1;
    return wait_for_child((pid_t)child, 37) ? 0 : 2;
}

#if defined(CRABC_IMMEDIATE_TERMINATION_FREESTANDING)
int crabc_x86_64_immediate_termination_probe(void)
{
    return immediate_termination_case();
}
#else
int main(void)
{
    return immediate_termination_case();
}
#endif

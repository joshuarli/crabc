/* Fixture-owned static-Pie lifecycle seam for the CRT -> libc TLS handoff.
 *
 * This intentionally is not x86 libc's public __libc_start_main. Real rcrt1
 * passes the lifecycle callbacks after libc has installed Static Initial TLS;
 * the seam merely orders init, main, fini, and exit_group for this one proof.
 */

#include <stddef.h>

typedef int (*application_main)(int, char **, char **);
typedef void (*lifecycle_hook)(void);

static void finish(int status) __attribute__((noreturn));

static void finish(int status)
{
    register unsigned long number __asm__("rax") = 231;
    register unsigned long code __asm__("rdi") = (unsigned int)status;

    __asm__ volatile("syscall" : "+a"(number) : "D"(code) : "rcx", "r11", "memory");
    __builtin_unreachable();
}

void __libc_start_main(
    application_main application,
    int argc,
    char **argv,
    void *init,
    void *fini,
    void *rtld_fini)
{
    lifecycle_hook init_hook = init;
    lifecycle_hook fini_hook = fini;
    char **envp;
    int status;

    if (application == 0 || argc < 0 || argv == 0 || rtld_fini != 0)
        finish(126);
    envp = argv + (unsigned int)argc + 1;
    if (init_hook != 0)
        init_hook();
    status = application(argc, argv, envp);
    if (fini_hook != 0)
        fini_hook();
    finish(status);
}

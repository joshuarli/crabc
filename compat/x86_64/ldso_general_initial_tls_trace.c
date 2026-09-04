/*
 * Small native harness that traces only ARCH_SET_FS in an expected-failing
 * candidate launch. It lets ELF negative fixtures prove their rejection
 * occurs before a general initial TLS transaction can install a new FS base.
 */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
    SYS_ARCH_PRCTL_X86_64 = 158,
    ARCH_SET_FS_X86_64 = 0x1002,
};

int main(int argc, char **argv) {
    if (argc < 2) {
        fputs("usage: ldso_general_initial_tls_trace PROGRAM [ARG...]\n", stderr);
        return 64;
    }

    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 65;
    }
    if (child == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) != 0) _exit(66);
        raise(SIGSTOP);
        execv(argv[1], &argv[1]);
        _exit(67);
    }

    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) {
        fputs("trace child did not stop\n", stderr);
        return 68;
    }
    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL) != 0
        || ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) {
        perror("ptrace setup");
        return 69;
    }

    int entering_syscall = 1;
    int saw_arch_set_fs = 0;
    for (;;) {
        if (waitpid(child, &status, 0) != child) {
            perror("waitpid");
            return 70;
        }
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) != 127) {
                fprintf(stderr, "candidate exit was %d, expected 127\n", WEXITSTATUS(status));
                return 71;
            }
            if (saw_arch_set_fs) {
                fputs("candidate executed ARCH_SET_FS before rejection\n", stderr);
                return 72;
            }
            return 0;
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "candidate died from signal %d\n", WTERMSIG(status));
            return 73;
        }
        if (!WIFSTOPPED(status)) {
            fputs("unexpected trace status\n", stderr);
            return 74;
        }

        int signal_number = WSTOPSIG(status);
        if (signal_number == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, 0, &regs) != 0) {
                perror("ptrace registers");
                return 75;
            }
            if (entering_syscall
                && regs.orig_rax == SYS_ARCH_PRCTL_X86_64
                && regs.rdi == ARCH_SET_FS_X86_64) {
                saw_arch_set_fs = 1;
            }
            entering_syscall = !entering_syscall;
            if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) {
                perror("ptrace syscall");
                return 76;
            }
            continue;
        }

        if (signal_number != SIGTRAP) {
            // Suppressing SIGSEGV/SIGILL would re-execute the faulting
            // instruction forever. Kill and reap this exact owned child.
            fprintf(stderr, "candidate stopped by signal %d\n", signal_number);
            kill(child, SIGKILL);
            waitpid(child, &status, 0);
            return 73;
        }
        if (ptrace(PTRACE_SYSCALL, child, 0, 0) != 0) {
            perror("ptrace signal");
            return 77;
        }
    }
}

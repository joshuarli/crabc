/* Count successful loader FS installations across the actual exec lifecycle. */
#include <signal.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 2) return 64;
    pid_t child = fork();
    if (child < 0) return 65;
    if (!child) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0)) _exit(66);
        raise(SIGSTOP);
        execv(argv[1], &argv[1]);
        _exit(67);
    }
    int status, entering = 1, pending_set_fs = 0, attempts = 0, successes = 0;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 68;
    if (ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD)
        || ptrace(PTRACE_SYSCALL, child, 0, 0)) return 69;
    for (;;) {
        if (waitpid(child, &status, 0) != child) return 70;
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) != 19 || attempts != 1 || successes != 1) {
                fprintf(stderr, "exit=%d ARCH_SET_FS attempts=%d successes=%d\n",
                        WEXITSTATUS(status), attempts, successes);
                return 71;
            }
            return 0;
        }
        if (!WIFSTOPPED(status)) return 72;
        int signal_number = WSTOPSIG(status);
        if (signal_number == (SIGTRAP | 0x80)) {
            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child, 0, &regs)) return 73;
            if (entering) {
                pending_set_fs = regs.orig_rax == 158 && regs.rdi == 0x1002;
                attempts += pending_set_fs;
            } else if (pending_set_fs && regs.rax == 0) {
                successes++;
            }
            entering = !entering;
        } else if (signal_number != SIGTRAP) {
            fprintf(stderr, "unexpected trace signal %d\n", signal_number);
            return 74;
        }
        if (ptrace(PTRACE_SYSCALL, child, 0, 0)) return 75;
    }
}

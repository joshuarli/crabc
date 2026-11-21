#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned long read_word(pid_t child, unsigned long address) {
    errno = 0;
    long value = ptrace(PTRACE_PEEKDATA, child, (void *)address, 0);
    if (value == -1 && errno) { perror("ptrace read"); exit(1); }
    return (unsigned long)value;
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    pid_t child = fork();
    if (child < 0) { perror("fork"); return 1; }
    if (!child) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) || chroot(argv[1]) || chdir("/")) _exit(125);
        execl("/work/probe", "probe", (char *)0);
        _exit(126);
    }
    int status;
    if (waitpid(child, &status, 0) != child || !WIFSTOPPED(status)) return 1;
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, child, 0, &regs)) { perror("ptrace registers"); return 1; }
    unsigned long p = regs.rsp;
    unsigned long count = read_word(child, p);
    p += (count + 2) * sizeof(long);
    while (read_word(child, p)) p += sizeof(long);
    p += sizeof(long);
    for (;;) {
        unsigned long tag = read_word(child, p);
        if (!tag) { fputs("AT_SECURE missing\n", stderr); return 1; }
        if (tag == 23) break;
        p += 2 * sizeof(long);
    }
    if (ptrace(PTRACE_POKEDATA, child, (void *)(p + sizeof(long)), (void *)1)) {
        perror("ptrace write"); return 1;
    }
    if (ptrace(PTRACE_DETACH, child, 0, 0)) { perror("ptrace detach"); return 1; }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 1;
    return WEXITSTATUS(status);
}

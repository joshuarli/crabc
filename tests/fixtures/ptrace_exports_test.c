#include <errno.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    pid_t child;
    int status;

    child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        errno = 0;
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0 || errno == EPERM)
            _exit(0);
        _exit(2);
    }
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
        WEXITSTATUS(status) != 0)
        return 3;

    errno = 0;
    /* Linux resolves the supplied tracee before rejecting this unknown
     * request; pid zero has no tracee here, so the real syscall returns ESRCH. */
    if (ptrace(-1, 0, NULL, NULL) != -1 || errno != ESRCH)
        return 4;
    puts("c-abi ptrace exports ok");
    return 0;
}

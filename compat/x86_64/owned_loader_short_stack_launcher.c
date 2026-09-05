// Exec one target with the libc-test upstream stack limit.
//
// This is an oracle-built launcher so its own startup cannot borrow either
// candidate loader. It enters a disposable target root in the child, then
// preserves the ordinary inherited environment, matching libc-test's `execv`
// child path. Its setrlimit sequence matches the pinned
// src/common/{runtest,setrlim}.c path: set both stack limits to 100 KiB
// immediately before exec.
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

enum { SHORT_STACK_LIMIT = 100 * 1024 };

int main(int argc, char **argv) {
    if (argc != 3)
        return 64;

    pid_t child = fork();
    if (child < 0)
        return 65;
    if (child != 0) {
        int status;
        if (waitpid(child, &status, 0) != child)
            return 66;
        if (WIFEXITED(status))
            return WEXITSTATUS(status);
        return WIFSIGNALED(status) ? 128 + WTERMSIG(status) : 67;
    }

    if (chroot(argv[1]) != 0 || chdir("/") != 0)
        _exit(68);

    struct rlimit limit;
    if (getrlimit(RLIMIT_STACK, &limit) != 0 || limit.rlim_max < SHORT_STACK_LIMIT)
        _exit(69);
    limit.rlim_max = SHORT_STACK_LIMIT;
    limit.rlim_cur = SHORT_STACK_LIMIT;
    if (setrlimit(RLIMIT_STACK, &limit) != 0 || getrlimit(RLIMIT_STACK, &limit) != 0 ||
        limit.rlim_cur != SHORT_STACK_LIMIT || limit.rlim_max != SHORT_STACK_LIMIT)
        _exit(70);

    char *const target_argv[] = {argv[2], 0};
    execv(argv[2], target_argv);
    _exit(127);
}

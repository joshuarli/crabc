#include "unistd.h"
#include "stdio.h"
#include "stdlib.h"
#include "errno.h"
#include <sys/wait.h>

int main(void) {
    int status = -1;
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid == 0) {
        _exit(42);
    }
    pid_t w = waitpid(pid, &status, 0);
    if (w != pid) return 2;
    if (!WIFEXITED(status)) return 3;
    if (WEXITSTATUS(status) != 42) return 4;

    pid = fork();
    if (pid < 0) return 5;
    if (pid == 0) {
        char *const argv[] = {(char*)"/bin/true", NULL};
        char *const envp[] = {NULL};
        execve("/bin/true", argv, envp);
        _exit(99);
    }
    w = wait(&status);
    if (w != pid) return 6;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 7;

    if (getpid() <= 0) return 8;
    if (getppid() <= 0) return 9;
    if (getuid() == (uid_t)-1) return 10;
    if (getgid() == (gid_t)-1) return 11;

    /* waitpid must retain the POSIX no-child and WNOHANG contracts. */
    int gate[2];
    if (pipe(gate) != 0) return 12;
    pid = fork();
    if (pid < 0) return 13;
    if (pid == 0) {
        char byte;
        if (read(gate[0], &byte, 1) != 1) _exit(98);
        _exit(7);
    }
    if (waitpid(pid, &status, WNOHANG) != 0) return 14;
    if (write(gate[1], "x", 1) != 1) return 15;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 7)
        return 16;
    errno = 0;
    if (waitpid(pid, &status, WNOHANG) != -1 || errno != ECHILD) return 17;

    {
        char *const argv[] = {(char*)"missing", NULL};
        char *const envp[] = {NULL};
        errno = 0;
        if (execve("/definitely-not-a-program", argv, envp) != -1 || errno != ENOENT) return 18;
    }

    puts("process ok");
    return 0;
}

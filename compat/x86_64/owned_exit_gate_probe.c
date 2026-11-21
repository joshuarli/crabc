#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static _Atomic int entered, contender;
static char buffer[64];

static void handler(void)
{
    atomic_store(&entered, 1);
    while (!atomic_load(&contender)) sched_yield();
    for (int i = 0; i < 1000; ++i) sched_yield();
    if (write(1, "H", 1) != 1) _Exit(127);
}

static void *worker(void *unused)
{
    (void)unused;
    exit(42);
}

static void recursive(void) { exit(43); }

static void child(void)
{
    pthread_t thread;
    if (setvbuf(stdout, buffer, _IOFBF, sizeof buffer) || fputs("S", stdout) < 0 ||
        atexit(handler) || pthread_create(&thread, NULL, worker, NULL)) _Exit(127);
    while (!atomic_load(&entered)) sched_yield();
    atomic_store(&contender, 1);
    exit(42);
}

int main(void)
{
    for (int i = 0; i < 200; ++i) {
        int pipefd[2], status;
        char output[8];
        if (pipe(pipefd)) return 1;
        pid_t pid = fork();
        if (pid < 0) return 1;
        if (!pid) {
            close(pipefd[0]);
            if (dup2(pipefd[1], 1) < 0) _Exit(127);
            close(pipefd[1]);
            child();
        }
        close(pipefd[1]);
        ssize_t count = 0, n;
        while (count < (ssize_t)sizeof output && (n = read(pipefd[0], output + count, sizeof output - count)) > 0) count += n;
        close(pipefd[0]);
        if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 42 ||
            count != 2 || memcmp(output, "HS", 2)) {
            fprintf(stderr, "contention iteration %d: status=%d output bytes=%zd\n", i, status, count);
            return 1;
        }
    }
    int status;
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (!pid) {
        if (atexit(recursive)) _Exit(127);
        exit(42);
    }
    if (waitpid(pid, &status, 0) != pid || !WIFSIGNALED(status)) {
        fprintf(stderr, "recursive exit: status=%d, expected signal\n", status);
        return 1;
    }
    puts("exit gate: 200 contention iterations and recursive signal PASS");
    return 0;
}

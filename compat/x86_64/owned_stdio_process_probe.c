#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <pthread.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "process:%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
static volatile sig_atomic_t interrupted;
static void handler(int sig) { (void)sig; interrupted = 1; }
/* Test-only Linux/x86 fault injection: deny execve in an isolated fork child.
   No production fallback, privilege, host filesystem mutation, or kernel-header
   dependency. These are Linux sock_filter/prctl ABI records, not a runtime API. */
struct filter_instruction { unsigned short code; unsigned char yes, no; unsigned value; };
struct filter_program { unsigned short count; struct filter_instruction *instructions; };
static long raw_prctl(long operation, long value, long pointer) {
    register long fourth __asm__("r10") = 0;
    register long fifth __asm__("r8") = 0;
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(157L), "D"(operation),
        "S"(value), "d"(pointer), "r"(fourth), "r"(fifth) : "rcx", "r11", "memory");
    return result;
}
static int denied_exec(void) {
    struct filter_instruction instructions[] = {
        {0x20, 0, 0, 0}, {0x15, 0, 1, 59},
        {0x06, 0, 0, 0x50000 | EACCES}, {0x06, 0, 0, 0x7fff0000}
    };
    struct filter_program program = {4, instructions};
    CHECK(raw_prctl(38, 1, 0) == 0);
    CHECK(raw_prctl(22, 2, (long)&program) == 0);
    errno = 0;
    CHECK(!popen("exit 0", "r") && errno == EACCES);
    errno = 0;
    CHECK(system("exit 0") == -1 && errno == EACCES);
    errno = 0;
    CHECK(waitpid(-1, NULL, WNOHANG) == -1 && errno == ECHILD);
    int fd = dup(STDIN_FILENO);
    CHECK(fd == 3 && !close(fd));
    return 0;
}
static void *worker(void *unused) {
    (void)unused;
    FILE *f = popen("printf worker", "r");
    char s[16] = {0};
    if (!f || fread(s, 1, sizeof s, f) != 6 || strcmp(s, "worker") || pclose(f))
        return (void *)1;
    return 0;
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    alarm(20);
    errno = 0;
    CHECK(!popen("exit 0", "bad") && errno == EINVAL);
    FILE *first = popen("printf 'alpha\\nbeta'; exit 23", "r");
    CHECK(first);
    int descriptor = fileno(first), flags = fcntl(descriptor, F_GETFD);
    CHECK(flags >= 0 && !(flags & FD_CLOEXEC));
    char command[1024], bytes[32] = {0};
    CHECK(snprintf(command, sizeof command, "test ! -e /proc/self/fd/%d", descriptor) > 0);
    FILE *second = popen(command, "re");
    CHECK(second);
    flags = fcntl(fileno(second), F_GETFD);
    CHECK(flags >= 0 && (flags & FD_CLOEXEC));
    CHECK(pclose(second) == 0);
    CHECK(fread(bytes, 1, sizeof bytes, first) == 10 && !memcmp(bytes, "alpha\nbeta", 10));
    CHECK(feof(first) && !ferror(first));
    int status = pclose(first);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 23);
    CHECK(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
    /* Private argv path is supplied by the harness; environment avoids shell quoting. */
    CHECK(!setenv("CRABC_PROCESS_PATH", argv[1], 1));
    first = popen("cat >\"$CRABC_PROCESS_PATH\"", "we");
    CHECK(first && fwrite("buffered-child\n", 1, 15, first) == 15 && pclose(first) == 0);
    first = fopen(argv[1], "r");
    CHECK(first && fread(bytes, 1, sizeof bytes, first) == 15 && !memcmp(bytes, "buffered-child\n", 15));
    CHECK(!fclose(first));
    /* dup2(fd,fd) must clear CLOEXEC, including when stdin began closed. */
    int saved_input = dup(STDIN_FILENO);
    CHECK(saved_input >= 0 && !close(STDIN_FILENO));
    first = popen("cat >\"$CRABC_PROCESS_PATH\"", "w");
    CHECK(first && fputs("same-fd", first) >= 0 && pclose(first) == 0);
    CHECK(dup2(saved_input, STDIN_FILENO) == STDIN_FILENO && !close(saved_input));
    first = fopen(argv[1], "r");
    CHECK(first && fread(bytes, 1, sizeof bytes, first) == 7 && !memcmp(bytes, "same-fd", 7));
    CHECK(!fclose(first));
    first = popen("kill -TERM $$", "r");
    CHECK(first);
    status = pclose(first);
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
    first = popen("command_that_does_not_exist 2>/dev/null", "r");
    CHECK(first && WEXITSTATUS(pclose(first)) == 127);
    /* Child close actions must not close ordinary non-popen descriptors. */
    int ordinary = open(argv[1], O_RDONLY);
    CHECK(ordinary >= 0);
    snprintf(command, sizeof command, "test -e /proc/self/fd/%d", ordinary);
    first = popen(command, "r");
    CHECK(first && pclose(first) == 0 && close(ordinary) == 0);
    struct sigaction action = {0}, old_int, observed;
    action.sa_handler = handler;
    CHECK(!sigaction(SIGINT, &action, &old_int));
    sigset_t blocked, old_mask, now;
    sigemptyset(&blocked); sigaddset(&blocked, SIGUSR1);
    CHECK(!sigprocmask(SIG_BLOCK, &blocked, &old_mask));
    CHECK(system(NULL) == 1);
    status = system("exit 37");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 37);
    status = system("kill -INT $$");
    CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGINT);
    CHECK(!sigaction(SIGINT, NULL, &observed) && observed.sa_handler == handler);
    CHECK(!sigprocmask(SIG_SETMASK, NULL, &now) && sigismember(&now, SIGUSR1));
    CHECK(!sigprocmask(SIG_SETMASK, &old_mask, NULL));
    action.sa_handler = SIG_IGN;
    CHECK(!sigaction(SIGINT, &action, NULL));
    status = system("kill -INT $$; exit 41");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 41);
    CHECK(!sigaction(SIGINT, &old_int, NULL) && !interrupted);
    /* Source pclose retries an interrupted wait without reopening the FILE. */
    struct sigaction old_alarm;
    action.sa_handler = handler;
    CHECK(!sigaction(SIGALRM, &action, &old_alarm));
    first = popen("sleep 2; exit 19", "r");
    CHECK(first);
    alarm(1);
    status = pclose(first);
    CHECK(interrupted && WIFEXITED(status) && WEXITSTATUS(status) == 19);
    CHECK(!sigaction(SIGALRM, &old_alarm, NULL));
    alarm(20);
    pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, worker, NULL));
    void *result;
    CHECK(!pthread_join(thread, &result) && !result);
    pid_t failure_child = fork();
    CHECK(failure_child >= 0);
    if (!failure_child) _exit(denied_exec());
    CHECK(waitpid(failure_child, &status, 0) == failure_child && status == 0);
    struct sigaction old_child;
    action.sa_handler = SIG_IGN;
    CHECK(!sigaction(SIGCHLD, &action, &old_child));
    first = popen("exit 0", "r");
    CHECK(first);
    descriptor = fileno(first);
    errno = 0;
    CHECK(pclose(first) == -1 && errno == ECHILD);
    CHECK(fcntl(descriptor, F_GETFD) == -1 && errno == EBADF);
    CHECK(!sigaction(SIGCHLD, &old_child, NULL));
    struct rlimit limit, low;
    CHECK(!getrlimit(RLIMIT_NOFILE, &limit));
    low = limit; low.rlim_cur = 3;
    CHECK(!setrlimit(RLIMIT_NOFILE, &low));
    errno = 0; first = popen("exit 0", "r");
    int error = errno;
    CHECK(!setrlimit(RLIMIT_NOFILE, &limit));
    CHECK(!first && error == EMFILE);
    /* Failure creating spawn's error pipe consumes neither FILE nor pipe FDs. */
    low.rlim_cur = 5;
    CHECK(!setrlimit(RLIMIT_NOFILE, &low));
    errno = 0; first = popen("exit 0", "r"); error = errno;
    CHECK(!setrlimit(RLIMIT_NOFILE, &limit));
    CHECK(!first && error == EMFILE);
    int reopened = open(argv[1], O_RDONLY);
    CHECK(reopened == 3 && !close(reopened));
    CHECK(!unlink(argv[1]));
    puts("owned-process-ok");
    return 0;
}

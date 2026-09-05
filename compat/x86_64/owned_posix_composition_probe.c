/*
 * Joint process-state witness over the selected musl 1.2.6 contracts:
 * src/process/{fork,posix_spawn}.c, src/env, src/signal, src/stdio and
 * src/misc/syslog.c. Run only in the runner's disposable chroot.
 *
 * The worker stops reading environment storage before the parent mutates it.
 * A fork child performs only execve/_exit before entering the fresh image.
 * The FILE lock remains owned by the live parent worker until its registered
 * cancellation cleanup releases it; no child attempts to use that FILE.
 */
#define _GNU_SOURCE 1
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { fprintf(stderr, "composition:%s:%d errno=%d\n", __func__, __LINE__, errno); return 1; } } while (0)
extern char **environ;
static FILE *stream;
static int ready_pipe[2], wait_pipe[2];
static int cleanup_ran;
static volatile sig_atomic_t deliveries;

static void handler(int signal_number) { if (signal_number == SIGUSR1) ++deliveries; }

static int log_receiver(void)
{
    struct sockaddr_un address;
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, "/dev/log", sizeof "/dev/log");
    unlink(address.sun_path);
    if (bind(fd, (struct sockaddr *)&address, sizeof address)) { close(fd); return -1; }
    return fd;
}

static int log_record(int receiver, const char *payload)
{
    char bytes[1024];
    struct pollfd pollfd = { receiver, POLLIN, 0 };
    CHECK(poll(&pollfd, 1, 2000) == 1 && (pollfd.revents & POLLIN));
    ssize_t count = recv(receiver, bytes, sizeof bytes - 1, 0);
    CHECK(count > 0);
    bytes[count] = 0;
    CHECK(strstr(bytes, "composition: ") && strstr(bytes, payload));
    /* Keep the unmodified, time-bearing wire bytes for inspection separately
     * from the deterministic stdout comparison. */
    int archive = open("/log-wire", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    CHECK(archive >= 0 && write(archive, bytes, (size_t)count) == count);
    CHECK(close(archive) == 0);
    return 0;
}

static void release_stream(void *unused)
{
    (void)unused;
    funlockfile(stream);
    cleanup_ran = 1;
}

static void *worker(void *unused)
{
    char byte;
    sigset_t mask;
    (void)unused;
    if (!getenv("CRABC_COMPOSITION") || strcmp(getenv("CRABC_COMPOSITION"), "worker-view")) return (void *)1;
    sigemptyset(&mask); sigaddset(&mask, SIGTERM);
    if (pthread_sigmask(SIG_BLOCK, &mask, 0)) return (void *)2;
    if (pthread_sigmask(SIG_SETMASK, 0, &mask) || sigismember(&mask, SIGTERM) != 1) return (void *)3;
    syslog(LOG_NOTICE, "worker-before-fork");
    flockfile(stream);
    pthread_cleanup_push(release_stream, 0);
    if (write(ready_pipe[1], "r", 1) != 1) _exit(90);
    /* The parent keeps the write end open. This is a real cancellation point
     * even if its request arrives before this read begins. */
    if (read(wait_pipe[0], &byte, 1) != -1) _exit(91);
    pthread_cleanup_pop(1);
    return (void *)4;
}

static int child_image(const char *kind, const char *descriptor)
{
    sigset_t mask;
    struct sigaction action;
    CHECK(getenv("CRABC_COMPOSITION") && !strcmp(getenv("CRABC_COMPOSITION"), "child-view"));
    CHECK(sigprocmask(SIG_SETMASK, 0, &mask) == 0);
    CHECK(sigismember(&mask, SIGTERM) == 0);
    CHECK(sigismember(&mask, SIGUSR1) == (!strcmp(kind, "fork")));
    CHECK(sigismember(&mask, SIGUSR2) == (!strcmp(kind, "spawn")));
    CHECK(sigaction(SIGUSR1, 0, &action) == 0 && action.sa_handler == SIG_DFL);
    CHECK(sigaction(SIGUSR2, 0, &action) == 0);
    CHECK(action.sa_handler == (!strcmp(kind, "fork") ? SIG_IGN : SIG_DFL));
    errno = 0;
    CHECK(fcntl(atoi(descriptor), F_GETFD) == -1 && errno == EBADF);
    CHECK(setenv("CRABC_COMPOSITION", "child-private", 1) == 0);
    printf("composition-child-%s env=child-view mask=expected handlers=expected cloexec=EBADF\n", kind);
    return 0;
}

static int reap(pid_t child)
{
    int status;
    CHECK(waitpid(child, &status, 0) == child);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--child")) return child_image(argv[2], argv[3]);
    CHECK(argc == 1);
    int receiver = log_receiver();
    CHECK(receiver >= 0);
    CHECK(setenv("CRABC_COMPOSITION", "worker-view", 1) == 0);
    struct sigaction action;
    memset(&action, 0, sizeof action);
    sigemptyset(&action.sa_mask); action.sa_handler = handler;
    CHECK(sigaction(SIGUSR1, &action, 0) == 0);
    action.sa_handler = SIG_IGN;
    CHECK(sigaction(SIGUSR2, &action, 0) == 0);
    sigset_t mask;
    sigemptyset(&mask); sigaddset(&mask, SIGUSR1);
    CHECK(pthread_sigmask(SIG_SETMASK, &mask, 0) == 0);
    stream = fopen("/stream", "w+");
    CHECK(stream && fcntl(fileno(stream), F_SETFD, FD_CLOEXEC) == 0);
    char descriptor[24];
    /* fileno itself locks FILE in musl; capture the descriptor before the
     * worker deliberately holds that lock through process creation. */
    CHECK(snprintf(descriptor, sizeof descriptor, "%d", fileno(stream)) > 0);
    CHECK(fputs("before\n", stream) >= 0);
    CHECK(pipe2(ready_pipe, O_CLOEXEC) == 0 && pipe2(wait_pipe, O_CLOEXEC) == 0);
    openlog("composition", LOG_NDELAY, LOG_LOCAL3);
    setlogmask(LOG_UPTO(LOG_NOTICE));
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, worker, 0) == 0);
    char byte;
    CHECK(read(ready_pipe[0], &byte, 1) == 1 && byte == 'r');
    CHECK(log_record(receiver, "worker-before-fork") == 0);
    /* The pipe handoff ends all worker environment access and proves FILE
     * lock ownership before any parent mutation or process creation. */
    CHECK(ftrylockfile(stream) != 0);
    CHECK(setenv("CRABC_COMPOSITION", "child-view", 1) == 0);
    char *fork_arguments[] = { argv[0], "--child", "fork", descriptor, 0 };
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) { execve(argv[0], fork_arguments, environ); _exit(92); }
    CHECK(reap(child) == 0);
    CHECK(!strcmp(getenv("CRABC_COMPOSITION"), "child-view"));
    posix_spawnattr_t attributes;
    CHECK(posix_spawnattr_init(&attributes) == 0);
    sigemptyset(&mask); sigaddset(&mask, SIGUSR2);
    CHECK(posix_spawnattr_setsigmask(&attributes, &mask) == 0);
    CHECK(posix_spawnattr_setsigdefault(&attributes, &mask) == 0);
    CHECK(posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF) == 0);
    char *spawn_arguments[] = { argv[0], "--child", "spawn", descriptor, 0 };
    CHECK(posix_spawn(&child, argv[0], 0, &attributes, spawn_arguments, environ) == 0);
    CHECK(reap(child) == 0 && posix_spawnattr_destroy(&attributes) == 0);
    CHECK(!strcmp(getenv("CRABC_COMPOSITION"), "child-view"));
    CHECK(pthread_sigmask(SIG_SETMASK, 0, &mask) == 0);
    CHECK(sigismember(&mask, SIGUSR1) == 1 && sigismember(&mask, SIGUSR2) == 0 && sigismember(&mask, SIGTERM) == 0);
    CHECK(sigaction(SIGUSR1, 0, &action) == 0 && action.sa_handler == handler);
    CHECK(sigaction(SIGUSR2, 0, &action) == 0 && action.sa_handler == SIG_IGN);
    CHECK(pthread_cancel(thread) == 0);
    void *result;
    CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED && cleanup_ran == 1);
    CHECK(ftrylockfile(stream) == 0);
    CHECK(fputs("after\n", stream) >= 0 && fflush(stream) == 0);
    funlockfile(stream);
    CHECK(fseek(stream, 0, SEEK_SET) == 0);
    char contents[32] = {0};
    CHECK(fread(contents, 1, sizeof contents - 1, stream) == 13 && !strcmp(contents, "before\nafter\n"));
    CHECK(fclose(stream) == 0);
    CHECK(setlogmask(0) == LOG_UPTO(LOG_NOTICE));
    syslog(LOG_NOTICE, "parent-after-cancel");
    CHECK(log_record(receiver, "parent-after-cancel") == 0);
    closelog();
    CHECK(pthread_kill(pthread_self(), SIGUSR1) == 0);
    sigemptyset(&mask); sigaddset(&mask, SIGUSR1);
    CHECK(pthread_sigmask(SIG_UNBLOCK, &mask, 0) == 0 && deliveries == 1);
    CHECK(unsetenv("CRABC_COMPOSITION") == 0 && getenv("CRABC_COMPOSITION") == 0);
    CHECK(close(receiver) == 0);
    for (int index = 0; index < 2; ++index) {
        CHECK(close(ready_pipe[index]) == 0 && close(wait_pipe[index]) == 0);
    }
    puts("composition-parent env=preserved signals=preserved cleanup=1 stream=before+after log=preserved");
    return 0;
}

#define _GNU_SOURCE 1

#include <err.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

extern char *__progname;

static void call_vwarn(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vwarn(format, ap);
    va_end(ap);
}

static void call_vwarnx(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    vwarnx(format, ap);
    va_end(ap);
}

static void call_verr(int status, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    verr(status, format, ap);
}

static void call_verrx(int status, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    verrx(status, format, ap);
}

static int expect_exit(pid_t child, int status)
{
    int waited;
    if (waitpid(child, &waited, 0) != child || !WIFEXITED(waited))
        return 0;
    return WEXITSTATUS(waited) == status;
}

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

int main(void)
{
    siginfo_t info;
    pid_t child;

    /* Pin the diagnostic prefix so the integration assertion is stable. */
    __progname = "m4err";

    errno = ENOENT;
    warn("warn %s", "one");
    CHECK(errno == ENOENT, "warn errno");

    errno = EACCES;
    call_vwarn("vwarn %d", 2);
    CHECK(errno == EACCES, "vwarn errno");

    errno = EAGAIN;
    warnx("warnx %s", "three");
    CHECK(errno == EAGAIN, "warnx errno");

    errno = EINTR;
    call_vwarnx("vwarnx %d", 4);
    CHECK(errno == EINTR, "vwarnx errno");

    info = (siginfo_t){0};
    info.si_signo = SIGUSR1;
    errno = EALREADY;
    psiginfo(&info, "signal");
    CHECK(errno == EALREADY, "psiginfo errno");

    child = fork();
    CHECK(child >= 0, "fork err");
    if (child == 0) {
        errno = ENOENT;
        err(17, "err %s", "five");
    }
    CHECK(expect_exit(child, 17), "err status");

    child = fork();
    CHECK(child >= 0, "fork errx");
    if (child == 0)
        errx(18, "errx %s", "six");
    CHECK(expect_exit(child, 18), "errx status");

    child = fork();
    CHECK(child >= 0, "fork verr");
    if (child == 0) {
        errno = EACCES;
        call_verr(19, "verr %s", "seven");
    }
    CHECK(expect_exit(child, 19), "verr status");

    child = fork();
    CHECK(child >= 0, "fork verrx");
    if (child == 0) {
        errno = EACCES;
        call_verrx(20, "verrx %s", "eight");
    }
    CHECK(expect_exit(child, 20), "verrx status");

    puts("m4 error reporting ok");
    return 0;
}

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <fmtmsg.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { dprintf(1, "fmtmsg line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)

static const char full[] = "app: ERROR: message\nTO FIX: repair TAG\n";
static void expect_file(int fd, const char *expected) {
    char actual[512];
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    ssize_t n = read(fd, actual, sizeof actual);
    CHECK(n == (ssize_t)strlen(expected));
    CHECK(!memcmp(actual, expected, n));
}
static int first_free(void) {
    for (int fd = 3; fd < 128; fd++) {
        if (fcntl(fd, F_GETFD) == -1 && errno == EBADF) return fd;
    }
    CHECK(0); return -1;
}
static void ordinary(void) {
    int saved = dup(2);
    int output = open("/state/output", O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(saved >= 0 && output >= 0 && dup2(output, 2) == 2);
    struct { const char *verb, *expected; } cases[] = {
        {0, full}, {"", full}, {"unknown", full}, {"textual", full},
        {":text", full}, {"label::text", full},
        {"label", "app: \n"}, {"severity", "ERROR: \n"},
        {"text", "message\n"}, {"action", "\nTO FIX: repair \n"},
        {"tag", "TAG\n"}, {"tag:text", "messageTAG\n"},
        {"text:text:", "message\n"},
        {"label:severity:text:action:tag", full},
    };
    for (unsigned i = 0; i < sizeof cases / sizeof *cases; i++) {
        CHECK(cases[i].verb ? setenv("MSGVERB", cases[i].verb, 1) == 0 : unsetenv("MSGVERB") == 0);
        CHECK(ftruncate(output, 0) == 0 && lseek(output, 0, SEEK_SET) == 0);
        CHECK(fmtmsg(MM_PRINT, "app", MM_ERROR, "message", "repair", "TAG") == MM_OK);
        expect_file(output, cases[i].expected);
    }
    CHECK(unsetenv("MSGVERB") == 0);
    const char *severities[] = {"\n", "HALT: \n", "ERROR: \n", "WARNING: \n", "INFO: \n", "(null)\n"};
    for (int severity = 0; severity < 6; severity++) {
        CHECK(ftruncate(output, 0) == 0 && lseek(output, 0, SEEK_SET) == 0);
        CHECK(fmtmsg(MM_PRINT, 0, severity, 0, 0, 0) == MM_OK);
        expect_file(output, severities[severity]);
    }
    CHECK(ftruncate(output, 0) == 0 && lseek(output, 0, SEEK_SET) == 0);
    CHECK(fmtmsg(MM_PRINT, "", MM_NULLSEV, "", "", "") == MM_OK);
    expect_file(output, ": \nTO FIX:  \n");
    CHECK(ftruncate(output, 0) == 0 && lseek(output, 0, SEEK_SET) == 0);
    CHECK(fmtmsg(MM_HARD | MM_SOFT | MM_APPL | MM_UTIL | MM_OPSYS | MM_RECOVER | MM_NRECOV,
        "app", MM_ERROR, "message", "repair", "TAG") == MM_OK);
    expect_file(output, "");
    int previous, restored;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    CHECK(fmtmsg(0, 0, 0, 0, 0, 0) == MM_OK);
    CHECK(pthread_setcancelstate(previous, &restored) == 0 && restored == PTHREAD_CANCEL_DISABLE);
    CHECK(dup2(saved, 2) == 2 && close(saved) == 0 && close(output) == 0);
    puts("owned-fmtmsg-ordinary-ok");
}
static void console_and_errors(void) {
    int saved = dup(2);
    int output = open("/state/output", O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(saved >= 0 && output >= 0 && dup2(output, 2) == 2);
    int console = open("/dev/console", O_RDWR | O_CREAT | O_TRUNC, 0600);
    CHECK(console >= 0 && setenv("MSGVERB", "text", 1) == 0);
    int available = first_free();
    CHECK(fmtmsg(MM_PRINT | MM_CONSOLE, "app", MM_ERROR, "message", "repair", "TAG") == MM_OK);
    CHECK(first_free() == available);
    expect_file(console, full);
    expect_file(output, "message\n");
    CHECK(close(console) == 0 && unlink("/dev/console") == 0);
    CHECK(fmtmsg(MM_CONSOLE, 0, 0, "missing", 0, 0) == MM_NOCON);
    CHECK(close(2) == 0);
    CHECK(fmtmsg(MM_PRINT, 0, 0, "closed", 0, 0) == MM_NOMSG);
    CHECK(fmtmsg(MM_PRINT | MM_CONSOLE, 0, 0, "closed", 0, 0) == MM_NOTOK);
    CHECK(dup2(output, 2) == 2);
    CHECK(symlink("/dev/full", "/dev/console") == 0);
    available = first_free();
    for (int i = 0; i < 8; i++) {
        CHECK(fmtmsg(MM_CONSOLE, 0, 0, "full", 0, 0) == MM_NOCON);
        CHECK(first_free() == available);
    }
    CHECK(dup2(saved, 2) == 2 && close(saved) == 0 && close(output) == 0);
    CHECK(unlink("/dev/console") == 0);
    puts("owned-fmtmsg-console-errors-ok");
}

static atomic_int cleanup_called, cleanup_closed, fmtmsg_returned, console_descriptor;
static void cleanup(void *unused) {
    (void)unused;
    int fd = atomic_load(&console_descriptor);
    atomic_store(&cleanup_closed, fcntl(fd, F_GETFD) == -1 && errno == EBADF);
    atomic_store(&cleanup_called, 1);
}
static void *blocked_output(void *unused) {
    (void)unused;
    pthread_cleanup_push(cleanup, 0);
    CHECK(fmtmsg(MM_CONSOLE | MM_PRINT, "app", MM_ERROR, "message", "repair", "TAG") == MM_OK);
    atomic_store(&fmtmsg_returned, 1);
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return 0;
}
static void cancellation(void) {
    CHECK(unsetenv("MSGVERB") == 0 && mkfifo("/dev/console", 0600) == 0);
    int fifo = open("/dev/console", O_RDWR | O_NONBLOCK);
    int output = open("/state/output", O_RDWR | O_CREAT | O_TRUNC, 0600);
    int saved = dup(2);
    CHECK(fifo >= 0 && output >= 0 && saved >= 0 && dup2(output, 2) == 2);
    char filler[4096]; memset(filler, 'x', sizeof filler);
    ssize_t filled = 0, n;
    while ((n = write(fifo, filler, sizeof filler)) > 0) filled += n;
    CHECK(n == -1 && errno == EAGAIN && filled > 0);
    int expected_fd = first_free();
    atomic_store(&console_descriptor, expected_fd);
    pthread_t worker;
    CHECK(pthread_create(&worker, 0, blocked_output, 0) == 0);
    /* Seeing the new writer proves fmtmsg has disabled cancellation before
       acquiring its console descriptor. The full FIFO prevents completion. */
    while (fcntl(expected_fd, F_GETFD) == -1) CHECK(sched_yield() == 0);
    CHECK((fcntl(expected_fd, F_GETFL) & O_ACCMODE) == O_WRONLY);
    CHECK(pthread_cancel(worker) == 0);
    CHECK(atomic_load(&cleanup_called) == 0 && atomic_load(&fmtmsg_returned) == 0);
    while (filled > 0) {
        n = read(fifo, filler, filled < (ssize_t)sizeof filler ? filled : (ssize_t)sizeof filler);
        CHECK(n > 0);
        for (ssize_t i = 0; i < n; i++) CHECK(filler[i] == 'x');
        filled -= n;
    }
    void *result;
    CHECK(pthread_join(worker, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(atomic_load(&cleanup_called) == 1 && atomic_load(&cleanup_closed) == 1);
    CHECK(atomic_load(&fmtmsg_returned) == 1);
    n = read(fifo, filler, sizeof filler);
    CHECK(n == (ssize_t)strlen(full) && !memcmp(filler, full, n));
    expect_file(output, full);
    CHECK(dup2(saved, 2) == 2 && close(saved) == 0 && close(output) == 0 && close(fifo) == 0);
    CHECK(unlink("/dev/console") == 0);
    puts("owned-fmtmsg-cancellation-ok");
}
int main(int argc, char **argv) {
    CHECK(argc == 2);
    if (!strcmp(argv[1], "ordinary")) ordinary();
    else if (!strcmp(argv[1], "console-errors")) console_and_errors();
    else if (!strcmp(argv[1], "cancellation")) cancellation();
    else CHECK(0);
    return 0;
}

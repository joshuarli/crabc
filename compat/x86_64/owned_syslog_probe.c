/*
 * Contained installed-product witness for musl 1.2.6 src/misc/syslog.c.
 *
 * The runner executes this only after chroot(2) into a disposable root below
 * .work.  This process itself binds the AF_UNIX /dev/log receiver, so neither
 * the oracle nor a candidate can contact the host logger or host console.
 */
#define _GNU_SOURCE 1

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "owned-syslog:%s:%d errno=%d\n", __func__, __LINE__, errno); \
            return 1; \
        } \
    } while (0)

static const char copied_ident[] = "abcdefghijklmnopqrstuvwxyz01234";

static void call_vsyslog(int priority, const char *format, ...)
{
    va_list arguments;
    va_start(arguments, format);
    vsyslog(priority, format, arguments);
    va_end(arguments);
}

static int receiver_open(void)
{
    struct sockaddr_un address;
    int descriptor;

    /* A previous scenario may have left the pathname after closing its
     * receiver.  This is inside the private chroot fixture, never host /dev. */
    unlink("/dev/log");
    memset(&address, 0, sizeof address);
    address.sun_family = AF_UNIX;
    memcpy(address.sun_path, "/dev/log", sizeof "/dev/log");
    descriptor = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0
        || bind(descriptor, (struct sockaddr *)&address, sizeof address)) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    return descriptor;
}

static int receive_record(int descriptor, char record[1025])
{
    struct pollfd ready = { descriptor, POLLIN, 0 };
    int count;

    if (poll(&ready, 1, 2000) != 1 || !(ready.revents & POLLIN)) return -1;
    count = recv(descriptor, record, 1024, 0);
    if (count < 0 || count >= 1024) return -1;
    record[count] = 0;
    return count;
}

static int no_record(int descriptor)
{
    struct pollfd ready = { descriptor, POLLIN, 0 };
    return poll(&ready, 1, 0) == 0;
}

static int ascii_alpha(char value)
{
    return (value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z');
}

static int ascii_digit(char value)
{
    return value >= '0' && value <= '9';
}

static int timestamp_shape(const char timestamp[16])
{
    return ascii_alpha(timestamp[0]) && ascii_alpha(timestamp[1])
        && ascii_alpha(timestamp[2]) && timestamp[3] == ' '
        && (timestamp[4] == ' ' || ascii_digit(timestamp[4]))
        && ascii_digit(timestamp[5]) && timestamp[6] == ' '
        && ascii_digit(timestamp[7]) && ascii_digit(timestamp[8])
        && timestamp[9] == ':' && ascii_digit(timestamp[10])
        && ascii_digit(timestamp[11]) && timestamp[12] == ':'
        && ascii_digit(timestamp[13]) && ascii_digit(timestamp[14]);
}

static int timestamp_is_current_utc(const char timestamp[16], time_t before)
{
    time_t after = time(0);
    time_t instant;

    /* The logger takes its timestamp after the caller's `before` sample. A
     * short inclusive interval handles a second boundary without accepting a
     * caller-local timestamp (the runner supplies TZ=UTC+12). */
    for (instant = before - 1; instant <= after + 1; ++instant) {
        struct tm broken_down;
        char expected[16];

        if (!gmtime_r(&instant, &broken_down)
            || !strftime(expected, sizeof expected, "%b %e %T", &broken_down)) {
            return 0;
        }
        if (!memcmp(timestamp, expected, 15)) return 1;
    }
    return 0;
}

static int expect_wire(
    int descriptor,
    int priority,
    const char *ident,
    int process_id,
    const char *payload,
    time_t before
)
{
    char record[1025];
    char prefix[16];
    char expected[192];
    int count;
    int prefix_length;

    count = receive_record(descriptor, record);
    if (count < 0) return 0;
    prefix_length = snprintf(prefix, sizeof prefix, "<%d>", priority);
    if (prefix_length <= 0 || strncmp(record, prefix, (size_t)prefix_length)
        || !timestamp_shape(record + prefix_length)
        || !timestamp_is_current_utc(record + prefix_length, before)) {
        return 0;
    }
    if (process_id) {
        snprintf(expected, sizeof expected, "%s[%d]: %s", ident, process_id, payload);
    } else {
        snprintf(expected, sizeof expected, "%s: %s", ident, payload);
    }
    return !strcmp(record + prefix_length + 16, expected);
}

static int normal(void)
{
    char mutable_ident[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    char expected_perror[96];
    char perror_record[128];
    int descriptor;
    int old_mask;
    int pipe_fds[2];
    int saved_stderr;
    int count;
    int console;
    int process_id = getpid();
    time_t before;

    descriptor = receiver_open();
    CHECK(descriptor >= 0);

    old_mask = setlogmask(LOG_MASK(LOG_ERR));
    CHECK(old_mask == LOG_UPTO(LOG_DEBUG));
    CHECK(setlogmask(0) == LOG_MASK(LOG_ERR));
    syslog(LOG_NOTICE, "masked-not-delivered");
    CHECK(no_record(descriptor));
    CHECK(setlogmask(old_mask) == LOG_MASK(LOG_ERR));

    openlog(mutable_ident, LOG_PID | LOG_NDELAY, LOG_LOCAL2);
    memset(mutable_ident, 'X', sizeof mutable_ident - 1);
    mutable_ident[sizeof mutable_ident - 1] = 0;
    errno = ENOENT;
    before = time(0);
    syslog(LOG_NOTICE, "saved-errno=%m");
    CHECK(errno == ENOENT);
    CHECK(expect_wire(
        descriptor, LOG_LOCAL2 | LOG_NOTICE, copied_ident, process_id,
        "saved-errno=No such file or directory\n", before));

    before = time(0);
    call_vsyslog(LOG_ERR, "via-va=%d", 7);
    CHECK(expect_wire(
        descriptor, LOG_LOCAL2 | LOG_ERR, copied_ident, process_id,
        "via-va=7\n", before));

    /* closelog closes only the descriptor: copied identifier, facility and
     * options remain and the following call reconnects lazily. */
    closelog();
    before = time(0);
    syslog(LOG_ERR, "lazy-after-close");
    CHECK(expect_wire(
        descriptor, LOG_LOCAL2 | LOG_ERR, copied_ident, process_id,
        "lazy-after-close\n", before));

    CHECK(pipe(pipe_fds) == 0);
    saved_stderr = dup(2);
    CHECK(saved_stderr >= 0 && dup2(pipe_fds[1], 2) == 2 && close(pipe_fds[1]) == 0);
    openlog("perror", LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_LOCAL0);
    before = time(0);
    syslog(LOG_ERR, "perror-record");
    CHECK(dup2(saved_stderr, 2) == 2 && close(saved_stderr) == 0);
    count = read(pipe_fds[0], perror_record, sizeof perror_record - 1);
    CHECK(close(pipe_fds[0]) == 0 && count > 0 && count < (int)sizeof perror_record);
    perror_record[count] = 0;
    snprintf(expected_perror, sizeof expected_perror, "perror[%d]: perror-record\n", process_id);
    CHECK(!strcmp(perror_record, expected_perror));
    CHECK(expect_wire(
        descriptor, LOG_LOCAL0 | LOG_ERR, "perror", process_id,
        "perror-record\n", before));

    /* The fixture starts with a regular empty /dev/console.  Remove the
     * private receiver after an eager connection so musl's lost-connection
     * retry reaches the one LOG_CONS fallback rather than a host service. */
    closelog();
    console = open("/dev/console", O_WRONLY | O_TRUNC);
    CHECK(console >= 0 && close(console) == 0);
    openlog("console", LOG_CONS | LOG_NDELAY, LOG_LOCAL3);
    CHECK(close(descriptor) == 0 && unlink("/dev/log") == 0);
    syslog(LOG_ERR, "console-fallback");
    closelog();
    console = open("/dev/console", O_RDONLY);
    CHECK(console >= 0);
    count = read(console, perror_record, sizeof perror_record - 1);
    CHECK(close(console) == 0 && count > 0 && count < (int)sizeof perror_record);
    perror_record[count] = 0;
    CHECK(!strcmp(perror_record, "console: console-fallback\n"));

    puts("owned-syslog-normal-ok");
    return 0;
}

struct worker_arguments {
    int ready_descriptor;
};

static void *worker_log_once(void *argument)
{
    const struct worker_arguments *arguments = argument;
    char ready = 'R';

    if (write(arguments->ready_descriptor, &ready, 1) != 1) return (void *)1;
    syslog(LOG_INFO, "worker-message");
    return 0;
}

static int worker(void)
{
    struct worker_arguments arguments;
    pthread_t thread;
    void *result;
    char ready;
    int descriptor;
    int pipe_fds[2];
    int process_id = getpid();
    time_t before;

    descriptor = receiver_open();
    CHECK(descriptor >= 0 && pipe(pipe_fds) == 0);
    openlog("worker", LOG_PID | LOG_NDELAY, LOG_LOCAL1);
    arguments.ready_descriptor = pipe_fds[1];
    before = time(0);
    CHECK(pthread_create(&thread, 0, worker_log_once, &arguments) == 0);
    CHECK(read(pipe_fds[0], &ready, 1) == 1 && ready == 'R');
    CHECK(expect_wire(
        descriptor, LOG_LOCAL1 | LOG_INFO, "worker", process_id,
        "worker-message\n", before));
    CHECK(pthread_join(thread, &result) == 0 && result == 0);
    CHECK(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0 && close(descriptor) == 0);
    closelog();
    puts("owned-syslog-worker-ok");
    return 0;
}

static int forked(void)
{
    int descriptor;
    int status;
    int process_id;
    pid_t child;
    time_t before;

    descriptor = receiver_open();
    CHECK(descriptor >= 0);
    openlog("fork", LOG_PID | LOG_NDELAY, LOG_LOCAL4);
    before = time(0);
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        syslog(LOG_ERR, "fork-child");
        _exit(0);
    }
    process_id = child;
    CHECK(expect_wire(
        descriptor, LOG_LOCAL4 | LOG_ERR, "fork", process_id, "fork-child\n", before));
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(close(descriptor) == 0);
    closelog();
    puts("owned-syslog-fork-ok");
    return 0;
}

struct cancellation_arguments {
    int ready_descriptor;
};

static void *worker_log_until_cancelled(void *argument)
{
    const struct cancellation_arguments *arguments = argument;
    char ready = 'R';
    int index;

    if (write(arguments->ready_descriptor, &ready, 1) != 1) return (void *)1;
    for (index = 0; index < 64; ++index) syslog(LOG_ERR, "cancel-safe");
    /* A pending deferred request must survive every syslog cancellation
     * guard, then deliver at this explicit selected cancellation point. */
    pthread_testcancel();
    return (void *)2;
}

static int cancellation(void)
{
    struct cancellation_arguments arguments;
    pthread_t thread;
    void *result;
    char ready;
    int descriptor;
    int pipe_fds[2];
    int index;
    int process_id = getpid();
    time_t before;

    descriptor = receiver_open();
    CHECK(descriptor >= 0 && pipe(pipe_fds) == 0);
    openlog("cancel", LOG_PID | LOG_NDELAY, LOG_LOCAL5);
    arguments.ready_descriptor = pipe_fds[1];
    before = time(0);
    CHECK(pthread_create(&thread, 0, worker_log_until_cancelled, &arguments) == 0);
    CHECK(read(pipe_fds[0], &ready, 1) == 1 && ready == 'R');
    CHECK(pthread_cancel(thread) == 0);
    for (index = 0; index < 64; ++index) {
        CHECK(expect_wire(
            descriptor, LOG_LOCAL5 | LOG_ERR, "cancel", process_id,
            "cancel-safe\n", before));
    }
    CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0 && close(descriptor) == 0);
    closelog();
    puts("owned-syslog-cancellation-ok");
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "normal")) return normal();
    if (!strcmp(argv[1], "worker")) return worker();
    if (!strcmp(argv[1], "fork")) return forked();
    if (!strcmp(argv[1], "cancellation")) return cancellation();
    return 2;
}

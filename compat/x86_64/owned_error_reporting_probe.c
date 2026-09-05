/*
 * Same-source pinned-musl and installed-product witness for the selected C
 * diagnostic entries.  The normal body covers the process-name aliases,
 * perror orientation preservation, all direct and va_list spellings, errno
 * text, ordinary exit, and record integrity.  The two conditional bodies
 * retain the source object's public strerror/perror call boundaries through
 * actual final static and shared links.
 */
#define _GNU_SOURCE 1

#include <errno.h>
#include <err.h>
#include <pthread.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <wchar.h>

#define CHECK(condition) \
    do { \
        if (!(condition)) return __LINE__; \
    } while (0)

struct captured_stderr {
    int saved;
    int read_end;
};

static int begin_stderr_capture(struct captured_stderr *capture)
{
    int descriptors[2];

    if (pipe(descriptors)) return 0;
    capture->saved = dup(STDERR_FILENO);
    if (capture->saved < 0
        || dup2(descriptors[1], STDERR_FILENO) != STDERR_FILENO
        || close(descriptors[1])) {
        if (capture->saved >= 0) close(capture->saved);
        close(descriptors[0]);
        return 0;
    }
    capture->read_end = descriptors[0];
    return 1;
}

static int finish_stderr_capture(
    struct captured_stderr *capture,
    char *destination,
    size_t capacity
)
{
    ssize_t count;

    if (capacity == 0
        || dup2(capture->saved, STDERR_FILENO) != STDERR_FILENO
        || close(capture->saved)) {
        close(capture->read_end);
        return -1;
    }
    count = read(capture->read_end, destination, capacity - 1);
    if (close(capture->read_end) || count < 0) return -1;
    destination[count] = 0;
    return (int)count;
}

static int captured_stderr_equals(
    struct captured_stderr *capture,
    const char *expected
)
{
    char observed[2048];
    int count = finish_stderr_capture(capture, observed, sizeof observed);

    return count >= 0
        && (size_t)count == strlen(expected)
        && !memcmp(observed, expected, (size_t)count);
}

static void call_vwarn(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    vwarn(format, arguments);
    va_end(arguments);
}

static void call_vwarnx(const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    vwarnx(format, arguments);
    va_end(arguments);
}

#if (defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR) \
    + defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR_PROVIDER) \
    + defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR_CONSUMER) \
    + defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR) \
    + defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR_PROVIDER) \
    + defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR_CONSUMER)) > 1
#error "select at most one owned error-reporting interposition role"
#endif

#if defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR) \
    || defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR_PROVIDER)

/* The source `perror.c` object calls strerror through its public link edge. */
char *strerror(int error)
{
    return error == 777 ? "application strerror" : "unexpected strerror";
}

#elif defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR) \
    || defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR_PROVIDER)

/* The source `err.c` object routes non-x warnings through public perror(0). */
void perror(const char *message)
{
    if (message == NULL) fputs("application perror\n", stderr);
    else fputs("unexpected perror\n", stderr);
}

#endif

#if defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR)

int main(int argc, char **argv)
{
    struct captured_stderr capture;

    CHECK(argc == 2 && !strcmp(argv[1], "interpose"));
    CHECK(begin_stderr_capture(&capture));
    errno = 777;
    perror("strerror boundary");
    CHECK(captured_stderr_equals(&capture,
        "strerror boundary: application strerror\n"));
    puts("owned-error-reporting-interpose-strerror-ok");
    return 0;
}

#elif defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR)

int main(int argc, char **argv)
{
    struct captured_stderr capture;
    char *saved_name;

    CHECK(argc == 2 && !strcmp(argv[1], "interpose"));
    saved_name = program_invocation_short_name;
    program_invocation_short_name = "perror-boundary";
    CHECK(begin_stderr_capture(&capture));
    errno = ENOENT;
    warn("from warning");
    CHECK(captured_stderr_equals(&capture,
        "perror-boundary: from warning: application perror\n"));
    program_invocation_short_name = saved_name;
    puts("owned-error-reporting-interpose-perror-ok");
    return 0;
}

#elif defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR_CONSUMER)

int main(int argc, char **argv)
{
    struct captured_stderr capture;

    CHECK(argc == 2 && !strcmp(argv[1], "interpose"));
    /* The DSO precedes libc for the consumer's public strerror reference. */
    CHECK(!strcmp(strerror(777), "application strerror"));
    CHECK(begin_stderr_capture(&capture));
    errno = 777;
    /* musl's libc-local perror -> strerror edge remains local in a DSO link. */
    perror("strerror boundary");
    CHECK(captured_stderr_equals(&capture,
        "strerror boundary: No error information\n"));
    puts("owned-error-reporting-interpose-strerror-ok");
    return 0;
}

#elif defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR_CONSUMER)

int main(int argc, char **argv)
{
    struct captured_stderr capture;
    char *saved_name;

    CHECK(argc == 2 && !strcmp(argv[1], "interpose"));
    CHECK(begin_stderr_capture(&capture));
    /* The DSO precedes libc for the consumer's public perror reference. */
    perror(NULL);
    CHECK(captured_stderr_equals(&capture, "application perror\n"));
    saved_name = program_invocation_short_name;
    program_invocation_short_name = "perror-boundary";
    CHECK(begin_stderr_capture(&capture));
    errno = ENOENT;
    /* musl's libc-local warn -> perror edge remains local in a DSO link. */
    warn("from warning");
    CHECK(captured_stderr_equals(&capture,
        "perror-boundary: from warning: No such file or directory\n"));
    program_invocation_short_name = saved_name;
    puts("owned-error-reporting-interpose-perror-ok");
    return 0;
}

#elif !defined(CRABC_ERROR_REPORTING_INTERPOSE_STRERROR_PROVIDER) \
    && !defined(CRABC_ERROR_REPORTING_INTERPOSE_PERROR_PROVIDER)


static void exit_notice(void)
{
    /* Ordinary err/verr exit must invoke this then flush its stdout buffer. */
    fputs("atexit-buffered\n", stdout);
}

static void call_verr(int status, const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    verr(status, format, arguments);
    va_end(arguments);
}

static void call_verrx(int status, const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    verrx(status, format, arguments);
    va_end(arguments);
}

static int read_child_output(int descriptor, char *destination, size_t capacity)
{
    ssize_t count;

    if (capacity == 0) return -1;
    count = read(descriptor, destination, capacity - 1);
    if (close(descriptor) || count < 0) return -1;
    destination[count] = 0;
    return (int)count;
}

static int exit_case(int kind)
{
    static const int statuses[] = { 41, 42, 43, 44 };
    static const char *const diagnostics[] = {
        "exit-name: err=1: No such file or directory\n",
        "exit-name: errx=2\n",
        "exit-name: verr=3: No such file or directory\n",
        "exit-name: verrx=4\n",
    };
    int error_pipe[2];
    int output_pipe[2];
    int status;
    pid_t child;
    char error_bytes[128];
    char output_bytes[128];

    CHECK(kind >= 0 && kind < 4 && !pipe(error_pipe) && !pipe(output_pipe));
    child = fork();
    CHECK(child >= 0);
    if (child == 0) {
        close(error_pipe[0]);
        close(output_pipe[0]);
        if (dup2(error_pipe[1], STDERR_FILENO) != STDERR_FILENO
            || dup2(output_pipe[1], STDOUT_FILENO) != STDOUT_FILENO
            || close(error_pipe[1]) || close(output_pipe[1])
            || atexit(exit_notice)) {
            _Exit(127);
        }
        program_invocation_short_name = "exit-name";
        errno = ENOENT;
        switch (kind) {
        case 0: err(statuses[kind], "err=%d", 1);
        case 1: errx(statuses[kind], "errx=%d", 2);
        case 2: call_verr(statuses[kind], "verr=%d", 3);
        default: call_verrx(statuses[kind], "verrx=%d", 4);
        }
    }
    close(error_pipe[1]);
    close(output_pipe[1]);
    CHECK(waitpid(child, &status, 0) == child
        && WIFEXITED(status) && WEXITSTATUS(status) == statuses[kind]);
    CHECK(read_child_output(error_pipe[0], error_bytes, sizeof error_bytes) >= 0
        && !strcmp(error_bytes, diagnostics[kind]));
    CHECK(read_child_output(output_pipe[0], output_bytes, sizeof output_bytes) >= 0
        && !strcmp(output_bytes, "atexit-buffered\n"));
    return 0;
}

struct record_worker {
    int record;
};

/* `err.c` has one stdio lock per public output call, not one record lock.
 * A concurrent warning may therefore split a prefix, formatted body, and
 * newline around another warning.  Require every source-call fragment and
 * byte, while accepting that source-permitted ordering. */
static void *write_warning_fragments(void *opaque)
{
    const struct record_worker *worker = opaque;

    warnx("record=%d [complete]", worker->record);
    return NULL;
}

static size_t occurrence_count(
    const char *bytes,
    size_t length,
    const char *needle
)
{
    size_t count = 0;
    size_t needle_length = strlen(needle);
    size_t position;

    if (needle_length == 0 || needle_length > length) return 0;
    for (position = 0; position + needle_length <= length; position++) {
        if (!memcmp(bytes + position, needle, needle_length)) count++;
    }
    return count;
}

static int complete_warning_fragments(const char *bytes, size_t length)
{
    static const char prefix[] = "record-owner: ";
    static const char newline[] = "\n";
    size_t record;

    if (length != 4 * (sizeof "record-owner: record=0 [complete]\n" - 1)
        || occurrence_count(bytes, length, prefix) != 4
        || occurrence_count(bytes, length, newline) != 4) {
        return 0;
    }
    for (record = 0; record < 4; record++) {
        char body[24];
        int count = snprintf(body, sizeof body, "record=%zu [complete]", record);

        if (count <= 0 || (size_t)count >= sizeof body
            || occurrence_count(bytes, length, body) != 1) {
            return 0;
        }
    }
    return 1;
}

static int concurrency_case(void)
{
    struct captured_stderr capture;
    struct record_worker workers[4] = {{0}, {1}, {2}, {3}};
    pthread_t threads[4];
    char observed[512];
    char *saved_name;
    int count;
    int index;

    saved_name = program_invocation_short_name;
    program_invocation_short_name = "record-owner";
    CHECK(begin_stderr_capture(&capture));
    for (index = 0; index < 4; index++) {
        CHECK(!pthread_create(&threads[index], NULL, write_warning_fragments, &workers[index]));
    }
    for (index = 0; index < 4; index++) {
        void *result = (void *)(uintptr_t)1;
        CHECK(!pthread_join(threads[index], &result) && result == NULL);
    }
    count = finish_stderr_capture(&capture, observed, sizeof observed);
    program_invocation_short_name = saved_name;
    CHECK(count >= 0 && complete_warning_fragments(observed, (size_t)count));
    return 0;
}

static int normal_case(void)
{
    static const char expected[] =
        "No such file or directory\n"
        "No such file or directory\n"
        "prefix: No such file or directory\n"
        "invalid: No error information\n"
        "warning-owner: warn=7: No such file or directory\n"
        "warning-owner: warnx=8\n"
        "warning-owner: vwarn=9: No such file or directory\n"
        "warning-owner: vwarnx=10\n"
        "warning-owner: percent=No such file or directory: No such file or directory\n"
        "(null): null-name\n"
        ": empty-name\n";
    struct captured_stderr capture;
    char *saved_name;

    CHECK(fwide(stderr, 0) == 0);
    CHECK(begin_stderr_capture(&capture));
    errno = ENOENT;
    perror(NULL);
    CHECK(errno == ENOENT && fwide(stderr, 0) == 0);
    perror("");
    perror("prefix");
    errno = 999;
    perror("invalid");
    CHECK(errno == 999);

    saved_name = program_invocation_short_name;
    program_invocation_short_name = "warning-owner";
    errno = ENOENT;
    warn("warn=%d", 7);
    warnx("warnx=%d", 8);
    call_vwarn("vwarn=%d", 9);
    call_vwarnx("vwarnx=%d", 10);
    warn("percent=%m");
    program_invocation_short_name = NULL;
    warnx("null-name");
    program_invocation_short_name = "";
    warnx("empty-name");
    program_invocation_short_name = saved_name;

    CHECK(captured_stderr_equals(&capture, expected));
    for (int kind = 0; kind < 4; kind++) CHECK(!exit_case(kind));
    CHECK(!concurrency_case());
    return 0;
}

static int worker_case(void)
{
    struct captured_stderr capture;
    char *saved_name;

    saved_name = program_invocation_short_name;
    program_invocation_short_name = "worker-owner";
    CHECK(begin_stderr_capture(&capture));
    errno = EACCES;
    perror("worker-perror");
    call_vwarn("worker-vwarn=%d", 11);
    call_vwarnx("worker-vwarnx=%d", 12);
    CHECK(captured_stderr_equals(&capture,
        "worker-perror: Permission denied\n"
        "worker-owner: worker-vwarn=11: Permission denied\n"
        "worker-owner: worker-vwarnx=12\n"));
    program_invocation_short_name = saved_name;
    return 0;
}

static void *run_worker_case(void *unused)
{
    (void)unused;
    return (void *)(intptr_t)worker_case();
}

int main(int argc, char **argv)
{
    pthread_t worker;
    void *result = (void *)(intptr_t)-1;

    CHECK(argc == 2);
    if (!strcmp(argv[1], "main")) {
        CHECK(!normal_case());
        puts("owned-error-reporting-main-ok");
        return 0;
    }
    if (!strcmp(argv[1], "worker")) {
        CHECK(!pthread_create(&worker, NULL, run_worker_case, NULL));
        CHECK(!pthread_join(worker, &result) && result == NULL);
        puts("owned-error-reporting-worker-ok");
        return 0;
    }
    return 2;
}

#endif

#ifndef CRABC_PERF_X86_64_WORKLOAD_PROTOCOL_H
#define CRABC_PERF_X86_64_WORKLOAD_PROTOCOL_H

/*
 * The supplemental fixtures are native Linux/x86-64 inputs. This header keeps
 * their opt-in observer handshake identical without changing a timed child
 * when neither descriptor environment variable is present.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "x86_64 supplemental performance fixtures require little-endian Linux x86-64"
#endif

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#define CRABC_PERF_OBSERVER_READY_ENV "CRABC_PERF_OBSERVER_READY_FD"
#define CRABC_PERF_OBSERVER_CONTINUE_ENV "CRABC_PERF_OBSERVER_CONTINUE_FD"

struct crabc_perf_observer {
    int enabled;
    int ready_fd;
    int continue_fd;
};

static volatile uintptr_t crabc_perf_result_sink;

static void
crabc_perf_consume_uintptr(uintptr_t value)
{
    crabc_perf_result_sink ^= value;
}

/* Canonical decimal accepts zero only as the single character "0". */
static int
crabc_perf_parse_unsigned(const char *text, unsigned long *result)
{
    unsigned long value = 0;
    const unsigned char *cursor;

    if (!text || !*text || !result)
        return 0;
    if (text[0] == '0' && text[1] != '\0')
        return 0;
    for (cursor = (const unsigned char *)text; *cursor; cursor++) {
        unsigned long digit;

        if (*cursor < '0' || *cursor > '9')
            return 0;
        digit = (unsigned long)(*cursor - '0');
        if (value > (ULONG_MAX - digit) / 10)
            return 0;
        value = value * 10 + digit;
    }
    *result = value;
    return 1;
}

static int
crabc_perf_parse_positive(const char *text, unsigned long *result)
{
    return crabc_perf_parse_unsigned(text, result) && *result != 0;
}

static int
crabc_perf_parse_fd(const char *text, int *result)
{
    unsigned long value;

    if (!crabc_perf_parse_positive(text, &value) || value < 3 ||
        value > (unsigned long)INT_MAX)
        return 0;
    *result = (int)value;
    return 1;
}

/*
 * Both variables are required together. A shared descriptor cannot provide
 * the one-way R/C exchange, so reject it before fixture setup.
 */
static int
crabc_perf_observer_from_environment(struct crabc_perf_observer *observer)
{
    const char *ready = getenv(CRABC_PERF_OBSERVER_READY_ENV);
    const char *continued = getenv(CRABC_PERF_OBSERVER_CONTINUE_ENV);

    if (!observer)
        return 0;
    observer->enabled = 0;
    observer->ready_fd = -1;
    observer->continue_fd = -1;
    if (!ready && !continued)
        return 1;
    if (!ready || !continued ||
        !crabc_perf_parse_fd(ready, &observer->ready_fd) ||
        !crabc_perf_parse_fd(continued, &observer->continue_fd) ||
        observer->ready_fd == observer->continue_fd)
        return 0;
    observer->enabled = 1;
    return 1;
}

static int
crabc_perf_write_byte(int fd, char value)
{
    for (;;) {
        ssize_t written = write(fd, &value, 1);

        if (written == 1)
            return 1;
        if (written < 0 && errno == EINTR)
            continue;
        return 0;
    }
}

static int
crabc_perf_read_byte(int fd, char *value)
{
    for (;;) {
        ssize_t read_count = read(fd, value, 1);

        if (read_count == 1)
            return 1;
        if (read_count < 0 && errno == EINTR)
            continue;
        return 0;
    }
}

/* Reach the declared plateau only after its real result has been checked. */
static int
crabc_perf_observer_reach(const struct crabc_perf_observer *observer)
{
    char acknowledgement;

    if (!observer || !observer->enabled)
        return 1;
    return crabc_perf_write_byte(observer->ready_fd, 'R') &&
        crabc_perf_read_byte(observer->continue_fd, &acknowledgement) &&
        acknowledgement == 'C';
}

#endif

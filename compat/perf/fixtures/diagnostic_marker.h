/*
 * Descriptor-only bounds for the non-timed syscall diagnostic.
 *
 * The timed children never receive CRABC_PERF_MARKER_FD.  The separate
 * strace child receives one inherited descriptor, so the runner can separate
 * a fixture's selected route from loader/startup work without changing the
 * measured runtime behavior.
 */
#ifndef CRABC_PERF_DIAGNOSTIC_MARKER_H
#define CRABC_PERF_DIAGNOSTIC_MARKER_H

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define DIAGNOSTIC_MARKER_BEGIN "CRABC_PERF_BEGIN"
#define DIAGNOSTIC_MARKER_END "CRABC_PERF_END"

static int diagnostic_marker_fd(void)
{
    const char *text = getenv("CRABC_PERF_MARKER_FD");
    char *end = NULL;
    long value;

    if (text == NULL)
        return -1;
    errno = 0;
    value = strtol(text, &end, 10);
    if (text[0] == '\0' || end == NULL || *end != '\0' || errno != 0 || value < 3 || value > INT_MAX) {
        fprintf(stderr, "invalid CRABC_PERF_MARKER_FD: %s\n", text);
        exit(2);
    }
    return (int)value;
}

static void write_diagnostic_marker(int fd, const char *marker, size_t marker_bytes)
{
    if (write(fd, marker, marker_bytes) != (ssize_t)marker_bytes) {
        perror("diagnostic marker write");
        exit(3);
    }
}

#endif

/* Application-fixture trace helper, never target-runtime implementation. */
#ifndef CRABC_SYSROOT_LIFECYCLE_TRACE_H
#define CRABC_SYSROOT_LIFECYCLE_TRACE_H

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

/*
 * Constructors have no argv parameter, so the harness names one trace file
 * through the already-published process environment.  Every event is a
 * single append-only byte; the fixture deliberately avoids stdio buffering
 * and keeps its ordering proof independent from output flushing.
 */
static inline void lifecycle_trace(char event)
{
    const char *path = getenv("CRABC_LIFECYCLE_TRACE");
    if (path == NULL)
        _Exit(120);
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT, 0600);
    if (fd < 0 || write(fd, &event, 1) != 1)
        _Exit(121);
    (void)close(fd);
}

static inline void lifecycle_require(int condition)
{
    if (!condition) {
        lifecycle_trace('!');
        _Exit(122);
    }
}

#endif

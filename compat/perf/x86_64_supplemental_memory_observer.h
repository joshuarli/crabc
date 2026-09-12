#ifndef CRABC_PERF_X86_64_SUPPLEMENTAL_MEMORY_OBSERVER_H
#define CRABC_PERF_X86_64_SUPPLEMENTAL_MEMORY_OBSERVER_H

/*
 * Private source-local wrapper state for the supplemental memory artifacts.
 *
 * Each timed source already owns one checked live-resource plateau through
 * `crabc_perf_observer_reach`.  An observer translation unit redirects only
 * that call after this header has declared the original protocol, then adds
 * main-initial before the renamed source main and main-final after it.  The
 * wrapper does not plan rows or recreate fixture work: unchanged argv selects
 * the source route and its existing plateau.
 */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "x86_64_workload_protocol.h"

#define CRABC_PERF_SUPPLEMENTAL_MEMORY_OBSERVER_PROTOCOL \
    "crabc.perf.observer-r-c/v1"
#define CRABC_PERF_SUPPLEMENTAL_MEMORY_READY_FD 97
#define CRABC_PERF_SUPPLEMENTAL_MEMORY_CONTINUE_FD 98

struct crabc_perf_supplemental_memory_observer {
    struct crabc_perf_observer control;
    int enabled;
    int initial_reached;
    int plateau_reached;
    int failed;
};

static struct crabc_perf_supplemental_memory_observer
    crabc_perf_supplemental_memory_observer;

static void
crabc_perf_supplemental_memory_reset(void)
{
    crabc_perf_supplemental_memory_observer.control.enabled = 0;
    crabc_perf_supplemental_memory_observer.control.ready_fd = -1;
    crabc_perf_supplemental_memory_observer.control.continue_fd = -1;
    crabc_perf_supplemental_memory_observer.enabled = 0;
    crabc_perf_supplemental_memory_observer.initial_reached = 0;
    crabc_perf_supplemental_memory_observer.plateau_reached = 0;
    crabc_perf_supplemental_memory_observer.failed = 0;
}

/*
 * Return 0 for ordinary source execution, 1 after a successful initial R/C,
 * -1 for a malformed observer environment, and -2 after a failed initial
 * handshake.  The latter two outcomes must not enter the original main.
 */
static int
crabc_perf_supplemental_memory_begin(void)
{
    const char *ready;
    const char *continued;
    int saved_errno = errno;
    int result;

    crabc_perf_supplemental_memory_reset();
    ready = getenv(CRABC_PERF_OBSERVER_READY_ENV);
    continued = getenv(CRABC_PERF_OBSERVER_CONTINUE_ENV);
    if (ready == NULL && continued == NULL) {
        result = 0;
    } else if (ready == NULL || continued == NULL || strcmp(ready, "97") != 0 ||
        strcmp(continued, "98") != 0) {
        result = -1;
    } else {
        crabc_perf_supplemental_memory_observer.enabled = 1;
        crabc_perf_supplemental_memory_observer.control.enabled = 1;
        crabc_perf_supplemental_memory_observer.control.ready_fd =
            CRABC_PERF_SUPPLEMENTAL_MEMORY_READY_FD;
        crabc_perf_supplemental_memory_observer.control.continue_fd =
            CRABC_PERF_SUPPLEMENTAL_MEMORY_CONTINUE_FD;
        if (crabc_perf_observer_reach(
                &crabc_perf_supplemental_memory_observer.control)) {
            crabc_perf_supplemental_memory_observer.initial_reached = 1;
            result = 1;
        } else {
            crabc_perf_supplemental_memory_observer.failed = 1;
            result = -2;
        }
    }
    errno = saved_errno;
    return result;
}

/*
 * This is substituted only for the frozen source's declared plateau.  It
 * keeps that source call and its resource lifetime in place while making the
 * observed sequence finite: initial, exactly one source plateau, final.
 */
static int
crabc_perf_supplemental_memory_reach(const struct crabc_perf_observer *observer)
{
    int saved_errno = errno;
    int reached;

    if (!crabc_perf_supplemental_memory_observer.enabled) {
        reached = crabc_perf_observer_reach(observer);
    } else if (crabc_perf_supplemental_memory_observer.failed ||
        crabc_perf_supplemental_memory_observer.plateau_reached ||
        observer == NULL || !observer->enabled ||
        observer->ready_fd != CRABC_PERF_SUPPLEMENTAL_MEMORY_READY_FD ||
        observer->continue_fd != CRABC_PERF_SUPPLEMENTAL_MEMORY_CONTINUE_FD) {
        crabc_perf_supplemental_memory_observer.failed = 1;
        reached = 0;
    } else {
        reached = crabc_perf_observer_reach(observer);
        if (reached)
            crabc_perf_supplemental_memory_observer.plateau_reached = 1;
        else
            crabc_perf_supplemental_memory_observer.failed = 1;
    }
    errno = saved_errno;
    return reached;
}

/*
 * Let the source complete its own cleanup and stdout path before this final
 * observer-only R/C.  A failed final acknowledgement changes only success to
 * failure and leaves the source's status and errno otherwise intact.
 */
static int
crabc_perf_supplemental_memory_finish(int original_status)
{
    int saved_errno = errno;
    int result = original_status;

    if (crabc_perf_supplemental_memory_observer.enabled) {
        if (original_status != 0 || crabc_perf_supplemental_memory_observer.failed ||
            !crabc_perf_supplemental_memory_observer.initial_reached ||
            !crabc_perf_supplemental_memory_observer.plateau_reached) {
            if (original_status == 0)
                result = 1;
        } else if (!crabc_perf_observer_reach(
                &crabc_perf_supplemental_memory_observer.control)) {
            crabc_perf_supplemental_memory_observer.failed = 1;
            result = 1;
        }
    }
    errno = saved_errno;
    return result;
}

#endif

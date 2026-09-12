#ifndef CRABC_PERF_X86_64_MEMORY_OBSERVER_PROTOCOL_H
#define CRABC_PERF_X86_64_MEMORY_OBSERVER_PROTOCOL_H

/*
 * Private source-local memory-observer protocol for the frozen legacy
 * fixtures.  The observer executable has a distinct ELF identity from the
 * timed fixture.  It receives the same argv and, only when both inherited
 * descriptor variables are present, pauses at the finite checkpoints below.
 *
 * This header deliberately has no generic interposition mechanism.  Each
 * observer translation unit pre-includes the fixture's system headers and
 * redirects only the source calls that own one declared lifetime boundary.
 */
#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    (__BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__)
#error "x86_64 memory observers require little-endian Linux x86-64"
#endif

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CRABC_PERF_MEMORY_OBSERVER_PROTOCOL "crabc.perf.observer-r-c/v1"
#define CRABC_PERF_MEMORY_OBSERVER_READY_ENV "CRABC_PERF_OBSERVER_READY_FD"
#define CRABC_PERF_MEMORY_OBSERVER_CONTINUE_ENV "CRABC_PERF_OBSERVER_CONTINUE_FD"
#define CRABC_PERF_MEMORY_OBSERVER_READY_FD 97
#define CRABC_PERF_MEMORY_OBSERVER_CONTINUE_FD 98

#if defined(__GNUC__)
#define CRABC_PERF_MEMORY_LOCAL static __attribute__((unused))
#else
#define CRABC_PERF_MEMORY_LOCAL static
#endif

enum crabc_perf_memory_row {
    CRABC_PERF_MEMORY_ROW_NONE,
    CRABC_PERF_MEMORY_ROW_STARTUP,
    CRABC_PERF_MEMORY_ROW_CLOCK,
    CRABC_PERF_MEMORY_ROW_OPEN,
    CRABC_PERF_MEMORY_ROW_FD,
    CRABC_PERF_MEMORY_ROW_STDIO,
    CRABC_PERF_MEMORY_ROW_PTHREAD_CREATE_JOIN_TLS,
    CRABC_PERF_MEMORY_ROW_MUTEX_UNCONTENDED,
    CRABC_PERF_MEMORY_ROW_MUTEX_COND_PING_PONG,
    CRABC_PERF_MEMORY_ROW_TLS_GROWTH,
    CRABC_PERF_MEMORY_ROW_SCALAR,
    CRABC_PERF_MEMORY_ROW_SPAN,
    CRABC_PERF_MEMORY_ROW_ALLOCATOR,
    CRABC_PERF_MEMORY_ROW_DLSYM,
    CRABC_PERF_MEMORY_ROW_GRAPH,
};

enum crabc_perf_memory_phase {
    CRABC_PERF_MEMORY_MAIN_INITIAL,
    CRABC_PERF_MEMORY_MAIN_FINAL,
    CRABC_PERF_MEMORY_CLOCK_FINAL_CALL,
    CRABC_PERF_MEMORY_OPEN_BEFORE_CLOSE,
    CRABC_PERF_MEMORY_FD_BEFORE_CLOSE,
    CRABC_PERF_MEMORY_STDIO_BEFORE_FCLOSE,
    CRABC_PERF_MEMORY_PTHREAD_CALLBACK_READY,
    CRABC_PERF_MEMORY_MUTEX_BEFORE_DESTROY,
    CRABC_PERF_MEMORY_PINGPONG_BEFORE_WORKER_EXIT,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_0,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_1,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_2,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_3,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_4,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_5,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_6,
    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_7,
    CRABC_PERF_MEMORY_TLS_WORKER_COMPLETE,
    CRABC_PERF_MEMORY_SCALAR_ARRAYS_LIVE,
    CRABC_PERF_MEMORY_SPAN_BEFORE_FIRST_MUNMAP,
    CRABC_PERF_MEMORY_ALLOCATOR_BEFORE_FINAL_FREE,
    CRABC_PERF_MEMORY_DLSYM_BEFORE_DLCLOSE,
    CRABC_PERF_MEMORY_GRAPH_BEFORE_DLCLOSE,
};

/*
 * Finite legacy row roster. The adapter selects the separate observer artifact
 * for the named source family and records that artifact identity per
 * invocation; this C side derives its ordered phase plan from unchanged timed
 * argv.
 */
#define CRABC_PERF_MEMORY_OBSERVER_ROSTER(X) \
    X(startup, workload, startup) \
    X(startup_constructor_destructor, constructor, startup) \
    X(startup_dependency_graph, graph, startup) \
    X(clock_gettime, workload, clock) \
    X(gettimeofday, workload, clock) \
    X(getpid, workload, clock) \
    X(open_close, workload, open) \
    X(fd_file_4k, workload, fd) \
    X(stdio_file_4k, workload, stdio) \
    X(stdio_format_parse, workload, stdio) \
    X(pthread_create_join_tls, workload, pthread_create_join_tls) \
    X(pthread_mutex_uncontended, workload, mutex_uncontended) \
    X(pthread_mutex_cond_ping_pong, workload, mutex_cond_ping_pong) \
    X(loader_dynamic_tls_growth, workload, tls_growth) \
    X(memcpy_16k, workload, scalar) \
    X(memset_16k, workload, scalar) \
    X(strlen_16k, workload, scalar) \
    X(memchr_16k, workload, scalar) \
    X(strstr_4k, workload, scalar) \
    X(memmem_4k, workload, scalar) \
    X(memcpy_64_aligned, workload, scalar) \
    X(memcpy_64_unaligned, workload, scalar) \
    X(memcpy_16k_aligned, workload, scalar) \
    X(memcpy_16k_unaligned, workload, scalar) \
    X(memcpy_256k_aligned, workload, scalar) \
    X(memcpy_256k_unaligned, workload, scalar) \
    X(memset_64_aligned, workload, scalar) \
    X(memset_64_unaligned, workload, scalar) \
    X(memset_16k_aligned, workload, scalar) \
    X(memset_16k_unaligned, workload, scalar) \
    X(memset_256k_aligned, workload, scalar) \
    X(memset_256k_unaligned, workload, scalar) \
    X(strlen_64_aligned, workload, scalar) \
    X(strlen_64_unaligned, workload, scalar) \
    X(strlen_16k_aligned, workload, scalar) \
    X(strlen_16k_unaligned, workload, scalar) \
    X(strlen_256k_aligned, workload, scalar) \
    X(strlen_256k_unaligned, workload, scalar) \
    X(memchr_64_aligned, workload, scalar) \
    X(memchr_64_unaligned, workload, scalar) \
    X(memchr_16k_aligned, workload, scalar) \
    X(memchr_16k_unaligned, workload, scalar) \
    X(memchr_256k_aligned, workload, scalar) \
    X(memchr_256k_unaligned, workload, scalar) \
    X(strstr_64_aligned, workload, scalar) \
    X(strstr_64_unaligned, workload, scalar) \
    X(strstr_16k_aligned, workload, scalar) \
    X(strstr_16k_unaligned, workload, scalar) \
    X(strstr_256k_aligned, workload, scalar) \
    X(strstr_256k_unaligned, workload, scalar) \
    X(memmem_64_aligned, workload, scalar) \
    X(memmem_64_unaligned, workload, scalar) \
    X(memmem_16k_aligned, workload, scalar) \
    X(memmem_16k_unaligned, workload, scalar) \
    X(memmem_256k_aligned, workload, scalar) \
    X(memmem_256k_unaligned, workload, scalar) \
    X(memcpy_128m_aligned, workload, span) \
    X(memcpy_128m_unaligned, workload, span) \
    X(memset_128m_aligned, workload, span) \
    X(memset_128m_unaligned, workload, span) \
    X(strlen_128m_aligned, workload, span) \
    X(strlen_128m_unaligned, workload, span) \
    X(memchr_128m_aligned, workload, span) \
    X(memchr_128m_unaligned, workload, span) \
    X(strstr_128m_aligned, workload, span) \
    X(strstr_128m_unaligned, workload, span) \
    X(memmem_128m_aligned, workload, span) \
    X(memmem_128m_unaligned, workload, span) \
    X(allocator_64, workload, allocator) \
    X(allocator_4k, workload, allocator) \
    X(dlsym_1, workload, dlsym) \
    X(dlsym_128, workload, dlsym) \
    X(dlsym_1024, workload, dlsym) \
    X(dlopen_graph, workload, graph)

enum {
    CRABC_PERF_MEMORY_MAX_PHASES = 11,
};

struct crabc_perf_memory_observer {
    int enabled;
    int failed;
    int ready_fd;
    int continue_fd;
    enum crabc_perf_memory_row row;
    unsigned long long iterations;
    unsigned long long clock_calls;
    unsigned long long close_calls;
    unsigned long long fclose_calls;
    unsigned long long free_calls;
    unsigned int tls_loads;
    int first_munmap_seen;
    size_t phase_count;
    size_t next_phase;
    enum crabc_perf_memory_phase phases[CRABC_PERF_MEMORY_MAX_PHASES];
};

static struct crabc_perf_memory_observer crabc_perf_memory_observer;

CRABC_PERF_MEMORY_LOCAL void
crabc_perf_memory_reset(void)
{
    memset(&crabc_perf_memory_observer, 0, sizeof crabc_perf_memory_observer);
    crabc_perf_memory_observer.ready_fd = -1;
    crabc_perf_memory_observer.continue_fd = -1;
}

CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_append(enum crabc_perf_memory_phase phase)
{
    if (crabc_perf_memory_observer.phase_count == CRABC_PERF_MEMORY_MAX_PHASES)
        return 0;
    crabc_perf_memory_observer.phases[crabc_perf_memory_observer.phase_count++] = phase;
    return 1;
}

CRABC_PERF_MEMORY_LOCAL enum crabc_perf_memory_row
crabc_perf_memory_row_from_mode(const char *mode)
{
    if (mode == NULL)
        return CRABC_PERF_MEMORY_ROW_NONE;
    if (strcmp(mode, "startup") == 0)
        return CRABC_PERF_MEMORY_ROW_STARTUP;
    if (strcmp(mode, "clock_gettime") == 0 || strcmp(mode, "gettimeofday") == 0 ||
        strcmp(mode, "getpid") == 0)
        return CRABC_PERF_MEMORY_ROW_CLOCK;
    if (strcmp(mode, "open_close") == 0)
        return CRABC_PERF_MEMORY_ROW_OPEN;
    if (strcmp(mode, "fd_file_4k") == 0)
        return CRABC_PERF_MEMORY_ROW_FD;
    if (strcmp(mode, "stdio_file_4k") == 0 || strcmp(mode, "stdio_format_parse") == 0)
        return CRABC_PERF_MEMORY_ROW_STDIO;
    if (strcmp(mode, "pthread_create_join_tls") == 0)
        return CRABC_PERF_MEMORY_ROW_PTHREAD_CREATE_JOIN_TLS;
    if (strcmp(mode, "pthread_mutex_uncontended") == 0)
        return CRABC_PERF_MEMORY_ROW_MUTEX_UNCONTENDED;
    if (strcmp(mode, "pthread_mutex_cond_ping_pong") == 0)
        return CRABC_PERF_MEMORY_ROW_MUTEX_COND_PING_PONG;
    if (strcmp(mode, "loader_dynamic_tls_growth") == 0)
        return CRABC_PERF_MEMORY_ROW_TLS_GROWTH;
    if (strcmp(mode, "memcpy_16k") == 0 || strcmp(mode, "memset_16k") == 0 ||
        strcmp(mode, "strlen_16k") == 0 || strcmp(mode, "memchr_16k") == 0 ||
        strcmp(mode, "strstr_4k") == 0 || strcmp(mode, "memmem_4k") == 0 ||
        strcmp(mode, "memcpy_matrix") == 0 || strcmp(mode, "memset_matrix") == 0 ||
        strcmp(mode, "strlen_matrix") == 0 || strcmp(mode, "memchr_matrix") == 0 ||
        strcmp(mode, "strstr_matrix") == 0 || strcmp(mode, "memmem_matrix") == 0)
        return CRABC_PERF_MEMORY_ROW_SCALAR;
    if (strcmp(mode, "span_matrix") == 0)
        return CRABC_PERF_MEMORY_ROW_SPAN;
    if (strcmp(mode, "allocator_64") == 0 || strcmp(mode, "allocator_4k") == 0)
        return CRABC_PERF_MEMORY_ROW_ALLOCATOR;
    if (strcmp(mode, "dlsym_1") == 0 || strcmp(mode, "dlsym_128") == 0 ||
        strcmp(mode, "dlsym_1024") == 0)
        return CRABC_PERF_MEMORY_ROW_DLSYM;
    if (strcmp(mode, "dlopen_graph") == 0)
        return CRABC_PERF_MEMORY_ROW_GRAPH;
    return CRABC_PERF_MEMORY_ROW_NONE;
}

/* Match the unchanged fixture's permissive positive strtoull grammar. */
CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_parse_count(const char *text, unsigned long long *result)
{
    char *end = NULL;
    int saved_errno = errno;
    unsigned long long value;

    if (text == NULL || result == NULL)
        return 0;
    value = strtoull(text, &end, 10);
    errno = saved_errno;
    if (text[0] == '\0' || end == NULL || *end != '\0' || value == 0)
        return 0;
    *result = value;
    return 1;
}

CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_plan(enum crabc_perf_memory_row row, unsigned long long iterations)
{
    unsigned int index;

    crabc_perf_memory_observer.row = row;
    crabc_perf_memory_observer.iterations = iterations;
    if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_MAIN_INITIAL))
        return 0;
    switch (row) {
    case CRABC_PERF_MEMORY_ROW_STARTUP:
        break;
    case CRABC_PERF_MEMORY_ROW_CLOCK:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_CLOCK_FINAL_CALL))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_OPEN:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_OPEN_BEFORE_CLOSE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_FD:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_FD_BEFORE_CLOSE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_STDIO:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_STDIO_BEFORE_FCLOSE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_PTHREAD_CREATE_JOIN_TLS:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_PTHREAD_CALLBACK_READY))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_MUTEX_UNCONTENDED:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_MUTEX_BEFORE_DESTROY))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_MUTEX_COND_PING_PONG:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_PINGPONG_BEFORE_WORKER_EXIT))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_TLS_GROWTH:
        if (iterations > 8)
            return 0;
        for (index = 0; index < (unsigned int)iterations; index++) {
            if (!crabc_perf_memory_append((enum crabc_perf_memory_phase)(
                    CRABC_PERF_MEMORY_TLS_PARENT_LOAD_0 + index)))
                return 0;
        }
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_TLS_WORKER_COMPLETE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_SCALAR:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_SCALAR_ARRAYS_LIVE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_SPAN:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_SPAN_BEFORE_FIRST_MUNMAP))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_ALLOCATOR:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_ALLOCATOR_BEFORE_FINAL_FREE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_DLSYM:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_DLSYM_BEFORE_DLCLOSE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_GRAPH:
        if (!crabc_perf_memory_append(CRABC_PERF_MEMORY_GRAPH_BEFORE_DLCLOSE))
            return 0;
        break;
    case CRABC_PERF_MEMORY_ROW_NONE:
        return 0;
    }
    return crabc_perf_memory_append(CRABC_PERF_MEMORY_MAIN_FINAL);
}

/*
 * The profile fixes the inherited descriptors to 97/98.  Requiring their
 * exact canonical spellings makes a malformed observer environment fail
 * before benchmark work; both variables absent leaves ordinary execution
 * untouched.
 */
CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_prepare_descriptors(void)
{
    const char *ready = getenv(CRABC_PERF_MEMORY_OBSERVER_READY_ENV);
    const char *continued = getenv(CRABC_PERF_MEMORY_OBSERVER_CONTINUE_ENV);

    if (ready == NULL && continued == NULL)
        return 0;
    if (ready == NULL || continued == NULL || strcmp(ready, "97") != 0 ||
        strcmp(continued, "98") != 0)
        return -1;
    crabc_perf_memory_observer.enabled = 1;
    crabc_perf_memory_observer.ready_fd = CRABC_PERF_MEMORY_OBSERVER_READY_FD;
    crabc_perf_memory_observer.continue_fd = CRABC_PERF_MEMORY_OBSERVER_CONTINUE_FD;
    return 1;
}

CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_write_byte(int descriptor, char byte)
{
    for (;;) {
        ssize_t written = write(descriptor, &byte, 1);

        if (written == 1)
            return 1;
        if (written < 0 && errno == EINTR)
            continue;
        return 0;
    }
}

CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_read_byte(int descriptor, char *byte)
{
    for (;;) {
        ssize_t read_count = read(descriptor, byte, 1);

        if (read_count == 1)
            return 1;
        if (read_count < 0 && errno == EINTR)
            continue;
        return 0;
    }
}

/* Every observer-only FD operation restores the fixture call's errno. */
CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_checkpoint(enum crabc_perf_memory_phase phase)
{
    char acknowledgement;
    int saved_errno = errno;
    int complete = 0;

    if (!crabc_perf_memory_observer.enabled)
        return 1;
    if (!crabc_perf_memory_observer.failed &&
        crabc_perf_memory_observer.next_phase < crabc_perf_memory_observer.phase_count &&
        crabc_perf_memory_observer.phases[crabc_perf_memory_observer.next_phase] == phase &&
        crabc_perf_memory_write_byte(crabc_perf_memory_observer.ready_fd, 'R') &&
        crabc_perf_memory_read_byte(crabc_perf_memory_observer.continue_fd, &acknowledgement) &&
        acknowledgement == 'C') {
        crabc_perf_memory_observer.next_phase++;
        complete = 1;
    } else {
        crabc_perf_memory_observer.failed = 1;
    }
    errno = saved_errno;
    return complete;
}

/* Return one of: run source, malformed environment, or failed initial R/C. */
CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_begin_workload(int argc, char **argv)
{
    enum crabc_perf_memory_row row;
    unsigned long long iterations;
    int descriptors;

    crabc_perf_memory_reset();
    descriptors = crabc_perf_memory_prepare_descriptors();
    if (descriptors < 0)
        return -1;
    if (descriptors == 0)
        return 0;
    if (argc < 3 || !crabc_perf_memory_parse_count(argv[2], &iterations))
        return 0;
    row = crabc_perf_memory_row_from_mode(argv[1]);
    if (row == CRABC_PERF_MEMORY_ROW_NONE || !crabc_perf_memory_plan(row, iterations)) {
        crabc_perf_memory_observer.enabled = 0;
        return 0;
    }
    return crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_MAIN_INITIAL) ? 1 : -2;
}

CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_begin_startup(void)
{
    int descriptors;

    crabc_perf_memory_reset();
    descriptors = crabc_perf_memory_prepare_descriptors();
    if (descriptors < 0)
        return -1;
    if (descriptors == 0)
        return 0;
    if (!crabc_perf_memory_plan(CRABC_PERF_MEMORY_ROW_STARTUP, 1))
        return -1;
    return crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_MAIN_INITIAL) ? 1 : -2;
}

CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_is_row(enum crabc_perf_memory_row row)
{
    return crabc_perf_memory_observer.enabled && crabc_perf_memory_observer.row == row;
}

CRABC_PERF_MEMORY_LOCAL int
crabc_perf_memory_finish(int original_status)
{
    if (!crabc_perf_memory_observer.enabled)
        return original_status;
    if (original_status != 0 || crabc_perf_memory_observer.failed)
        return original_status == 0 ? 1 : original_status;
    if (!crabc_perf_memory_checkpoint(CRABC_PERF_MEMORY_MAIN_FINAL))
        return 1;
    return 0;
}

#undef CRABC_PERF_MEMORY_LOCAL

#endif

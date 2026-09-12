/*
 * Static timing supervisor for the native x86 performance harness.
 *
 * The supervisor completes every filesystem, descriptor, chroot, and cwd
 * operation before fork(2).  The measured child then has exactly one path:
 * direct execve(2), or _exit(127) when execve fails.  wait4(2) therefore
 * describes the client and does not require a guessed setup-cost subtraction.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>


#ifndef SYS_close_range
#error "the native x86 timing launcher requires SYS_close_range (Linux >= 5.10)"
#endif

#ifndef SYS_pidfd_open
#error "the native x86 timing launcher requires SYS_pidfd_open (Linux >= 5.10)"
#endif

enum {
    EXIT_SETUP_FAILURE = 125,
    EXIT_COLLECTION_FAILURE = 126,
    RESULT_DESCRIPTOR = 3,
    SAVED_DESCRIPTOR_MINIMUM = 10,
};

static const char RESULT_SCHEMA[] = "crabc.perf.x86_64-timing-launcher/v1";


static bool absolute_path(const char *value) {
    return value != NULL && value[0] == '/';
}


static bool direct_application_binary(const char *value) {
    const char *part;

    if (value == NULL || strncmp(value, "/app/bin/", 9) != 0 || value[9] == '\0') {
        return false;
    }
    part = value + 9;
    while (*part != '\0') {
        const char *slash = strchr(part, '/');
        size_t length = slash == NULL ? strlen(part) : (size_t)(slash - part);

        if (length == 0 || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) {
            return false;
        }
        if (slash == NULL) {
            return true;
        }
        part = slash + 1;
    }
    return false;
}


static int parse_timeout_ms(const char *text, int *value) {
    char *end = NULL;
    unsigned long parsed;
    const unsigned char *cursor;

    if (text == NULL || text[0] == '\0') {
        return -1;
    }
    for (cursor = (const unsigned char *)text; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9') {
            return -1;
        }
    }
    errno = 0;
    parsed = strtoul(text, &end, 10);
    if (errno != 0 || end == NULL || *end != '\0' || parsed == 0 || parsed > INT_MAX) {
        return -1;
    }
    *value = (int)parsed;
    return 0;
}


static int open_root_directory(const char *path) {
    int descriptor;
    struct stat metadata;

    descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }
    if (fstat(descriptor, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) {
        int saved_errno = errno == 0 ? ENOTDIR : errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    return descriptor;
}


static int open_root_stdin(int root_descriptor) {
    int descriptor;
    struct stat metadata;

    descriptor = openat(root_descriptor, "dev/null", O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0) {
        return -1;
    }
    if (fstat(descriptor, &metadata) != 0 || !S_ISCHR(metadata.st_mode) ||
        major(metadata.st_rdev) != 1 || minor(metadata.st_rdev) != 3) {
        int saved_errno = errno == 0 ? EINVAL : errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    return descriptor;
}


static int open_new_regular_output(const char *path) {
    int descriptor;
    struct stat metadata;

    descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (descriptor < 0) {
        return -1;
    }
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode)) {
        int saved_errno = errno == 0 ? EINVAL : errno;
        (void)close(descriptor);
        errno = saved_errno;
        return -1;
    }
    return descriptor;
}


static int duplicate_saved(int descriptor) {
    return fcntl(descriptor, F_DUPFD_CLOEXEC, SAVED_DESCRIPTOR_MINIMUM);
}


static void close_descriptors(int *descriptors, size_t count) {
    size_t index;

    for (index = 0; index < count; ++index) {
        if (descriptors[index] >= 0) {
            (void)close(descriptors[index]);
            descriptors[index] = -1;
        }
    }
}


static int close_after_result_descriptor(void) {
    if (syscall(SYS_close_range, (unsigned int)(RESULT_DESCRIPTOR + 1), UINT_MAX, 0U) != 0) {
        return -1;
    }
    return 0;
}


/*
 * All retained descriptors are copied above stdio before any dup2 call.  That
 * also handles an invoker which entered with one or more standard descriptors
 * already closed.  Once this function returns, only 0, 1, 2, and the
 * close-on-exec result descriptor 3 remain open.
 */
static int prepare_supervisor(const char *root_path, const char *stdout_path,
                              const char *stderr_path, const char *result_path) {
    int opened[5] = {-1, -1, -1, -1, -1};
    int saved[5] = {-1, -1, -1, -1, -1};
    size_t index;

    opened[0] = open_root_directory(root_path);
    if (opened[0] < 0) {
        goto failure;
    }
    opened[1] = open_root_stdin(opened[0]);
    if (opened[1] < 0) {
        goto failure;
    }
    opened[2] = open_new_regular_output(stdout_path);
    if (opened[2] < 0) {
        goto failure;
    }
    opened[3] = open_new_regular_output(stderr_path);
    if (opened[3] < 0) {
        goto failure;
    }
    opened[4] = open_new_regular_output(result_path);
    if (opened[4] < 0) {
        goto failure;
    }
    for (index = 0; index < sizeof(saved) / sizeof(saved[0]); ++index) {
        saved[index] = duplicate_saved(opened[index]);
        if (saved[index] < 0) {
            goto failure;
        }
    }
    close_descriptors(opened, sizeof(opened) / sizeof(opened[0]));

    if (fchdir(saved[0]) != 0 || chroot(".") != 0 || chdir("/app") != 0) {
        goto failure;
    }
    if (dup2(saved[1], STDIN_FILENO) < 0 || dup2(saved[2], STDOUT_FILENO) < 0 ||
        dup2(saved[3], STDERR_FILENO) < 0 ||
        dup3(saved[4], RESULT_DESCRIPTOR, O_CLOEXEC) < 0) {
        goto failure;
    }
    if (close_after_result_descriptor() != 0) {
        goto failure;
    }
    return RESULT_DESCRIPTOR;

failure:
    close_descriptors(opened, sizeof(opened) / sizeof(opened[0]));
    close_descriptors(saved, sizeof(saved) / sizeof(saved[0]));
    return -1;
}


static int monotonic_ns(uint64_t *value) {
    struct timespec instant;

    if (clock_gettime(CLOCK_MONOTONIC, &instant) != 0 || instant.tv_sec < 0 || instant.tv_nsec < 0 ||
        instant.tv_nsec >= 1000000000L ||
        (uint64_t)instant.tv_sec > (UINT64_MAX - (uint64_t)instant.tv_nsec) / UINT64_C(1000000000)) {
        return -1;
    }
    *value = (uint64_t)instant.tv_sec * UINT64_C(1000000000) + (uint64_t)instant.tv_nsec;
    return 0;
}


static int remaining_poll_ms(uint64_t deadline, int *milliseconds) {
    uint64_t now;
    uint64_t remaining;
    uint64_t rounded;

    if (monotonic_ns(&now) != 0) {
        return -1;
    }
    if (now >= deadline) {
        *milliseconds = 0;
        return 0;
    }
    remaining = deadline - now;
    rounded = (remaining + UINT64_C(999999)) / UINT64_C(1000000);
    *milliseconds = rounded > (uint64_t)INT_MAX ? INT_MAX : (int)rounded;
    return 0;
}


static int wait4_retry(pid_t child, int *status, struct rusage *usage) {
    pid_t waited;

    do {
        waited = wait4(child, status, 0, usage);
    } while (waited < 0 && errno == EINTR);
    return waited == child ? 0 : -1;
}


static void kill_and_reap_owned_child(pid_t child) {
    int ignored_status;
    struct rusage ignored_usage;

    if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
        return;
    }
    (void)wait4_retry(child, &ignored_status, &ignored_usage);
}


/*
 * pidfd polling blocks for the remaining deadline in one kernel wait.  EINTR
 * only recalculates the same deadline; this is not a user-space millisecond
 * polling loop.
 */
static int wait_for_owned_child(pid_t child, uint64_t deadline, int *status,
                                struct rusage *usage, bool *timed_out) {
    int pidfd;
    struct pollfd event;

    pidfd = (int)syscall(SYS_pidfd_open, child, 0U);
    if (pidfd < 0) {
        kill_and_reap_owned_child(child);
        return -1;
    }
    event.fd = pidfd;
    event.events = POLLIN;
    event.revents = 0;
    *timed_out = false;
    for (;;) {
        int milliseconds;
        int poll_result;

        if (remaining_poll_ms(deadline, &milliseconds) != 0) {
            int saved_errno = errno;
            (void)close(pidfd);
            kill_and_reap_owned_child(child);
            errno = saved_errno;
            return -1;
        }
        poll_result = poll(&event, 1, milliseconds);
        if (poll_result > 0) {
            break;
        }
        if (poll_result == 0) {
            *timed_out = true;
            if (kill(child, SIGKILL) != 0 && errno != ESRCH) {
                int saved_errno = errno;
                (void)close(pidfd);
                kill_and_reap_owned_child(child);
                errno = saved_errno;
                return -1;
            }
            break;
        }
        if (errno != EINTR) {
            int saved_errno = errno;
            (void)close(pidfd);
            kill_and_reap_owned_child(child);
            errno = saved_errno;
            return -1;
        }
    }
    (void)close(pidfd);
    if (wait4_retry(child, status, usage) != 0) {
        return -1;
    }
    return 0;
}


static int timeval_to_ns(const struct timeval *value, uint64_t *nanoseconds) {
    uint64_t seconds;
    uint64_t microseconds;

    if (value->tv_sec < 0 || value->tv_usec < 0 || value->tv_usec >= 1000000L) {
        return -1;
    }
    seconds = (uint64_t)value->tv_sec;
    microseconds = (uint64_t)value->tv_usec;
    if (seconds > (UINT64_MAX - microseconds * UINT64_C(1000)) / UINT64_C(1000000000)) {
        return -1;
    }
    *nanoseconds = seconds * UINT64_C(1000000000) + microseconds * UINT64_C(1000);
    return 0;
}


static int nonnegative_long(long value, uint64_t *result) {
    if (value < 0) {
        return -1;
    }
    *result = (uint64_t)value;
    return 0;
}


static int write_all(int descriptor, const char *buffer, size_t length) {
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(descriptor, buffer + written, length - written);

        if (result > 0) {
            written += (size_t)result;
            continue;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return -1;
    }
    return 0;
}


static int write_result(int descriptor, pid_t child, int status, bool timed_out,
                        uint64_t elapsed_ns, const struct rusage *usage) {
    uint64_t user_cpu_ns;
    uint64_t system_cpu_ns;
    uint64_t max_rss_kib;
    uint64_t minor_faults;
    uint64_t major_faults;
    uint64_t voluntary_switches;
    uint64_t involuntary_switches;
    char encoded[1024];
    int length;

    if (child <= 0 || status < 0 || timeval_to_ns(&usage->ru_utime, &user_cpu_ns) != 0 ||
        timeval_to_ns(&usage->ru_stime, &system_cpu_ns) != 0 ||
        nonnegative_long(usage->ru_maxrss, &max_rss_kib) != 0 ||
        nonnegative_long(usage->ru_minflt, &minor_faults) != 0 ||
        nonnegative_long(usage->ru_majflt, &major_faults) != 0 ||
        nonnegative_long(usage->ru_nvcsw, &voluntary_switches) != 0 ||
        nonnegative_long(usage->ru_nivcsw, &involuntary_switches) != 0) {
        return -1;
    }
    length = snprintf(
        encoded, sizeof(encoded),
        "{\"schema\":\"%s\",\"child_pid\":%ld,\"wait_status\":%d,\"timed_out\":%s,"
        "\"elapsed_wall_ns\":%" PRIu64 ",\"resources\":{\"user_cpu_ns\":%" PRIu64
        ",\"system_cpu_ns\":%" PRIu64 ",\"max_rss_kib\":%" PRIu64
        ",\"minor_faults\":%" PRIu64 ",\"major_faults\":%" PRIu64
        ",\"voluntary_context_switches\":%" PRIu64
        ",\"involuntary_context_switches\":%" PRIu64 "}}\n",
        RESULT_SCHEMA, (long)child, status, timed_out ? "true" : "false", elapsed_ns,
        user_cpu_ns, system_cpu_ns, max_rss_kib, minor_faults, major_faults,
        voluntary_switches, involuntary_switches);
    if (length < 0 || (size_t)length >= sizeof(encoded)) {
        return -1;
    }
    return write_all(descriptor, encoded, (size_t)length);
}


int main(int argc, char **argv) {
    int timeout_ms;
    int result_descriptor;
    pid_t child;
    int status;
    bool timed_out;
    struct rusage usage;
    uint64_t started;
    uint64_t deadline;
    uint64_t completed;

    if (argc < 7 || !absolute_path(argv[1]) || !absolute_path(argv[2]) || !absolute_path(argv[3]) ||
        !absolute_path(argv[4]) || !direct_application_binary(argv[6]) ||
        strcmp(argv[2], argv[3]) == 0 || strcmp(argv[2], argv[4]) == 0 || strcmp(argv[3], argv[4]) == 0 ||
        parse_timeout_ms(argv[5], &timeout_ms) != 0) {
        return EXIT_SETUP_FAILURE;
    }
    result_descriptor = prepare_supervisor(argv[1], argv[2], argv[3], argv[4]);
    if (result_descriptor != RESULT_DESCRIPTOR) {
        return EXIT_SETUP_FAILURE;
    }

    if (monotonic_ns(&started) != 0 ||
        started > UINT64_MAX - (uint64_t)timeout_ms * UINT64_C(1000000)) {
        return EXIT_COLLECTION_FAILURE;
    }
    deadline = started + (uint64_t)timeout_ms * UINT64_C(1000000);
    child = fork();
    if (child < 0) {
        return EXIT_COLLECTION_FAILURE;
    }
    if (child == 0) {
        execve(argv[6], &argv[6], environ);
        _exit(127);
    }
    if (wait_for_owned_child(child, deadline, &status, &usage, &timed_out) != 0 ||
        monotonic_ns(&completed) != 0 || completed < started ||
        write_result(result_descriptor, child, status, timed_out, completed - started, &usage) != 0) {
        return EXIT_COLLECTION_FAILURE;
    }
    return 0;
}

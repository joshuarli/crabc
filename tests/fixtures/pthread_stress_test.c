#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <poll.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern int sched_yield(void);

/* Keep this above the fixed libc table capacity: all workers are sequential,
 * so success proves that completed slots (including detached slots) return to
 * the creator rather than merely increasing the live-thread limit. */
#define LIFETIMES 96
#define TIMED_ROUNDS 8

static int failures;

#define CHECK(expr, message) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "FAIL: %s\n", message); \
            failures++; \
        } \
    } while (0)

static pthread_mutex_t lifecycle_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t lifecycle_cond = PTHREAD_COND_INITIALIZER;
static int detached_done;

static void *joinable_worker(void *arg) {
    int *value = (int *)arg;
    pthread_mutex_lock(&lifecycle_mutex);
    (*value)++;
    pthread_mutex_unlock(&lifecycle_mutex);
    return arg;
}

static int held_joinable_done;

static void *held_joinable_worker(void *arg) {
    pthread_mutex_lock(&lifecycle_mutex);
    held_joinable_done = 1;
    pthread_cond_signal(&lifecycle_cond);
    pthread_mutex_unlock(&lifecycle_mutex);
    return arg;
}

static void *detached_worker(void *arg) {
    (void)arg;
    pthread_mutex_lock(&lifecycle_mutex);
    detached_done++;
    pthread_cond_signal(&lifecycle_cond);
    pthread_mutex_unlock(&lifecycle_mutex);
    return NULL;
}

static void test_joinable_lifetimes(void) {
    for (int i = 0; i < LIFETIMES; i++) {
        pthread_t thread;
        int value = i;
        void *result = NULL;

        int create_result = pthread_create(&thread, NULL, joinable_worker, &value);
        CHECK(create_result == 0, "create joinable worker");
        if (create_result != 0)
            return;
        CHECK(pthread_join(thread, &result) == 0, "join joinable worker");
        CHECK(result == &value, "join result points at worker argument");
        CHECK(value == i + 1, "joinable worker ran");
    }
}

#define RWLOCK_WORKERS 4
#define RWLOCK_ROUNDS 256

static pthread_rwlock_t stress_rwlock;
static int stress_rwlock_value;

static void *rwlock_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < RWLOCK_ROUNDS; i++) {
        if (pthread_rwlock_rdlock(&stress_rwlock) != 0)
            return (void *)1;
        int snapshot = stress_rwlock_value;
        if (pthread_rwlock_unlock(&stress_rwlock) != 0 || snapshot < 0)
            return (void *)1;
        if (pthread_rwlock_wrlock(&stress_rwlock) != 0)
            return (void *)1;
        stress_rwlock_value++;
        if (pthread_rwlock_unlock(&stress_rwlock) != 0)
            return (void *)1;
    }
    return NULL;
}

static void test_rwlock_stress(void) {
    pthread_t threads[RWLOCK_WORKERS];
    int created = 0;
    stress_rwlock_value = 0;
    CHECK(pthread_rwlock_init(&stress_rwlock, NULL) == 0, "rwlock stress init");
    for (int i = 0; i < RWLOCK_WORKERS; i++) {
        int result = pthread_create(&threads[i], NULL, rwlock_worker, NULL);
        CHECK(result == 0, "create rwlock stress worker");
        if (result != 0)
            break;
        created++;
    }
    for (int i = 0; i < created; i++) {
        void *result = NULL;
        CHECK(pthread_join(threads[i], &result) == 0, "join rwlock stress worker");
        CHECK(result == NULL, "rwlock stress worker completed");
    }
    CHECK(created == RWLOCK_WORKERS, "all rwlock stress workers created");
    CHECK(stress_rwlock_value == RWLOCK_WORKERS * RWLOCK_ROUNDS,
          "rwlock stress write count");
    CHECK(pthread_rwlock_destroy(&stress_rwlock) == 0, "rwlock stress destroy");
}

#define ONCE_WORKERS 4
#define ONCE_ROUNDS 256

static pthread_once_t stress_once = PTHREAD_ONCE_INIT;
static int stress_once_calls;

static void stress_once_init(void) {
    stress_once_calls++;
}

static void *once_worker(void *arg) {
    (void)arg;
    for (int i = 0; i < ONCE_ROUNDS; i++) {
        if (pthread_once(&stress_once, stress_once_init) != 0)
            return (void *)1;
    }
    return NULL;
}

static void test_once_stress(void) {
    pthread_t threads[ONCE_WORKERS];
    int created = 0;
    stress_once_calls = 0;
    for (int i = 0; i < ONCE_WORKERS; i++) {
        int result = pthread_create(&threads[i], NULL, once_worker, NULL);
        CHECK(result == 0, "create once stress worker");
        if (result != 0)
            break;
        created++;
    }
    for (int i = 0; i < created; i++) {
        void *result = NULL;
        CHECK(pthread_join(threads[i], &result) == 0, "join once stress worker");
        CHECK(result == NULL, "once stress worker completed");
    }
    CHECK(created == ONCE_WORKERS, "all once stress workers created");
    CHECK(stress_once_calls == 1, "once initializer ran once");
}

static void deadline_after_ms(struct timespec *deadline, long milliseconds) {
    clock_gettime(CLOCK_REALTIME, deadline);
    deadline->tv_sec += milliseconds / 1000;
    deadline->tv_nsec += (milliseconds % 1000) * 1000000L;
    if (deadline->tv_nsec >= 1000000000L) {
        deadline->tv_sec++;
        deadline->tv_nsec -= 1000000000L;
    }
}

static pthread_mutex_t timed_hold_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t timed_gate_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t timed_gate_cond = PTHREAD_COND_INITIALIZER;
static int timed_holder_ready;
static int timed_holder_release;

static void *timed_mutex_holder(void *arg) {
    (void)arg;
    pthread_mutex_lock(&timed_hold_mutex);
    pthread_mutex_lock(&timed_gate_mutex);
    timed_holder_ready = 1;
    pthread_cond_signal(&timed_gate_cond);
    while (!timed_holder_release)
        pthread_cond_wait(&timed_gate_cond, &timed_gate_mutex);
    pthread_mutex_unlock(&timed_gate_mutex);
    pthread_mutex_unlock(&timed_hold_mutex);
    return NULL;
}

static void test_timed_waits(void) {
    pthread_t holder;
    timed_holder_ready = 0;
    timed_holder_release = 0;
    int create_result = pthread_create(&holder, NULL, timed_mutex_holder, NULL);
    CHECK(create_result == 0, "create timed mutex holder");
    if (create_result == 0) {
        pthread_mutex_lock(&timed_gate_mutex);
        while (!timed_holder_ready)
            pthread_cond_wait(&timed_gate_cond, &timed_gate_mutex);
        pthread_mutex_unlock(&timed_gate_mutex);

        for (int i = 0; i < TIMED_ROUNDS; i++) {
            struct timespec deadline;
            deadline_after_ms(&deadline, 5);
            int timed_result = pthread_mutex_timedlock(&timed_hold_mutex, &deadline);
            CHECK(timed_result == ETIMEDOUT, "mutex timedlock expires while held");
            if (timed_result == 0)
                pthread_mutex_unlock(&timed_hold_mutex);
        }

        pthread_mutex_lock(&timed_gate_mutex);
        timed_holder_release = 1;
        pthread_cond_signal(&timed_gate_cond);
        pthread_mutex_unlock(&timed_gate_mutex);
        CHECK(pthread_join(holder, NULL) == 0, "join timed mutex holder");
    }

    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_lock(&cond_mutex);
    for (int i = 0; i < TIMED_ROUNDS; i++) {
        struct timespec cond_deadline;
        deadline_after_ms(&cond_deadline, 5);
        CHECK(pthread_cond_timedwait(&cond, &cond_mutex, &cond_deadline) == ETIMEDOUT,
              "condition timedwait expires without signal");
    }
    pthread_mutex_unlock(&cond_mutex);
    pthread_cond_destroy(&cond);
    pthread_mutex_destroy(&cond_mutex);
}

static pthread_mutex_t fork_live_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t fork_live_cond = PTHREAD_COND_INITIALIZER;
static int fork_live_ready;
static int fork_live_release;

static void *fork_live_worker(void *arg) {
    (void)arg;
    pthread_mutex_lock(&fork_live_mutex);
    fork_live_ready = 1;
    pthread_cond_signal(&fork_live_cond);
    while (!fork_live_release)
        pthread_cond_wait(&fork_live_cond, &fork_live_mutex);
    pthread_mutex_unlock(&fork_live_mutex);
    return NULL;
}

static int waitpid_bounded(pid_t pid, int *status) {
    for (int i = 0; i < 1000; i++) {
        pid_t result = waitpid(pid, status, WNOHANG);
        if (result == pid)
            return 0;
        if (result < 0)
            return -1;
        struct timespec pause_for = {0, 1000000L};
        nanosleep(&pause_for, NULL);
    }
    kill(pid, SIGKILL);
    waitpid(pid, status, 0);
    return -2;
}

static void test_fork_with_live_thread(void) {
    int pipefd[2];
    pthread_t worker;
    int pipe_result = pipe(pipefd);
    CHECK(pipe_result == 0, "fork live-thread pipe");
    if (pipe_result != 0)
        return;
    fork_live_ready = 0;
    fork_live_release = 0;
    int create_result = pthread_create(&worker, NULL, fork_live_worker, NULL);
    CHECK(create_result == 0, "create live thread before fork");
    if (create_result != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    pthread_mutex_lock(&fork_live_mutex);
    while (!fork_live_ready)
        pthread_cond_wait(&fork_live_cond, &fork_live_mutex);
    pthread_mutex_unlock(&fork_live_mutex);

    pid_t child = fork();
    CHECK(child >= 0, "fork with live thread");
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        pthread_mutex_lock(&fork_live_mutex);
        fork_live_release = 1;
        pthread_cond_signal(&fork_live_cond);
        pthread_mutex_unlock(&fork_live_mutex);
        CHECK(pthread_join(worker, NULL) == 0, "join live thread after failed fork");
        return;
    }
    if (child == 0) {
        char byte = 'F';
        pthread_t self = pthread_self();
        int previous_state = -1;
        int state_result = pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
                                                  &previous_state);
        if (state_result == 0)
            pthread_setcancelstate(previous_state, NULL);
        _exit(self != (pthread_t)0 && state_result == 0 &&
                      previous_state == PTHREAD_CANCEL_ENABLE &&
                      write(pipefd[1], &byte, 1) == 1
                  ? 0
                  : 111);
    }
    struct pollfd event = {pipefd[0], POLLIN, 0};
    int poll_result = poll(&event, 1, 1000);
    CHECK(poll_result == 1, "child write became readable");
    char byte = 0;
    if (poll_result == 1) {
        CHECK(read(pipefd[0], &byte, 1) == 1 && byte == 'F',
              "child wrote through inherited pipe");
    } else {
        kill(child, SIGKILL);
    }
    int status = 0;
    CHECK(waitpid_bounded(child, &status) == 0, "wait for fork child");
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "fork child exited successfully");
    close(pipefd[0]);
    close(pipefd[1]);
    pthread_mutex_lock(&fork_live_mutex);
    fork_live_release = 1;
    pthread_cond_signal(&fork_live_cond);
    pthread_mutex_unlock(&fork_live_mutex);
    CHECK(pthread_join(worker, NULL) == 0, "join live thread after fork");
}

static pthread_mutex_t cancel_probe_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cancel_probe_cond = PTHREAD_COND_INITIALIZER;
static int cancel_probe_ready;
static int cancel_probe_cleanup_count;
static int cancel_probe_fd;
static int cancel_probe_setup_error;

static void cancel_probe_signal_ready(void) {
    pthread_mutex_lock(&cancel_probe_mutex);
    cancel_probe_ready = 1;
    pthread_cond_signal(&cancel_probe_cond);
    pthread_mutex_unlock(&cancel_probe_mutex);
    sched_yield();
}

static void cancel_probe_wait_ready(void) {
    pthread_mutex_lock(&cancel_probe_mutex);
    while (!cancel_probe_ready)
        pthread_cond_wait(&cancel_probe_cond, &cancel_probe_mutex);
    pthread_mutex_unlock(&cancel_probe_mutex);
    for (int i = 0; i < 64; i++)
        sched_yield();
    struct timespec settle = {0, 1000000L};
    nanosleep(&settle, NULL);
}

static void cancel_probe_close_fd(void *arg) {
    int *fd = (int *)arg;
    close(*fd);
    cancel_probe_cleanup_count++;
}

static void *deferred_read_worker(void *arg) {
    (void)arg;
    char byte = 0;
    ssize_t result = -99;
    int type_result = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    cancel_probe_setup_error = type_result;
    pthread_cleanup_push(cancel_probe_close_fd, &cancel_probe_fd);
    cancel_probe_signal_ready();
    if (type_result == 0)
        result = read(cancel_probe_fd, &byte, 1);
    pthread_cleanup_pop(0);
    return (void *)(long)result;
}

static int deferred_read_probe(void) {
    int pipefd[2];
    pthread_t thread;
    void *result = NULL;
    cancel_probe_ready = 0;
    cancel_probe_cleanup_count = 0;
    cancel_probe_setup_error = -1;
    int pipe_result = pipe(pipefd);
    CHECK(pipe_result == 0, "deferred read pipe");
    if (pipe_result != 0)
        return 1;
    cancel_probe_fd = pipefd[0];
    int create_result = pthread_create(&thread, NULL, deferred_read_worker, NULL);
    CHECK(create_result == 0, "create deferred read worker");
    if (create_result != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }
    cancel_probe_wait_ready();
    CHECK(pthread_cancel(thread) == 0, "cancel deferred read worker");
    CHECK(pthread_join(thread, &result) == 0, "join deferred read worker");
    CHECK(cancel_probe_setup_error == 0, "deferred read cancellation type");
    CHECK(result == PTHREAD_CANCELED, "deferred read is a cancellation point");
    CHECK(cancel_probe_cleanup_count == 1, "deferred read cleanup ran");
    close(pipefd[1]);
    return failures == 0 ? 0 : 1;
}

static int cancel_probe_stream_cleanup_count;
static int cancel_probe_stream_cleanup_error;

static void cancel_probe_close_stream(void *arg) {
    FILE *stream = (FILE *)arg;
    if (fclose(stream) != 0)
        cancel_probe_stream_cleanup_error = 1;
    cancel_probe_stream_cleanup_count++;
}

static void *deferred_stdio_worker(void *arg) {
    FILE *stream = (FILE *)arg;
    int result = -99;
    int type_result = pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
    cancel_probe_setup_error = type_result;
    pthread_cleanup_push(cancel_probe_close_stream, stream);
    cancel_probe_signal_ready();
    if (type_result == 0)
        result = fgetc(stream);
    pthread_cleanup_pop(0);
    return (void *)(long)result;
}

static int deferred_stdio_probe(void) {
    int pipefd[2];
    pthread_t thread;
    void *result = NULL;
    cancel_probe_ready = 0;
    cancel_probe_stream_cleanup_count = 0;
    cancel_probe_stream_cleanup_error = 0;
    cancel_probe_setup_error = -1;
    int pipe_result = pipe(pipefd);
    CHECK(pipe_result == 0, "deferred stdio pipe");
    if (pipe_result != 0)
        return 1;
    FILE *stream = fdopen(pipefd[0], "r");
    CHECK(stream != NULL, "deferred stdio stream");
    if (stream == NULL) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }
    int create_result = pthread_create(&thread, NULL, deferred_stdio_worker, stream);
    CHECK(create_result == 0, "create deferred stdio worker");
    if (create_result != 0) {
        fclose(stream);
        close(pipefd[1]);
        return 1;
    }
    cancel_probe_wait_ready();
    CHECK(pthread_cancel(thread) == 0, "cancel deferred stdio worker");
    CHECK(pthread_join(thread, &result) == 0, "join deferred stdio worker");
    CHECK(cancel_probe_setup_error == 0, "deferred stdio cancellation type");
    CHECK(result == PTHREAD_CANCELED, "stdio read is a cancellation point");
    CHECK(cancel_probe_stream_cleanup_count == 1, "deferred stdio cleanup ran");
    CHECK(cancel_probe_stream_cleanup_error == 0, "deferred stdio cleanup closed stream");
    if (cancel_probe_stream_cleanup_count == 0)
        fclose(stream);
    close(pipefd[1]);
    return failures == 0 ? 0 : 1;
}

static void *async_read_worker(void *arg) {
    (void)arg;
    char byte = 0;
    ssize_t result = -99;
    pthread_cleanup_push(cancel_probe_close_fd, &cancel_probe_fd);
    int type_result = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    cancel_probe_setup_error = type_result;
    cancel_probe_signal_ready();
    if (type_result == 0)
        result = read(cancel_probe_fd, &byte, 1);
    pthread_cleanup_pop(0);
    return (void *)(long)result;
}

static int asynchronous_read_probe(void) {
    int pipefd[2];
    pthread_t thread;
    void *result = NULL;
    cancel_probe_ready = 0;
    cancel_probe_cleanup_count = 0;
    cancel_probe_setup_error = -1;
    int pipe_result = pipe(pipefd);
    CHECK(pipe_result == 0, "asynchronous read pipe");
    if (pipe_result != 0)
        return 1;
    cancel_probe_fd = pipefd[0];
    int create_result = pthread_create(&thread, NULL, async_read_worker, NULL);
    CHECK(create_result == 0, "create asynchronous read worker");
    if (create_result != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }
    cancel_probe_wait_ready();
    CHECK(pthread_cancel(thread) == 0, "cancel asynchronous read worker");
    CHECK(pthread_join(thread, &result) == 0, "join asynchronous read worker");
    CHECK(cancel_probe_setup_error == 0, "asynchronous cancellation type");
    CHECK(result == PTHREAD_CANCELED, "asynchronous cancellation result");
    CHECK(cancel_probe_cleanup_count == 1, "asynchronous cleanup ran");
    close(pipefd[1]);
    return failures == 0 ? 0 : 1;
}

static void cancel_probe_record_stream_cleanup(void *arg) {
    int *count = (int *)arg;
    (*count)++;
}

static void *async_stdio_worker(void *arg) {
    FILE *stream = (FILE *)arg;
    int result = -99;
    pthread_cleanup_push(cancel_probe_record_stream_cleanup,
                         &cancel_probe_stream_cleanup_count);
    int type_result = pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);
    cancel_probe_setup_error = type_result;
    cancel_probe_signal_ready();
    if (type_result == 0)
        result = fgetc(stream);
    pthread_cleanup_pop(0);
    return (void *)(long)result;
}

static int asynchronous_stdio_probe(void) {
    int pipefd[2];
    pthread_t thread;
    void *result = NULL;
    cancel_probe_ready = 0;
    cancel_probe_stream_cleanup_count = 0;
    cancel_probe_setup_error = -1;
    int pipe_result = pipe(pipefd);
    CHECK(pipe_result == 0, "asynchronous stdio pipe");
    if (pipe_result != 0)
        return 1;
    FILE *stream = fdopen(pipefd[0], "r");
    CHECK(stream != NULL, "asynchronous stdio stream");
    if (stream == NULL) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }
    int create_result = pthread_create(&thread, NULL, async_stdio_worker, stream);
    CHECK(create_result == 0, "create asynchronous stdio worker");
    if (create_result != 0) {
        fclose(stream);
        close(pipefd[1]);
        return 1;
    }
    cancel_probe_wait_ready();
    CHECK(pthread_cancel(thread) == 0, "cancel asynchronous stdio worker");
    CHECK(pthread_join(thread, &result) == 0, "join asynchronous stdio worker");
    CHECK(cancel_probe_setup_error == 0, "asynchronous stdio cancellation type");
    CHECK(result == PTHREAD_CANCELED, "asynchronous stdio cancellation result");
    CHECK(cancel_probe_stream_cleanup_count == 1, "asynchronous stdio cleanup ran");
    fclose(stream);
    close(pipefd[1]);
    return failures == 0 ? 0 : 1;
}

static pthread_mutex_t join_cancel_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t join_cancel_cond = PTHREAD_COND_INITIALIZER;
static int join_cancel_target_ready;
static int join_cancel_waiter_ready;
static int join_cancel_target_release;

static void *join_cancel_target_worker(void *arg) {
    pthread_mutex_lock(&join_cancel_mutex);
    join_cancel_target_ready = 1;
    pthread_cond_broadcast(&join_cancel_cond);
    while (!join_cancel_target_release)
        pthread_cond_wait(&join_cancel_cond, &join_cancel_mutex);
    pthread_mutex_unlock(&join_cancel_mutex);
    return arg;
}

static void *join_cancel_waiter(void *arg) {
    pthread_t target = *(pthread_t *)arg;

    pthread_mutex_lock(&join_cancel_mutex);
    join_cancel_waiter_ready = 1;
    pthread_cond_broadcast(&join_cancel_cond);
    pthread_mutex_unlock(&join_cancel_mutex);
    return (void *)(long)pthread_join(target, NULL);
}

static int joiner_cancellation_probe(void) {
    pthread_t target;
    pthread_t waiter;
    void *result = NULL;

    join_cancel_target_ready = 0;
    join_cancel_waiter_ready = 0;
    join_cancel_target_release = 0;
    CHECK(pthread_create(&target, NULL, join_cancel_target_worker, (void *)0x2468) == 0,
          "create join cancellation target");
    pthread_mutex_lock(&join_cancel_mutex);
    while (!join_cancel_target_ready)
        pthread_cond_wait(&join_cancel_cond, &join_cancel_mutex);
    pthread_mutex_unlock(&join_cancel_mutex);

    CHECK(pthread_create(&waiter, NULL, join_cancel_waiter, &target) == 0,
          "create join cancellation waiter");
    pthread_mutex_lock(&join_cancel_mutex);
    while (!join_cancel_waiter_ready)
        pthread_cond_wait(&join_cancel_cond, &join_cancel_mutex);
    pthread_mutex_unlock(&join_cancel_mutex);
    for (int i = 0; i < 64; i++)
        sched_yield();
    {
        const struct timespec settle = { 0, 1000000L };
        nanosleep(&settle, NULL);
    }

    CHECK(pthread_cancel(waiter) == 0, "cancel blocked join waiter");
    CHECK(pthread_join(waiter, &result) == 0, "join canceled join waiter");
    CHECK(result == PTHREAD_CANCELED, "join waiter observes cancellation");

    pthread_mutex_lock(&join_cancel_mutex);
    join_cancel_target_release = 1;
    pthread_cond_broadcast(&join_cancel_cond);
    pthread_mutex_unlock(&join_cancel_mutex);
    result = NULL;
    CHECK(pthread_join(target, &result) == 0, "join target after canceled waiter");
    CHECK(result == (void *)0x2468, "canceled waiter leaves target joinable");
    return failures == 0 ? 0 : 1;
}

static void run_probe_with_timeout(int (*probe)(void), const char *label) {
    pid_t child = fork();
    CHECK(child >= 0, label);
    if (child < 0)
        return;
    if (child == 0) {
        failures = 0;
        _exit(probe() == 0 && failures == 0 ? 0 : 1);
    }
    int status = 0;
    int wait_result = waitpid_bounded(child, &status);
    CHECK(wait_result == 0, label);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0, label);
}

static int rwlock_probe(void) {
    test_rwlock_stress();
    return failures == 0 ? 0 : 1;
}

static int once_probe(void) {
    test_once_stress();
    return failures == 0 ? 0 : 1;
}

static int timed_wait_probe(void) {
    test_timed_waits();
    return failures == 0 ? 0 : 1;
}

static int fork_live_probe(void) {
    test_fork_with_live_thread();
    return failures == 0 ? 0 : 1;
}

static void test_detached_lifetimes(void) {
    pthread_attr_t attr;
    CHECK(pthread_attr_init(&attr) == 0, "detached attr init");
    CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0,
          "set detached state");

    detached_done = 0;
    for (int i = 0; i < LIFETIMES; i++) {
        pthread_t thread;
        int create_result = pthread_create(&thread, &attr, detached_worker, NULL);
        CHECK(create_result == 0, "create detached worker");
        if (create_result != 0)
            break;

        pthread_mutex_lock(&lifecycle_mutex);
        while (detached_done <= i)
            pthread_cond_wait(&lifecycle_cond, &lifecycle_mutex);
        pthread_mutex_unlock(&lifecycle_mutex);

        /* Let the child reach its kernel exit/child-cleartid before the next
         * creator-side reclamation attempt. */
        for (volatile int spin = 0; spin < 128; spin++)
            ;
    }
    CHECK(pthread_attr_destroy(&attr) == 0, "detached attr destroy");
}

static void test_joinable_survives_detached_churn(void) {
    pthread_t held_thread;
    int held_value = 7;
    void *result = NULL;

    held_joinable_done = 0;
    int create_result = pthread_create(&held_thread, NULL, held_joinable_worker, &held_value);
    CHECK(create_result == 0, "create held joinable worker");
    if (create_result != 0)
        return;

    pthread_mutex_lock(&lifecycle_mutex);
    while (!held_joinable_done)
        pthread_cond_wait(&lifecycle_cond, &lifecycle_mutex);
    pthread_mutex_unlock(&lifecycle_mutex);

    /* A completed joinable slot must not be mistaken for an automatically
     * reclaimable detached slot while unrelated detached lifetimes churn. */
    test_detached_lifetimes();
    CHECK(pthread_join(held_thread, &result) == 0,
          "joinable worker survives detached reclamation");
    CHECK(result == &held_value, "held joinable result remains available");
    CHECK(held_value == 7, "held joinable worker completed");
}

static pthread_key_t stress_key;
static int destructor_calls;
static int destructor_token;

static void stress_destructor(void *value) {
    CHECK(value == &destructor_token, "TSD destructor value");
    destructor_calls++;
    /* Re-arm for the first three passes. The fourth pass must leave the key
     * clear, matching PTHREAD_DESTRUCTOR_ITERATIONS semantics. */
    if (destructor_calls < 4)
        CHECK(pthread_setspecific(stress_key, value) == 0, "TSD destructor rearm");
}

static pthread_mutex_t cancel_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cancel_cond = PTHREAD_COND_INITIALIZER;
static int cancel_started;
static int cleanup_count;
static int cleanup_order[3];

static void record_cleanup(void *arg) {
    if (cleanup_count < 3)
        cleanup_order[cleanup_count++] = (int)(long)arg;
}

static void unlock_cancel_mutex(void *arg) {
    if (cleanup_count < 3)
        cleanup_order[cleanup_count++] = 3;
    pthread_mutex_unlock((pthread_mutex_t *)arg);
}

static void *cancel_worker(void *arg) {
    (void)arg;
    CHECK(pthread_setspecific(stress_key, &destructor_token) == 0,
          "set cancellation TSD");
    CHECK(pthread_getspecific(stress_key) == &destructor_token,
          "get cancellation TSD");

    pthread_mutex_lock(&cancel_mutex);
    cancel_started = 1;
    pthread_cond_signal(&cancel_cond);

    /* The outer handler releases the mutex after the two inner handlers. */
    pthread_cleanup_push(unlock_cancel_mutex, &cancel_mutex);
    pthread_cleanup_push(record_cleanup, (void *)1L);
    pthread_cleanup_push(record_cleanup, (void *)2L);
    while (cancel_started)
        pthread_cond_wait(&cancel_cond, &cancel_mutex);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(1);
    return NULL;
}

static void test_cancellation_cleanup(void) {
    pthread_t thread;
    void *result = NULL;

    destructor_calls = 0;
    cleanup_count = 0;
    cancel_started = 0;
    int create_result = pthread_create(&thread, NULL, cancel_worker, NULL);
    CHECK(create_result == 0, "create cancellation worker");
    if (create_result != 0)
        return;

    pthread_mutex_lock(&cancel_mutex);
    while (!cancel_started)
        pthread_cond_wait(&cancel_cond, &cancel_mutex);
    pthread_mutex_unlock(&cancel_mutex);

    CHECK(pthread_cancel(thread) == 0, "cancel blocked worker");
    CHECK(pthread_join(thread, &result) == 0, "join canceled worker");
    CHECK(result == PTHREAD_CANCELED, "canceled join result");
    CHECK(cleanup_count == 3, "all cancellation handlers ran");
    CHECK(cleanup_order[0] == 2 && cleanup_order[1] == 1 && cleanup_order[2] == 3,
          "cancellation cleanup is LIFO");
    CHECK(destructor_calls == 4, "TSD destructor rearmed four passes");
    CHECK(pthread_getspecific(stress_key) == NULL, "canceled TSD is clear");
}

int main(void) {
    CHECK(pthread_key_create(&stress_key, stress_destructor) == 0, "create stress key");
    test_joinable_lifetimes();
    run_probe_with_timeout(rwlock_probe, "rwlock stress probe");
    run_probe_with_timeout(once_probe, "once stress probe");
    run_probe_with_timeout(timed_wait_probe, "timed wait probe");
    run_probe_with_timeout(fork_live_probe, "fork live-thread probe");
    run_probe_with_timeout(deferred_read_probe, "deferred read cancellation probe");
    run_probe_with_timeout(deferred_stdio_probe, "deferred stdio cancellation probe");
    run_probe_with_timeout(asynchronous_read_probe, "asynchronous read cancellation probe");
    run_probe_with_timeout(asynchronous_stdio_probe, "asynchronous stdio cancellation probe");
    run_probe_with_timeout(joiner_cancellation_probe, "joiner cancellation probe");
    test_joinable_survives_detached_churn();
    test_cancellation_cleanup();

    /* A canceled slot must be reusable immediately by a later lifecycle. */
    pthread_t final_thread;
    int final_value = 0;
    int final_create_result = pthread_create(&final_thread, NULL, joinable_worker, &final_value);
    CHECK(final_create_result == 0, "create post-cancel worker");
    if (final_create_result == 0)
        CHECK(pthread_join(final_thread, NULL) == 0, "join post-cancel worker");

    CHECK(pthread_key_delete(stress_key) == 0, "delete stress key");
    if (failures == 0) {
        printf("pthread stress ok\n");
        return 0;
    }
    printf("pthread stress FAIL %d\n", failures);
    return 1;
}

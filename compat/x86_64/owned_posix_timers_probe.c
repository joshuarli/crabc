#define _GNU_SOURCE
#include <errno.h>
#include <dlfcn.h>
#include <sys/resource.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s errno=%d\n", __LINE__, #x, errno); _Exit(1); } } while (0)
static _Thread_local int initialized = 73;
static _Thread_local int zeroed;
static _Thread_local unsigned char *allocation;
static pthread_key_t key;
static atomic_int callbacks, destructors, cleaned, cancel_ready, timer_tid;
static int cancel_pipe[2];
static pthread_t worker;
static timer_t callback_timer;
static int callback_mode;
static int dynamic_tls;
static const char *plugin_path = "/libtimer-tls.so";
static void *plugin;
static int (*plugin_touch)(void);
static void destructor(void *value)
{
    int pass = (int)(intptr_t)value;
    if (pass == 1) {
        CHECK(allocation != NULL && allocation[0] == 0x5a && allocation[4096] == 0x5a);
        free(allocation);
        allocation = NULL;
    }
    atomic_fetch_add(&destructors, 1);
    if (pass < 3) CHECK(pthread_setspecific(key, (void *)(intptr_t)(pass + 1)) == 0);
}
static void cleanup(void *value) { CHECK(value == &worker); atomic_fetch_add(&cleaned, 1); }
static void notify(union sigval value)
{
    if (atomic_load(&callbacks)) CHECK(errno == 67);
    CHECK(value.sival_int == 91);
    CHECK(initialized == 73 && zeroed == 0 && allocation == NULL);
    CHECK(pthread_getspecific(key) == NULL);
    int state, type;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state) == 0 && state == PTHREAD_CANCEL_ENABLE);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &type) == 0 && type == PTHREAD_CANCEL_DEFERRED);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
    int n = atomic_fetch_add(&callbacks, 1);
    if (!n) { worker = pthread_self(); atomic_store(&timer_tid, gettid()); }
    else CHECK(pthread_equal(worker, pthread_self()));
    if (dynamic_tls) {
        if (!plugin) {
            plugin = dlopen(plugin_path, RTLD_NOW | RTLD_LOCAL);
            CHECK(plugin != NULL);
            *(void **)(&plugin_touch) = dlsym(plugin, "timer_tls_touch");
            CHECK(plugin_touch != NULL);
        }
        CHECK(plugin_touch() == 1);
    }
    initialized = 99; zeroed = 99;
    allocation = malloc(4097);
    CHECK(allocation != NULL);
    memset(allocation, 0x5a, 4097);
    CHECK(pthread_setspecific(key, (void *)1) == 0);
    errno = 67;
    pthread_cleanup_push(cleanup, &worker);
    if (n == 0 && callback_mode >= 4) {
        if (callback_mode == 5) CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
        atomic_store(&cancel_ready, 1);
        if (callback_mode == 4) { char byte; read(cancel_pipe[0], &byte, 1); CHECK(0); }
        for (;;) atomic_signal_fence(memory_order_seq_cst);
    }
    if (callback_mode == 1) pthread_exit(NULL);
    if (callback_mode == 3) CHECK(timer_delete(callback_timer) == 0);
    if (callback_mode == 2) { CHECK(pthread_cancel(pthread_self()) == 0); pthread_testcancel(); CHECK(0); }
    pthread_cleanup_pop(1);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL) == 0);
}
static void wait_count(atomic_int *word, int wanted)
{
    for (int i = 0; atomic_load(word) < wanted && i < 2000; ++i) {
        struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL);
    }
    CHECK(atomic_load(word) >= wanted);
}
static void *initialize_cancellation_handler(void *unused)
{
    (void)unused;
    CHECK(pthread_cancel(pthread_self()) == 0);
    pthread_testcancel();
    return NULL;
}
static void thread_timer(void)
{
    pthread_t initializer;
    void *result;
    CHECK(pthread_create(&initializer, NULL, initialize_cancellation_handler, NULL) == 0);
    CHECK(pthread_join(initializer, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(pipe(cancel_pipe) == 0);
    CHECK(pthread_key_create(&key, destructor) == 0);
    for (callback_mode = 0; callback_mode < 6; ++callback_mode) {
        atomic_store(&cancel_ready, 0);
        atomic_store(&callbacks, 0); atomic_store(&destructors, 0); atomic_store(&cleaned, 0);
        struct sigevent event = {.sigev_notify = SIGEV_THREAD, .sigev_value.sival_int = 91, .sigev_notify_function = notify};
        pthread_attr_t attr;
        CHECK(pthread_attr_init(&attr) == 0);
        CHECK(pthread_attr_setstacksize(&attr, 262144) == 0);
        event.sigev_notify_attributes = &attr;
        timer_t timer;
        CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
        callback_timer = timer;
        CHECK(pthread_attr_destroy(&attr) == 0);
        struct itimerspec arm = {.it_value = {0, 1000000}}, old;
        for (int n = 1; n <= (callback_mode == 3 ? 1 : 4); ++n) {
            CHECK(timer_settime(timer, 0, &arm, &old) == 0);
            if (callback_mode >= 4 && n == 1) {
                wait_count(&cancel_ready, 1);
                CHECK(pthread_cancel(worker) == 0);
            }
            wait_count(&destructors, n * 3);
            CHECK(atomic_load(&callbacks) == n && atomic_load(&cleaned) == n);
            if (callback_mode == 0 && n == 1) {
                /* A reserved cancellation signal with no pending request
                   interrupts the wait, but musl retries it before errno translation. */
                struct timespec delay = {0, 10000000}; nanosleep(&delay, NULL);
                CHECK(syscall(SYS_tgkill, getpid(), atomic_load(&timer_tid), 33) == 0);
                nanosleep(&delay, NULL);
            }
        }
        if (callback_mode != 3) {
            CHECK(timer_gettime(timer, &old) == 0);
            CHECK(timer_getoverrun(timer) >= 0);
            CHECK(timer_delete(timer) == 0);
        }
    }
    CHECK(pthread_key_delete(key) == 0);
    CHECK(close(cancel_pipe[0]) == 0 && close(cancel_pipe[1]) == 0);
    puts("thread normal/exit/cancel/self-delete: identity, errno, TLS, allocation, cleanup, TSD reset");
}
static void kernel_timer(void)
{
    struct sigevent event = {.sigev_notify = SIGEV_NONE};
    timer_t timer;
    CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
    struct itimerspec arm = {.it_value = {30, 0}, .it_interval = {2, 0}}, old;
    CHECK(timer_settime(timer, 0, &arm, &old) == 0);
    CHECK(old.it_value.tv_sec == 0 && old.it_value.tv_nsec == 0);
    CHECK(timer_gettime(timer, &old) == 0 && old.it_value.tv_sec >= 29 && old.it_interval.tv_sec == 2);
    CHECK(timer_getoverrun(timer) == 0);
    arm = (struct itimerspec){0};
    CHECK(timer_settime(timer, 0, &arm, &old) == 0);
    CHECK(old.it_value.tv_sec >= 29);
    CHECK(timer_gettime(timer, &old) == 0);
    /* Compare the pinned oracle's observed SIGEV_NONE disarm query class;
       the signal-notification branches below separately require zero. */
    printf("none disarmed query zero: %d\n", old.it_value.tv_sec == 0 && old.it_value.tv_nsec == 0);
    CHECK(timer_delete(timer) == 0);
    errno = 123; CHECK(timer_delete(timer) == -EINVAL && errno == 123);
    errno = 0; CHECK(timer_gettime(timer, &old) == -1 && errno == EINVAL);
    sigset_t set, previous;
    sigemptyset(&set); sigaddset(&set, SIGUSR1);
    CHECK(pthread_sigmask(SIG_BLOCK, &set, &previous) == 0);
    for (int mode = 0; mode < 2; ++mode) {
        event.sigev_notify = mode ? SIGEV_THREAD_ID : SIGEV_SIGNAL;
        event.sigev_signo = SIGUSR1; event.sigev_value.sival_int = 47;
        event.sigev_notify_thread_id = gettid();
        CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
        arm = (struct itimerspec){.it_value = {30, 0}};
        CHECK(timer_settime(timer, 0, &arm, NULL) == 0);
        arm = (struct itimerspec){0};
        CHECK(timer_settime(timer, 0, &arm, &old) == 0 && old.it_value.tv_sec >= 29);
        CHECK(timer_gettime(timer, &old) == 0 && old.it_value.tv_sec == 0 && old.it_value.tv_nsec == 0);
        arm = (struct itimerspec){.it_value = {0, 1000000}};
        CHECK(timer_settime(timer, 0, &arm, NULL) == 0);
        siginfo_t info; struct timespec limit = {2, 0};
        CHECK(sigtimedwait(&set, &info, &limit) == SIGUSR1);
        CHECK(info.si_code == SI_TIMER && info.si_value.sival_int == 47);
        CHECK(timer_delete(timer) == 0);
    }
    event.sigev_notify = SIGEV_SIGNAL;
    CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == 0);
    struct timespec now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &now) == 0);
    arm = (struct itimerspec){.it_value = now, .it_interval = {0, 1000000}};
    CHECK(timer_settime(timer, TIMER_ABSTIME, &arm, NULL) == 0);
    struct timespec delay = {0, 20000000}; nanosleep(&delay, NULL);
    siginfo_t info; struct timespec limit = {2, 0};
    CHECK(sigtimedwait(&set, &info, &limit) == SIGUSR1 && info.si_overrun > 0);
    CHECK(timer_getoverrun(timer) == info.si_overrun);
    CHECK(timer_delete(timer) == 0);
    /* Drain any signal queued between the overrun observation and deletion. */
    limit = (struct timespec){0, 0};
    while (sigtimedwait(&set, &info, &limit) == SIGUSR1) {}
    CHECK(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
    sigemptyset(&set); sigaddset(&set, SIGALRM);
    CHECK(pthread_sigmask(SIG_BLOCK, &set, &previous) == 0);
    CHECK(timer_create(CLOCK_MONOTONIC, NULL, &timer) == 0);
    arm = (struct itimerspec){.it_value = {0, 1000000}};
    CHECK(timer_settime(timer, 0, &arm, NULL) == 0);
    limit = (struct timespec){2, 0};
    CHECK(sigtimedwait(&set, &info, &limit) == SIGALRM);
    CHECK(info.si_code == SI_TIMER && info.si_value.sival_int == (int)(intptr_t)timer);
    CHECK(timer_delete(timer) == 0);
    CHECK(pthread_sigmask(SIG_SETMASK, &previous, NULL) == 0);
    event.sigev_notify = 99;
    errno = 0; CHECK(timer_create(CLOCK_MONOTONIC, &event, &timer) == -1 && errno == EINVAL);
    puts("kernel none/signal/thread-id: lifecycle, delivery, raw-delete errno");
}
static void failure_reclamation(void)
{
    struct rlimit previous, bounded;
    CHECK(getrlimit(RLIMIT_AS, &previous) == 0);
    bounded = previous;
    bounded.rlim_cur = 64 * 1024 * 1024;
    CHECK(setrlimit(RLIMIT_AS, &bounded) == 0);
    struct sigevent event = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = notify};
    for (int i = 0; i < 32768; ++i) {
        timer_t timer;
        errno = 0;
        CHECK(timer_create(0x3fffffff, &event, &timer) == -1 && errno == EINVAL);
        struct timespec delay = {0, 100000}; nanosleep(&delay, NULL);
    }
    CHECK(setrlimit(RLIMIT_AS, &previous) == 0);
    puts("creation failure reclaims detached workers under bounded address space");
}
static atomic_int creator_returned, creator_cleaned, creator_errno;
static timer_t creator_timer;
static void unused_notification(union sigval value) { (void)value; }
static void creator_cleanup(void *unused)
{
    (void)unused;
    atomic_store(&creator_errno, errno);
    atomic_store(&creator_cleaned, 1);
}
static void *cancelled_creator(void *argument)
{
    int mode = (int)(intptr_t)argument;
    struct sigevent event = {.sigev_notify = mode == 2 ? SIGEV_NONE : SIGEV_THREAD,
                            .sigev_notify_function = unused_notification};
    pthread_cleanup_push(creator_cleanup, NULL);
    if (mode == 1) CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL) == 0);
    errno = 79;
    CHECK(pthread_cancel(pthread_self()) == 0);
    CHECK(timer_create(mode == 3 ? 0x3fffffff : CLOCK_MONOTONIC, &event, &creator_timer) == 0);
    atomic_store(&creator_returned, 1);
    CHECK(timer_delete(creator_timer) == 0);
    if (mode == 1) CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) == 0);
    if (mode != 0) pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static void creator_cancellation(void)
{
    for (int mode = 0; mode < 4; ++mode) {
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) {
            /* Source cancellation can orphan the newly created timer; the
               disposable process contains that resource and its worker. */
            creator_timer = (timer_t)(uintptr_t)0x1234;
            pthread_t caller;
            void *result = NULL;
            CHECK(pthread_create(&caller, NULL, cancelled_creator, (void *)(intptr_t)mode) == 0);
            CHECK(pthread_join(caller, &result) == 0);
            CHECK(result == PTHREAD_CANCELED && atomic_load(&creator_cleaned) == 1);
            CHECK(atomic_load(&creator_returned) == (mode == 1 || mode == 2));
            /* A disabled source sem_wait can leave EAGAIN from an empty
               sem_trywait; successful timer_create does not promise errno. */
            if (mode == 1) CHECK(atomic_load(&creator_errno) == 79 || atomic_load(&creator_errno) == EAGAIN);
            else CHECK(atomic_load(&creator_errno) == (mode == 3 ? EINVAL : 79));
            if (mode == 0 || mode == 3) CHECK(creator_timer == (timer_t)(uintptr_t)0x1234);
            _Exit(0);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    puts("timer creator: pending cancellation, disabled state, non-thread path");
}
static int failure_once(void)
{
    struct sigevent event = {.sigev_notify = SIGEV_THREAD, .sigev_notify_function = notify};
    timer_t timer;
    /* Fresh process: no keys, previous timer, allocation or callback state. */
    CHECK(timer_create(0x3fffffff, &event, &timer) == -1 && errno == EINVAL);
    return 0;
}
int main(int argc, char **argv)
{
    if (argc > 1 && !strcmp(argv[1], "failure-once")) return failure_once();
    dynamic_tls = argc > 1 && !strcmp(argv[1], "dynamic");
    alarm(20);
    if (argc > 1 && !strcmp(argv[1], "failure")) { failure_reclamation(); return 0; }
    if (argc > 2) plugin_path = argv[2];
    creator_cancellation();
    kernel_timer(); thread_timer();
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) { kernel_timer(); thread_timer(); _Exit(0); }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    puts("fork child creates fresh timers");
    return 0;
}

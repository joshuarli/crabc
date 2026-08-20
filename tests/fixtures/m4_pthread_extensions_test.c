#define _GNU_SOURCE 1

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile int release_worker;
static volatile int worker_name_ok;

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

static void *worker(void *arg)
{
    char name[32];
    int ok = pthread_setname_np(pthread_self(), "m4-self") == 0;
    ok = ok && pthread_getname_np(pthread_self(), name, sizeof name) == 0;
    ok = ok && strcmp(name, "m4-self") == 0;
    worker_name_ok = ok;
    while (!release_worker)
        sched_yield();
    return arg;
}

int main(void)
{
    pthread_attr_t attr;
    pthread_attr_t defaults;
    pthread_t thread;
    struct sched_param param;
    struct timespec deadline;
    char name[32];
    size_t stack_size;
    size_t guard_size;
    int detach_state;
    int policy;
    int old_ceiling;
    void *result = NULL;

    errno = EBUSY;
    CHECK(pthread_getconcurrency() == 0, "getconcurrency");
    CHECK(pthread_setconcurrency(0) == 0 && errno == EBUSY,
          "setconcurrency zero");
    CHECK(pthread_setconcurrency(1) == EAGAIN && errno == EBUSY,
          "setconcurrency positive");
    CHECK(pthread_setconcurrency(-1) == EINVAL && errno == EBUSY,
          "setconcurrency negative");

    CHECK(pthread_attr_init(&attr) == 0, "attr init");
    CHECK(pthread_getattr_default_np(&defaults) == 0, "get default attr");
    CHECK(pthread_attr_getstacksize(&defaults, &stack_size) == 0 && stack_size > 0,
          "default stack size");
    CHECK(pthread_attr_getguardsize(&defaults, &guard_size) == 0 && guard_size > 0,
          "default guard size");
    CHECK(pthread_attr_setstacksize(&attr, 2 * 1024 * 1024) == 0,
          "set default stack size");
    CHECK(pthread_attr_setguardsize(&attr, 8192) == 0,
          "set default guard size");
    CHECK(pthread_setattr_default_np(&attr) == 0, "set default attr");
    CHECK(pthread_getattr_default_np(&defaults) == 0, "get changed default attr");
    CHECK(pthread_attr_getstacksize(&defaults, &stack_size) == 0 &&
              stack_size >= 2 * 1024 * 1024,
          "changed default stack size");
    CHECK(pthread_attr_getguardsize(&defaults, &guard_size) == 0 && guard_size >= 8192,
          "changed default guard size");
    CHECK(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) == 0,
          "set non-size attr");
    CHECK(pthread_setattr_default_np(&attr) == EINVAL, "reject non-size default attr");
    pthread_attr_destroy(&attr);
    pthread_attr_destroy(&defaults);

    CHECK(pthread_create(&thread, NULL, worker, (void *)0x1234) == 0,
          "create worker");
    for (int i = 0; i < 100000 && !worker_name_ok; i++)
        sched_yield();
    CHECK(worker_name_ok, "worker self name");

    CHECK(pthread_setname_np(thread, "m4-target") == 0, "set target name");
    CHECK(pthread_getname_np(thread, name, sizeof name) == 0 &&
              strcmp(name, "m4-target") == 0,
          "get target name");
    CHECK(pthread_getname_np(thread, name, 15) == ERANGE, "name length error");

    CHECK(pthread_getattr_np(thread, &attr) == 0, "get thread attr");
    CHECK(pthread_attr_getstacksize(&attr, &stack_size) == 0 &&
              stack_size >= 2 * 1024 * 1024,
          "thread default stack size");
    CHECK(pthread_attr_getdetachstate(&attr, &detach_state) == 0 &&
              detach_state == PTHREAD_CREATE_JOINABLE,
          "thread detach state");

    memset(&param, 0, sizeof param);
    CHECK(pthread_getschedparam(thread, &policy, &param) == 0 &&
              policy == SCHED_OTHER && param.sched_priority == 0,
          "get thread scheduling");
    errno = EBUSY;
    {
        int result = pthread_setschedparam(thread, SCHED_OTHER, &param);
        CHECK((result == 0 || result == EPERM) && errno == EBUSY,
              "set thread scheduling");
    }
    errno = EBUSY;
    {
        int result = pthread_setschedprio(thread, 0);
        CHECK((result == 0 || result == EPERM) && errno == EBUSY,
              "set thread priority");
    }

    errno = EBUSY;
    CHECK(pthread_mutex_getprioceiling(NULL, &old_ceiling) == EINVAL && errno == EBUSY,
          "mutex get priority ceiling");
    CHECK(pthread_mutex_setprioceiling(NULL, 0, &old_ceiling) == EINVAL && errno == EBUSY,
          "mutex set priority ceiling");

    errno = EBUSY;
    CHECK(pthread_tryjoin_np(thread, &result) == EBUSY && errno == EBUSY,
          "tryjoin busy");
    release_worker = 1;
    CHECK(clock_gettime(CLOCK_REALTIME, &deadline) == 0, "clock gettime");
    deadline.tv_sec += 2;
    CHECK(pthread_timedjoin_np(thread, &result, &deadline) == 0 && result == (void *)0x1234,
          "timedjoin");

    errno = EBUSY;
    CHECK(pthread_getname_np((pthread_t)0, name, sizeof name) == ESRCH && errno == EBUSY,
          "invalid name target");
    CHECK(pthread_getattr_np((pthread_t)0, &attr) == ESRCH && errno == EBUSY,
          "invalid attr target");
    pthread_attr_destroy(&attr);
    puts("m4 pthread extensions ok");
    return 0;
}

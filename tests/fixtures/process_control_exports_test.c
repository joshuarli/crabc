#define _GNU_SOURCE 1

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

static int scheduling_case(void)
{
    struct sched_param param;
    int result;
    memset(&param, 0, sizeof param);

    CHECK(sched_getscheduler(0) == SCHED_OTHER, "sched_getscheduler");
    CHECK(sched_getparam(0, &param) == 0 && param.sched_priority == 0,
          "sched_getparam");
    errno = 0;
    result = sched_setparam(0, &param);
    CHECK(result == 0 || (result == -1 && errno == EPERM),
          "sched_setparam");
    errno = 0;
    result = sched_setscheduler(0, SCHED_OTHER, &param);
    CHECK(result == 0 || (result == -1 && errno == EPERM),
          "sched_setscheduler");

    errno = 0;
    CHECK(sched_getscheduler(99999999) == -1 && errno == ESRCH,
          "sched_getscheduler error");
    errno = 0;
    /* Linux validates the parameter pointer before attempting a user copy. */
    CHECK(sched_getparam(0, NULL) == -1 && errno == EINVAL,
          "sched_getparam error");
    return 0;
}

static int process_group_case(void)
{
    /* Signal 0 validates the group without delivering a signal. */
    CHECK(killpg(getpgrp(), 0) == 0, "killpg");
    errno = 0;
    CHECK(killpg(99999999, 0) == -1 && errno == ESRCH,
          "killpg error");
    return 0;
}

static int waitid_case(void)
{
    pid_t child;
    int status;
    siginfo_t info;

    child = fork();
    CHECK(child >= 0, "fork");
    if (child == 0)
        _exit(37);

    memset(&info, 0, sizeof info);
    CHECK(waitid(P_PID, (id_t)child, &info, WEXITED | WNOWAIT) == 0,
          "waitid");
    /* siginfo_t member offsets are verified as part of the ABI contract.
     * This runtime case proves the native waitid/ WNOWAIT state transition
     * directly: the child must remain available to the subsequent waitpid. */
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
              WEXITSTATUS(status) == 37,
          "waitid reap");

    errno = 0;
    CHECK(waitid(P_PID, (id_t)99999999, &info, WEXITED) == -1 &&
              errno == ECHILD,
          "waitid error");
    return 0;
}

static int thread_clock_case(void)
{
    pthread_t self = pthread_self();
    clockid_t clock;
    struct timespec now;
    int saved_errno;

    errno = EAGAIN;
    CHECK(pthread_getcpuclockid(self, &clock) == 0, "pthread_getcpuclockid");
    saved_errno = errno;
    CHECK(saved_errno == EAGAIN, "pthread direct error convention");
    CHECK(clock_gettime(clock, &now) == 0 && now.tv_sec >= 0 &&
              now.tv_nsec >= 0 && now.tv_nsec < 1000000000L,
          "thread cpu clock");

    errno = EBUSY;
    CHECK(pthread_getcpuclockid((pthread_t)0, &clock) == ESRCH,
          "pthread invalid thread");
    CHECK(errno == EBUSY, "pthread invalid direct error convention");
    return 0;
}

int main(void)
{
    CHECK(scheduling_case() == 0, "scheduling case");
    CHECK(process_group_case() == 0, "process group case");
    CHECK(waitid_case() == 0, "waitid case");
    CHECK(thread_clock_case() == 0, "thread clock case");
    puts("c-abi process control exports ok");
    return 0;
}

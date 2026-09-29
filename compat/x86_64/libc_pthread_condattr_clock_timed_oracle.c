/* Pinned-musl condition clock observation for the static clock-record slice.
 *
 * The selected static archive provides no pthread_cond_timedwait. This
 * reference-only consumer proves that a condition initialized from each
 * supported attribute clock interprets the same absolute deadline according
 * to that clock. It does not claim candidate timed-wait support.
 */
#if !defined(__linux__) || !defined(__x86_64__)
#error "this fixture requires native Linux/x86-64"
#endif

#include <errno.h>
#include <pthread.h>
#include <time.h>

static int report_phase(const char *message, unsigned long length)
{
    long result;

    __asm__ volatile("syscall" : "=a"(result)
        : "a"(1L), "D"(1L), "S"(message), "d"(length)
        : "rcx", "r11", "memory");
    return result == (long)length ? 0 : 1;
}

#define REPORT_PHASE(message) report_phase(message, sizeof(message) - 1)

static int run_clock(clockid_t clock)
{
    pthread_condattr_t attr;
    pthread_cond_t condition;
    pthread_mutex_t mutex;
    struct timespec before, deadline, after;
    long long elapsed_ns;
    int result;

    if (pthread_condattr_init(&attr) != 0 ||
        pthread_condattr_setclock(&attr, clock) != 0 ||
        pthread_cond_init(&condition, &attr) != 0 ||
        pthread_condattr_destroy(&attr) != 0 ||
        pthread_mutex_init(&mutex, 0) != 0 ||
        pthread_mutex_lock(&mutex) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &before) != 0)
        return 1;

    deadline = before;
    deadline.tv_nsec += 30000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        ++deadline.tv_sec;
        deadline.tv_nsec -= 1000000000L;
    }
    result = pthread_cond_timedwait(&condition, &mutex, &deadline);
    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0 ||
        pthread_mutex_unlock(&mutex) != 0 ||
        pthread_mutex_destroy(&mutex) != 0 ||
        pthread_cond_destroy(&condition) != 0 || result != ETIMEDOUT)
        return 2;

    elapsed_ns = (long long)(after.tv_sec - before.tv_sec) * 1000000000LL +
        after.tv_nsec - before.tv_nsec;
    if (clock == CLOCK_MONOTONIC && elapsed_ns < 20000000LL)
        return 3;
    if (clock == CLOCK_REALTIME && elapsed_ns > 1000000000LL)
        return 4;
    return 0;
}

int main(void)
{
    if (run_clock(CLOCK_REALTIME) != 0)
        return 1;
    if (REPORT_PHASE("musl-realtime-past-monotonic-deadline: pass\n"))
        return 2;
    if (run_clock(CLOCK_MONOTONIC) != 0)
        return 3;
    if (REPORT_PHASE("musl-monotonic-future-deadline: pass\n"))
        return 4;
    return 0;
}

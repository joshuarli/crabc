#define _GNU_SOURCE 1

#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>

/* The public sched.h in this tree has not yet grown the optional cpu_set_t
 * macros.  Keep this fixture's mask explicit: Linux's public CPU_SETSIZE is
 * 1024 bits (128 bytes) on the supported 64-bit targets. */
typedef struct {
    unsigned long bits[16];
} cabi_cpu_set_t;

extern int sched_getaffinity(pid_t, size_t, void *);
extern int sched_setaffinity(pid_t, size_t, const void *);
extern int sched_getcpu(void);
extern int __sched_cpucount(size_t, const void *);
extern int pthread_getaffinity_np(pthread_t, size_t, void *);
extern int pthread_setaffinity_np(pthread_t, size_t, const void *);
extern pthread_t pthread_self(void);

#define CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            puts(message); \
            return 1; \
        } \
    } while (0)

static void clear_mask(cabi_cpu_set_t *mask)
{
    size_t i;
    for (i = 0; i < sizeof(mask->bits) / sizeof(mask->bits[0]); i++)
        mask->bits[i] = 0;
}

int main(void)
{
    struct timespec interval;
    cabi_cpu_set_t mask;
    cabi_cpu_set_t known;
    pthread_t self;

    CHECK(sched_yield() == 0, "sched_yield");
    CHECK(sched_getcpu() >= 0, "sched_getcpu");

    CHECK(sched_get_priority_min(SCHED_OTHER) == 0 &&
              sched_get_priority_max(SCHED_OTHER) == 0,
          "other priority range");
    CHECK(sched_get_priority_min(SCHED_FIFO) == 1 &&
              sched_get_priority_max(SCHED_FIFO) == 99,
          "fifo priority range");
    CHECK(sched_get_priority_min(SCHED_RR) == 1 &&
              sched_get_priority_max(SCHED_RR) == 99,
          "rr priority range");
    errno = 0;
    CHECK(sched_get_priority_min(-1) == -1 && errno == EINVAL,
          "invalid priority policy");

    CHECK(sched_rr_get_interval(0, &interval) == 0 &&
              interval.tv_sec >= 0 && interval.tv_nsec >= 0 &&
              interval.tv_nsec < 1000000000L,
          "sched_rr_get_interval");

    clear_mask(&mask);
    CHECK(sched_getaffinity(0, sizeof(mask), &mask) == 0,
          "sched_getaffinity");
    CHECK(__sched_cpucount(sizeof(mask), &mask) > 0,
          "sched_getaffinity nonempty");
    CHECK(sched_setaffinity(0, sizeof(mask), &mask) == 0,
          "sched_setaffinity");
    errno = 0;
    CHECK(sched_getaffinity(0, 0, &mask) == -1 && errno == EINVAL,
          "sched_getaffinity invalid size");

    clear_mask(&known);
    known.bits[0] = 0x5UL;
    known.bits[3] = 0x8000000000000000UL;
    CHECK(__sched_cpucount(sizeof(known), &known) == 3,
          "__sched_cpucount");

    self = pthread_self();
    CHECK(self != 0, "pthread_self");
    CHECK(pthread_getaffinity_np(self, sizeof(mask), &mask) == 0,
          "pthread_getaffinity_np");
    CHECK(pthread_setaffinity_np(self, sizeof(mask), &mask) == 0,
          "pthread_setaffinity_np");
    errno = EAGAIN;
    CHECK(pthread_getaffinity_np(self, 0, &mask) == EINVAL && errno == EAGAIN,
          "pthread affinity error contract");

    puts("c-abi sched affinity exports ok");
    return 0;
}

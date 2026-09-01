/*
 * Pinned-musl Linux/x86-64 sched_rr_get_interval C ABI differential body.
 *
 * The shared fixture checks the directly useful C contract without a worker:
 * PID zero writes one canonical caller-owned timespec and preserves stale
 * errno; an impossible PID returns -1/ESRCH without corrupting caller storage.
 * The dedicated rr-interval-reference gate independently covers live-task
 * selection and raw-syscall agreement. This body selects no scheduler policy
 * mutation, parameter query, affinity, pthread lifecycle, or allocator.
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>

struct guarded_timespec {
    struct timespec value;
    unsigned char trailing[16];
};

typedef int (*sched_rr_get_interval_signature)(pid_t, struct timespec *);

_Static_assert(sizeof(pid_t) == 4 && _Alignof(pid_t) == 4,
    "x86 pid_t ABI");
_Static_assert(sizeof(struct timespec) == 16 && _Alignof(struct timespec) == 8,
    "x86 timespec ABI");
_Static_assert(__builtin_offsetof(struct timespec, tv_sec) == 0 &&
    __builtin_offsetof(struct timespec, tv_nsec) == 8,
    "x86 timespec member offsets");
_Static_assert(SYS_sched_rr_get_interval == 148,
    "Linux 5.10 x86 sched_rr_get_interval syscall number");
_Static_assert(__builtin_types_compatible_p(__typeof__(&sched_rr_get_interval),
    sched_rr_get_interval_signature), "sched_rr_get_interval declaration");

static void fill_bytes(unsigned char *bytes, unsigned long count)
{
    unsigned long index;

    for (index = 0; index < count; ++index)
        bytes[index] = 0xa5;
}

static int bytes_are_sentinel(const unsigned char *bytes, unsigned long count)
{
    unsigned long index;

    for (index = 0; index < count; ++index) {
        if (bytes[index] != 0xa5)
            return 0;
    }
    return 1;
}

static int trailing_is_unchanged(const struct guarded_timespec *value)
{
    return bytes_are_sentinel(value->trailing, sizeof(value->trailing));
}

static int record_is_unchanged(const struct guarded_timespec *value)
{
    return bytes_are_sentinel((const unsigned char *)value, sizeof(*value));
}

static int canonical_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 &&
        value->tv_nsec < 1000000000L;
}

static int check_current_task_interval(void)
{
    struct guarded_timespec self;

    fill_bytes((unsigned char *)&self, sizeof(self));
    errno = ERANGE;
    if (sched_rr_get_interval(0, &self.value) != 0)
        return 1;
    if (errno != ERANGE)
        return 2;
    if (!canonical_timespec(&self.value))
        return 3;
    return trailing_is_unchanged(&self) ? 0 : 4;
}

static int check_missing_task_interval(void)
{
    struct guarded_timespec missing;

    fill_bytes((unsigned char *)&missing, sizeof(missing));
    errno = ERANGE;
    if (sched_rr_get_interval(INT_MAX, &missing.value) != -1)
        return 1;
    if (errno != ESRCH)
        return 2;
    return record_is_unchanged(&missing) ? 0 : 3;
}

int crabc_x86_64_sched_rr_interval_probe(void)
{
    int status = check_current_task_interval();

    if (status != 0)
        return 10 + status;
    status = check_missing_task_interval();
    return status == 0 ? 0 : 20 + status;
}

#ifndef CRABC_SCHED_RR_INTERVAL_FREESTANDING
int main(void)
{
    return crabc_x86_64_sched_rr_interval_probe();
}
#endif

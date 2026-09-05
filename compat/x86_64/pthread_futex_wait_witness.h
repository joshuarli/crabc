/* Observe the named task inside FUTEX_WAIT before issuing cancellation.
 * The runner supplies a read-only /proc descriptor across the private chroot;
 * this requires neither a proc mount nor a timing assumption. No other task
 * can release the fixture's futex while the observer checks it. */
#include <fcntl.h>
#include <sys/syscall.h>
static void witness_pthread_futex_wait_at(int tid, unsigned long operation, unsigned long expected_address)
{
    const char *value = getenv("CRABC_TEST_PROC_FD");
    if (!value) _Exit(70);
    int proc_fd = atoi(value);
    char path[80], record[256];
    snprintf(path, sizeof path, "self/task/%d/syscall", tid);
    for (;;) {
        int fd = (int)syscall(SYS_openat, proc_fd, path, O_RDONLY | O_CLOEXEC, 0);
        if (fd < 0) _Exit(71);
        long count = syscall(SYS_read, fd, record, sizeof record - 1);
        syscall(SYS_close, fd);
        if (count > 0) {
            record[count] = 0;
            long number;
            unsigned long address, observed_operation;
            if (sscanf(record, "%ld %lx %lx", &number, &address, &observed_operation) == 3 &&
                number == SYS_futex && address && observed_operation == operation &&
                (!expected_address || address == expected_address)) return;
        }
        sched_yield();
    }
}

static void witness_pthread_futex_wait(int tid, unsigned long operation)
{
    witness_pthread_futex_wait_at(tid, operation, 0);
}

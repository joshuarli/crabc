#include <pthread.h>
#include <stdint.h>

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__)
#error "the x86 thread-pointer fixture requires Linux x86-64 LP64"
#endif

struct thread_snapshot {
    uintptr_t observed_first;
    uintptr_t observed_second;
    uintptr_t inline_first;
    uintptr_t inline_second;
};

static uintptr_t inline_fs0(void)
{
    uintptr_t value;

    __asm__ volatile ("movq %%fs:0, %0" : "=r"(value) : : "memory");
    return value;
}

#ifdef CRABC_THREAD_POINTER_ORACLE
static uintptr_t observed_thread_pointer(void)
{
    return inline_fs0();
}
#else
extern uintptr_t crabc_x86_64_thread_pointer_probe(void);

static uintptr_t observed_thread_pointer(void)
{
    return crabc_x86_64_thread_pointer_probe();
}
#endif

static void snapshot(struct thread_snapshot *snapshot)
{
    snapshot->observed_first = observed_thread_pointer();
    snapshot->inline_first = inline_fs0();
    snapshot->observed_second = observed_thread_pointer();
    snapshot->inline_second = inline_fs0();
}

static int snapshot_matches_inline_fs0(const struct thread_snapshot *snapshot)
{
    return snapshot->observed_first == snapshot->observed_second
        && snapshot->observed_first == snapshot->inline_first
        && snapshot->observed_first == snapshot->inline_second;
}

static void *worker(void *opaque)
{
    snapshot(opaque);
    return 0;
}

int main(void)
{
    pthread_t thread;
    struct thread_snapshot main_snapshot = {0};
    struct thread_snapshot worker_snapshot = {0};
    void *thread_return = (void *)(uintptr_t)1;

    snapshot(&main_snapshot);
    if (!snapshot_matches_inline_fs0(&main_snapshot))
        return 10;

    if (pthread_create(&thread, 0, worker, &worker_snapshot) != 0)
        return 11;
    if (pthread_join(thread, &thread_return) != 0 || thread_return != 0)
        return 12;

    if (!snapshot_matches_inline_fs0(&worker_snapshot))
        return 13;
    if (worker_snapshot.observed_first == main_snapshot.observed_first)
        return 14;

    return 0;
}

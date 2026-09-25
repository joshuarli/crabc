/*
 * Installed worker allocator lifecycle against pinned musl 1.2.6.
 *
 * The transcript is identical for every conforming libc. Built against an
 * installed native-shadow product with its scalar lifecycle audit
 * (CRABC_NATIVE_WORKER_AUDIT), the probe also checks the allocator owner:
 *
 *   - a worker's persistent owner is attached before its start routine runs,
 *     before any allocation, and starts no page engine until it allocates;
 *   - cleanup handlers and every TSD destructor iteration run while that
 *     owner is still attached, for return, pthread_exit and cancellation;
 *     after join the owner is gone and libc has released its TLS/control
 *     mappings, one reclaimed descriptor per joined worker;
 *   - a refused pthread_create leaves no owner, and creation then succeeds;
 *   - the final worker's ordinary-exit callbacks run on a fresh owner that
 *     has not allocated, never on the finished owner reopened;
 *   - `deferred` (run with the allocator's OS and arena allocation
 *     disallowed) starts a worker whose thread-local-data metadata cannot be
 *     allocated: as in pinned mimalloc's lazy `_mi_thread_init`, the worker
 *     runs without an owner, each of its allocations fails with ENOMEM, and
 *     as the final task its ordinary-exit callbacks run the same way.
 *
 * Allocation refusal with later valid use, and remote frees of live and
 * exited workers' blocks in every size class, run in both builds.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <malloc.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(c) do { if (!(c)) { dprintf(2, "worker lifecycle line %d errno %d\n", __LINE__, errno); _exit(1); } } while (0)

#ifdef CRABC_NATIVE_WORKER_AUDIT
struct owner_audit {
    size_t owner_installed, page_engine_active, attached_worker_owners, reclaimed_worker_descriptors;
};
int __crabc_x86_owned_allocator_worker_owner_test_audit(struct owner_audit *);
static struct owner_audit audit(void) {
    struct owner_audit value;
    CHECK(__crabc_x86_owned_allocator_worker_owner_test_audit(&value) == 0);
    return value;
}
/* The calling worker's owner is attached; `engine` is -1 when either is fine. */
static void require_owner(int engine) {
    struct owner_audit value = audit();
    CHECK(value.owner_installed == 1);
    if (engine >= 0) CHECK(value.page_engine_active == (size_t)engine);
}
static struct owner_audit baseline;
static void mark_baseline(void) { baseline = audit(); }
/* After joining `joined` workers since the baseline, none remains attached. */
static void require_joined(size_t joined) {
    struct owner_audit value = audit();
    CHECK(value.attached_worker_owners == baseline.attached_worker_owners);
    CHECK(value.reclaimed_worker_descriptors == baseline.reclaimed_worker_descriptors + joined);
}
#else
static void require_owner(int engine) { (void)engine; }
static void mark_baseline(void) {}
static void require_joined(size_t joined) { (void)joined; }
#endif

static unsigned char *filled(size_t size, unsigned char byte) {
    unsigned char *block = malloc(size);
    CHECK(block);
    memset(block, byte, size);
    return block;
}
static void release(unsigned char *block, size_t size, unsigned char byte) {
    for (size_t i = 0; i < size; i++) CHECK(block[i] == byte);
    free(block);
}
static void allocation_round(void) {
    unsigned char *block = filled(200, 0x11);
    block = realloc(block, 70000);
    CHECK(block && block[199] == 0x11);
    free(block);
}

/* Owner before user code, before and after the first allocation. */
static void *first_allocation(void *argument) {
    require_owner(0);
    allocation_round();
    require_owner(1);
    return argument;
}
static void *no_allocation(void *argument) { require_owner(0); return argument; }

/* Cleanup and TSD destructors precede native owner teardown. */
static pthread_key_t key;
static int destructor_calls, cleanup_calls;
static void destructor(void *value) {
    require_owner(-1);
    free(value);
    allocation_round();
    /* A second iteration: the owner is still attached then too. */
    if (++destructor_calls == 1) CHECK(pthread_setspecific(key, filled(900, 0x22)) == 0);
}
static void cleanup(void *value) {
    require_owner(-1);
    cleanup_calls++;
    free(value);
    allocation_round();
}
static void *exiting_worker(void *argument) {
    int mode = (int)(intptr_t)argument;
    CHECK(pthread_setspecific(key, filled(64, 0x33)) == 0);
    pthread_cleanup_push(cleanup, filled(128, 0x44));
    if (mode == 1) pthread_exit((void *)7);
    if (mode == 2) for (;;) { pthread_testcancel(); sched_yield(); }
    pthread_cleanup_pop(1);
    return (void *)7;
}
static void exit_modes(void) {
    static const char *const names[] = { "return", "pthread_exit", "cancel" };
    for (int mode = 0; mode < 3; mode++) {
        destructor_calls = cleanup_calls = 0;
        mark_baseline();
        pthread_t thread;
        void *result;
        CHECK(pthread_create(&thread, 0, exiting_worker, (void *)(intptr_t)mode) == 0);
        if (mode == 2) CHECK(pthread_cancel(thread) == 0);
        CHECK(pthread_join(thread, &result) == 0);
        CHECK(result == (mode == 2 ? PTHREAD_CANCELED : (void *)7));
        CHECK(destructor_calls == 2 && cleanup_calls == 1);
        require_joined(1);
        dprintf(1, "%s: cleanup %d destructors %d\n", names[mode], cleanup_calls, destructor_calls);
    }
}

/* Refusal with subsequent valid use in a worker. */
static void *refusal(void *argument) {
    (void)argument;
    errno = 0;
    CHECK(malloc(SIZE_MAX / 2) == 0 && errno == ENOMEM);
    unsigned char *block = filled(100, 0x55);
    errno = 0;
    CHECK(realloc(block, SIZE_MAX / 2) == 0 && errno == ENOMEM);
    volatile size_t count = SIZE_MAX / 8, width = 16;
    errno = 0;
    CHECK(calloc(count, width) == 0 && errno == ENOMEM);
    void *aligned = 0;
    CHECK(posix_memalign(&aligned, 3, 16) == EINVAL);
    CHECK(posix_memalign(&aligned, 64, SIZE_MAX / 2) == ENOMEM && aligned == 0);
    release(block, 100, 0x55);
    allocation_round();
    free(filled(1u << 20, 0x66));
    return 0;
}

/* Remote ownership: a live worker frees ours; we free exited workers'. */
struct transfer { size_t size; unsigned char *block; };
static void *allocate_for_main(void *argument) {
    struct transfer *transfer = argument;
    transfer->block = filled(transfer->size, 0x77);
    return 0;
}
static void *free_for_main(void *argument) {
    struct transfer *transfer = argument;
    release(transfer->block, transfer->size, 0x13);
    return 0;
}
static void remote_ownership(void) {
    mark_baseline();
    size_t joined = 0;
    for (size_t size = 48; size <= (4u << 20); size *= 7) {
        struct transfer exited = { size, 0 }, mine = { size, filled(size, 0x13) };
        pthread_t thread;
        CHECK(pthread_create(&thread, 0, allocate_for_main, &exited) == 0);
        CHECK(pthread_join(thread, 0) == 0);
        CHECK(pthread_create(&thread, 0, free_for_main, &mine) == 0);
        CHECK(pthread_join(thread, 0) == 0);
        release(exited.block, size, 0x77);
        joined += 2;
    }
    require_joined(joined);
    dprintf(1, "remote ownership: %zu workers\n", joined);
}

/* A refused creation leaves no owner; the next one attaches normally. */
static void *hold_block(void *argument) { return filled((size_t)(intptr_t)argument, 0x21); }
static void creation_refusal(void) {
    mark_baseline();
    struct rlimit saved, low;
    CHECK(getrlimit(RLIMIT_AS, &saved) == 0);
    low = saved;
    low.rlim_cur = 96u << 20;
    pthread_attr_t attributes;
    CHECK(pthread_attr_init(&attributes) == 0);
    CHECK(pthread_attr_setstacksize(&attributes, 16u << 20) == 0);
    pthread_t threads[64];
    int created = 0, refused = 0;
    CHECK(setrlimit(RLIMIT_AS, &low) == 0);
    for (int i = 0; i < 64; i++) {
        int error = pthread_create(&threads[created], &attributes, hold_block, (void *)(intptr_t)100);
        if (error == 0) created++; else { CHECK(error == EAGAIN); refused++; }
    }
    CHECK(setrlimit(RLIMIT_AS, &saved) == 0);
    CHECK(pthread_attr_destroy(&attributes) == 0);
    CHECK(refused > 0);
    for (int i = 0; i < created; i++) {
        void *block;
        CHECK(pthread_join(threads[i], &block) == 0);
        release(block, 100, 0x21);
    }
    pthread_t thread;
    void *result;
    CHECK(pthread_create(&thread, 0, first_allocation, (void *)9) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)9);
    require_joined((size_t)created + 1);
    dprintf(1, "creation refusal: EAGAIN then success\n");
}

/* The final worker's ordinary exit runs callbacks on a fresh owner. */
static void final_callback(void) {
    require_owner(0);
    allocation_round();
    require_owner(1);
    dprintf(1, "final worker atexit\n");
}
static void wait_for_initial_task_exit(void) {
    char path[64], state[512];
    snprintf(path, sizeof path, "/proc/self/task/%d/stat", (int)getpid());
    for (;;) {
        int fd = open(path, O_RDONLY);
        if (fd < 0) return;
        ssize_t length = read(fd, state, sizeof state - 1);
        close(fd);
        CHECK(length > 0);
        state[length] = 0;
        char *end = strrchr(state, ')');
        CHECK(end && end[1] == ' ');
        if (end[2] == 'Z') return;
        sched_yield();
    }
}
static void *final_worker(void *argument) {
    (void)argument;
    wait_for_initial_task_exit();
    allocation_round();
    require_owner(1);
    return 0;
}

/* A worker whose attachment was deferred: every allocation fails. */
static void require_deferred_allocation_failure(void) {
    errno = 0;
    void *block = malloc(64);
#ifdef CRABC_NATIVE_WORKER_AUDIT
    CHECK(block == NULL && errno == ENOMEM);
    CHECK(audit().owner_installed == 0);
#endif
    free(block);
}
static void deferred_callback(void) {
    require_deferred_allocation_failure();
    dprintf(1, "deferred final worker atexit\n");
}
static void *deferred_worker(void *argument) {
    (void)argument;
    wait_for_initial_task_exit();
    require_deferred_allocation_failure();
    return 0;
}

int main(int argc, char **argv) {
    CHECK(argc == 2);
    CHECK(pthread_key_create(&key, destructor) == 0);
    pthread_t thread;
    void *result;
    if (!strcmp(argv[1], "deferred")) {
        CHECK(atexit(deferred_callback) == 0);
        CHECK(pthread_create(&thread, 0, deferred_worker, 0) == 0);
        pthread_exit(0);
    }
    mark_baseline();
    CHECK(pthread_create(&thread, 0, no_allocation, (void *)3) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)3);
    CHECK(pthread_create(&thread, 0, first_allocation, (void *)4) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)4);
    require_joined(2);
    dprintf(1, "attach before user code\n");
    exit_modes();
    CHECK(pthread_create(&thread, 0, refusal, 0) == 0);
    CHECK(pthread_join(thread, 0) == 0);
    dprintf(1, "allocation refusal then valid use\n");
    remote_ownership();
    creation_refusal();
    if (!strcmp(argv[1], "final")) {
        CHECK(atexit(final_callback) == 0);
        CHECK(pthread_create(&thread, 0, final_worker, 0) == 0);
        pthread_exit(0);
    }
    CHECK(!strcmp(argv[1], "main"));
    return 0;
}

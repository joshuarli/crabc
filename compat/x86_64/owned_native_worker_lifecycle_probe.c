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
 *   - all four TSD destructor passes retain their owner; worker-born and
 *     last-pass clients remain live until the joining thread frees them;
 *   - pthread and C11 workers hand loader diagnostics back on normal return
 *     and explicit exit, so the next loader error releases those buffers;
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
#include <dlfcn.h>
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
#include <threads.h>
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
struct page_class_audit {
    size_t registered_slices, small_empty_slices, small_used_slices;
    size_t medium_empty_slices, medium_used_slices;
    size_t large_empty_slices, large_used_slices;
    size_t singleton_empty_slices, singleton_used_slices, unknown_kind_slices;
    size_t abandoned_slices, detached_slices, attached_slices, nonprimary_slices;
    size_t medium_abandoned_slices, medium_detached_slices, medium_attached_slices;
    size_t medium_remote_pending_slices, medium_reusable_slices, medium_retired_slices;
};
int __crabc_x86_owned_allocator_page_class_test_audit(struct page_class_audit *);
/* Joined workers and the main task are quiescent during this snapshot. */
static size_t live_small_pages(void) {
    struct page_class_audit value;
    CHECK(__crabc_x86_owned_allocator_page_class_test_audit(&value) == 0);
    return value.small_used_slices;
}
#else
static void require_owner(int engine) { (void)engine; }
static void mark_baseline(void) {}
static void require_joined(size_t joined) { (void)joined; }
#endif

/* Each loader error replaces the main task's diagnostic and drains buffers
 * handed back by exited threads. Consuming dlerror keeps its buffer alive
 * until that replacement or thread exit. */
static void loader_error(void) {
    CHECK(dlopen("/proc/self/fd/-1", RTLD_NOW) == 0);
    char *message = dlerror();
    CHECK(message && message[0]);
    CHECK(dlerror() == 0);
}
static void *loader_error_worker(void *argument) {
    loader_error();
    if (argument) pthread_exit(argument);
    return argument;
}
static int loader_error_c11_worker(void *argument) {
    loader_error();
    if (argument) thrd_exit(7);
    return 7;
}
static void loader_error_retirement(void) {
    pthread_t thread;
    void *result;
    /* Warm the same owner, diagnostic and reclamation operations through
     * explicit exit before comparing the normal return path. */
    loader_error();
    CHECK(pthread_create(&thread, 0, loader_error_worker, (void *)1) == 0);
    CHECK(pthread_join(thread, &result) == 0 && result == (void *)1);
    loader_error();
#ifdef CRABC_NATIVE_WORKER_AUDIT
    size_t before = live_small_pages();
#endif
    for (int mode = 0; mode < 2; mode++) {
        CHECK(pthread_create(&thread, 0, loader_error_worker, (void *)(intptr_t)mode) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == (void *)(intptr_t)mode);
        loader_error();
#ifdef CRABC_NATIVE_WORKER_AUDIT
        size_t after = live_small_pages();
        if (after != before)
            dprintf(2, "loader diagnostic pages before %zu after %zu mode %d\n", before, after, mode);
        CHECK(after == before);
#endif
    }
    for (int mode = 0; mode < 2; mode++) {
        thrd_t c11_thread;
        int c11_result;
        CHECK(thrd_create(&c11_thread, loader_error_c11_worker, (void *)(intptr_t)mode) == thrd_success);
        CHECK(thrd_join(c11_thread, &c11_result) == thrd_success && c11_result == 7);
        loader_error();
#ifdef CRABC_NATIVE_WORKER_AUDIT
        CHECK(live_small_pages() == before);
#endif
    }
    dprintf(1, "loader diagnostic retirement\n");
}

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

/* Deferred requests remain pending while DISABLE owns resources. ENABLE
 * returns before the explicit cancellation point; exit then runs nested LIFO
 * cleanup and TSD while the worker's allocator and descriptor are still live. */
struct cancel_state_round {
    volatile int ready, release_request;
    unsigned after_enable, order_count, order[5];
    int descriptor;
    unsigned char *inner_client, *outer_client, *tsd_client;
};
static pthread_key_t cancel_state_key;

static void cancel_state_record(struct cancel_state_round *round, unsigned event) {
    CHECK(round->order_count < 5);
    round->order[round->order_count++] = event;
}
static void cancel_state_require_disabled(void) {
    int previous = -1;
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    CHECK(previous == PTHREAD_CANCEL_DISABLE);
    pthread_testcancel();
    require_owner(1);
}
static void cancel_state_nested(void *opaque) {
    struct cancel_state_round *round = opaque;
    cancel_state_require_disabled();
    cancel_state_record(round, 2);
    allocation_round();
}
static void cancel_state_inner(void *opaque) {
    struct cancel_state_round *round = opaque;
    cancel_state_require_disabled();
    cancel_state_record(round, 1);
    release(round->inner_client, 128, 0x29);
    round->inner_client = NULL;
    pthread_cleanup_push(cancel_state_nested, round);
    allocation_round();
    pthread_cleanup_pop(1);
    cancel_state_record(round, 3);
}
static void cancel_state_outer(void *opaque) {
    struct cancel_state_round *round = opaque;
    cancel_state_require_disabled();
    cancel_state_record(round, 4);
    CHECK(close(round->descriptor) == 0);
    release(round->outer_client, 64, 0x44);
    round->outer_client = NULL;
    allocation_round();
}
static void cancel_state_tsd(void *opaque) {
    struct cancel_state_round *round = opaque;
    cancel_state_require_disabled();
    CHECK(pthread_getspecific(cancel_state_key) == NULL);
    cancel_state_record(round, 5);
    release(round->tsd_client, 96, 0x53);
    round->tsd_client = NULL;
    allocation_round();
}
static void *cancel_state_worker(void *opaque) {
    struct cancel_state_round *round = opaque;
    int previous;
    require_owner(0);
    CHECK(pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &previous) == 0);
    CHECK(previous == PTHREAD_CANCEL_DEFERRED);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous) == 0);
    CHECK(previous == PTHREAD_CANCEL_ENABLE);
    round->inner_client = filled(128, 0x29);
    round->outer_client = filled(64, 0x44);
    round->tsd_client = filled(96, 0x53);
    CHECK(pthread_setspecific(cancel_state_key, round) == 0);
    pthread_cleanup_push(cancel_state_outer, round);
    pthread_cleanup_push(cancel_state_inner, round);
    __atomic_store_n(&round->ready, 1, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&round->release_request, __ATOMIC_ACQUIRE)) sched_yield();
    pthread_testcancel();
    unsigned char byte;
    CHECK(read(round->descriptor, &byte, 1) == 1 && byte == 0x57);
    CHECK(round->order_count == 0);
    CHECK(pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &previous) == 0);
    CHECK(previous == PTHREAD_CANCEL_DISABLE);
    round->after_enable = 1;
    pthread_testcancel();
    CHECK(0);
    pthread_cleanup_pop(0);
    pthread_cleanup_pop(0);
    return NULL;
}
static void cancellation_state_resources(void) {
    int descriptors[2];
    CHECK(pipe(descriptors) == 0);
    unsigned char byte = 0x57;
    CHECK(write(descriptors[1], &byte, 1) == 1);
    struct cancel_state_round round = { .descriptor = descriptors[0] };
    CHECK(pthread_key_create(&cancel_state_key, cancel_state_tsd) == 0);
    mark_baseline();
    pthread_t thread;
    void *result;
    CHECK(pthread_create(&thread, NULL, cancel_state_worker, &round) == 0);
    while (!__atomic_load_n(&round.ready, __ATOMIC_ACQUIRE)) sched_yield();
    CHECK(pthread_cancel(thread) == 0 && pthread_cancel(thread) == 0);
    __atomic_store_n(&round.release_request, 1, __ATOMIC_RELEASE);
    CHECK(pthread_join(thread, &result) == 0 && result == PTHREAD_CANCELED);
    CHECK(round.after_enable == 1 && round.order_count == 5);
    for (unsigned index = 0; index != 5; ++index) CHECK(round.order[index] == index + 1);
    CHECK(!round.inner_client && !round.outer_client && !round.tsd_client);
    errno = 0;
    CHECK(fcntl(descriptors[0], F_GETFD) == -1 && errno == EBADF);
    CHECK(close(descriptors[1]) == 0);
    CHECK(pthread_key_delete(cancel_state_key) == 0);
    require_joined(1);
    dprintf(1, "cancel state: disabled read, enable testcancel, nested cleanup, fd and allocation retirement\n");
}

/* Four TSD passes leave both worker-born clients live until join. */
struct four_pass_round {
    unsigned int calls, cleanup_calls;
    int explicit_exit;
    unsigned char *start_client, *last_client;
};
static pthread_key_t four_pass_key;
static void four_pass_cleanup(void *opaque) {
    struct four_pass_round *round = opaque;
    require_owner(1);
    CHECK(round->calls == 0);
    release(filled(73, 0x29), 73, 0x29);
    ++round->cleanup_calls;
}
static void four_pass_destructor(void *opaque);
static void four_pass_replacement_destructor(void *opaque);

static void four_pass_step(void *opaque) {
    struct four_pass_round *round = opaque;
    require_owner(1);
    CHECK(++round->calls <= 4);
    CHECK(pthread_getspecific(four_pass_key) == NULL);
    CHECK(!round->explicit_exit || round->cleanup_calls == 1);
    unsigned char byte = (unsigned char)(0x40 + round->calls);
    unsigned char *block = filled(97, byte);
    block = realloc(block, 241);
    CHECK(block);
    for (size_t index = 0; index < 97; ++index) CHECK(block[index] == byte);
    memset(block, byte, 241);
    if (round->calls < 4) {
        release(block, 241, byte);
        /* Deletion does not own the cleared callback value. Replacing the
         * key from its own callback must dispatch the newly selected
         * destructor on the next pass, while this worker can still allocate. */
        pthread_key_t previous = four_pass_key;
        pthread_key_t replacement;
        CHECK(pthread_key_delete(previous) == 0);
        CHECK(pthread_key_create(&replacement, round->calls & 1
            ? four_pass_replacement_destructor : four_pass_destructor) == 0);
        CHECK(replacement == previous);
        four_pass_key = replacement;
        CHECK(pthread_getspecific(four_pass_key) == NULL);
        CHECK(pthread_setspecific(four_pass_key, round) == 0);
    } else {
        round->last_client = block;
    }
}
static void four_pass_destructor(void *opaque) {
    struct four_pass_round *round = opaque;
    CHECK((round->calls & 1) == 0);
    four_pass_step(opaque);
}
static void four_pass_replacement_destructor(void *opaque) {
    struct four_pass_round *round = opaque;
    CHECK((round->calls & 1) == 1);
    four_pass_step(opaque);
}
static void *four_pass_worker(void *opaque) {
    struct four_pass_round *round = opaque;
    require_owner(0);
    round->start_client = filled(113, 0x71);
    require_owner(1);
    CHECK(pthread_setspecific(four_pass_key, round) == 0);
    pthread_cleanup_push(four_pass_cleanup, round);
    if (round->explicit_exit) pthread_exit(round);
    pthread_cleanup_pop(0);
    return round;
}
static void four_tsd_passes(void) {
    CHECK(pthread_key_create(&four_pass_key, four_pass_destructor) == 0);
    for (int mode = 0; mode < 2; ++mode) {
        /* The prior round ends on the replacement callback. Reset the next
         * ordinary worker to the original callback with an empty key slot. */
        if (mode != 0) {
            CHECK(pthread_key_delete(four_pass_key) == 0);
            CHECK(pthread_key_create(&four_pass_key, four_pass_destructor) == 0);
        }
        struct four_pass_round round = { .explicit_exit = mode };
        pthread_t thread;
        void *result;
        mark_baseline();
        CHECK(pthread_create(&thread, NULL, four_pass_worker, &round) == 0);
        CHECK(pthread_join(thread, &result) == 0 && result == &round);
        CHECK(round.calls == 4 && round.cleanup_calls == (unsigned int)mode);
        CHECK(round.start_client && round.last_client);
        require_joined(1);
        release(round.start_client, 113, 0x71);
        release(round.last_client, 241, 0x44);
    }
    CHECK(pthread_key_delete(four_pass_key) == 0);
    dprintf(1, "TSD four passes: callback key replacement, return and pthread_exit joined clients\n");
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
/* Joining the initial thread returns only once it has left the process's
 * thread list, as musl's pthread_join waits for its exit; this worker is then
 * the final task. It needs no /proc, which the dynamic modes' chroot lacks. */
static pthread_t initial_thread;
static void wait_for_initial_task_exit(void) {
    void *result = &initial_thread;
    CHECK(pthread_join(initial_thread, &result) == 0 && result == 0);
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
    if (!strcmp(argv[1], "cancel-state")) {
        cancellation_state_resources();
        return 0;
    }
    if (!strcmp(argv[1], "tsd-four")) {
        four_tsd_passes();
        return 0;
    }
    CHECK(pthread_key_create(&key, destructor) == 0);
    pthread_t thread;
    void *result;
    if (!strcmp(argv[1], "deferred")) {
        CHECK(atexit(deferred_callback) == 0);
        initial_thread = pthread_self();
        CHECK(pthread_create(&thread, 0, deferred_worker, 0) == 0);
        pthread_exit(0);
    }
    loader_error_retirement();
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
        initial_thread = pthread_self();
        CHECK(pthread_create(&thread, 0, final_worker, 0) == 0);
        pthread_exit(0);
    }
    CHECK(!strcmp(argv[1], "main"));
    return 0;
}

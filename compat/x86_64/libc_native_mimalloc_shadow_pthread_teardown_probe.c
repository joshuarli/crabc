/* Selected static x86 native-mimalloc pthread teardown fixture.
 *
 * The pinned-musl arm establishes the ordinary C/POSIX worker observations.
 * The native-shadow arm is a real `-nostdlib -static` owned-runtime process:
 * its entry first proves that a worker created before `__libc_start_main`
 * receives EAGAIN without invoking user code, then starts libc normally.
 * Normal return, pthread_exit, and deferred pthread cancellation each make a
 * user TSD destructor allocate and free before the selected native owner is
 * finished. A distinct normal-return round makes no public allocation from
 * its user start routine: its TSD destructor observes a rejected first
 * request and then makes the worker's first successful public allocation.
 * A separate ordinary worker retains a live small client across a rejected
 * `realloc` failure, frees that original client, and then reaches the
 * same post-user-TSD allocation and native teardown boundary.
 * A final worker also reaches ordinary `atexit` only after the
 * bootstrapped thread called `pthread_exit`; before logical process done its
 * completed owner is reinitialized, while after logical process done the
 * final-task decision preserves its same active source owner for callbacks.
 * That callback allocates and frees in the selected post-done case. It
 * does not qualify main-thread or process shutdown, dynamic loader ownership,
 * cross-worker pointer transfer, allocator promotion, or public x86 support.
 */

#if !defined(__linux__) || !defined(__x86_64__) || !defined(__LP64__) || \
    !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
    __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "this fixture requires native Linux/x86-64 little-endian LP64"
#endif

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#define CRABC_TYPE_IS(actual, expected) \
    __builtin_types_compatible_p(actual, expected)

enum {
    CRABC_WAIT_LIMIT = 100000000u,
    CRABC_NORMAL_MARKER = 0x13579bdfu,
    CRABC_EXPLICIT_MARKER = 0x2468ace0u,
    CRABC_TSD_FIRST_MARKER = 0x10293847u,
    CRABC_REALLOC_FAILURE_MARKER = 0x31415926u,
    CRABC_PROCESS_DONE_CLIENT_COUNT = 2u,
};

_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_create),
    int (*)(pthread_t *__restrict, const pthread_attr_t *__restrict,
        void *(*)(void *), void *__restrict)), "pthread_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_join),
    int (*)(pthread_t, void **)), "pthread_join declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_cancel),
    int (*)(pthread_t)), "pthread_cancel declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_testcancel),
    void (*)(void)), "pthread_testcancel declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&pthread_key_create),
    int (*)(pthread_key_t *, void (*)(void *))), "pthread_key_create declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&malloc), void *(*)(size_t)),
    "malloc declaration");
_Static_assert(CRABC_TYPE_IS(__typeof__(&free), void (*)(void *)),
    "free declaration");
_Static_assert(PTHREAD_CANCELED == (void *)-1,
    "pthread cancellation result spelling");

struct teardown_round {
    volatile int ready;
    volatile int tsd_finished;
    volatile int failure;
    /* The first-public-allocation round sets these before its worker returns.
     * They distinguish the source-order receipt from an unsupported claim
     * that pthread attachment itself performs no internal allocation. */
    volatile int first_public_allocation_from_tsd;
    volatile int user_start_returned;
    volatile int rejected_first_request;
    /* The ordinary realloc-failure round proves that a rejected replacement
     * leaves its exact current-worker client usable before user TSD teardown. */
    volatile int realloc_failure_preserved;
    uintptr_t marker;
};

static pthread_key_t teardown_key;
static volatile int prestart_callback_count;
static void *final_worker_pre_teardown_allocation;

/* These are normal parent/child completion witnesses for the three raw
 * process-copy entries. The fixture's child code takes no allocator, loader,
 * stdio, or user callback path after libc has completed its copied-current-descriptor
 * admission: `fork` and `_Fork` immediately `_Exit`, while non-CLONE_VM
 * `clone` returns one fixed status. They therefore exercise only the interim
 * raw-copy guard, not generic vanished-owner repair in a copied process. */
enum {
    CRABC_RAW_COPY_FORK_STATUS = 61,
    CRABC_RAW_COPY_UNDERSCORE_FORK_STATUS = 62,
    CRABC_RAW_COPY_CLONE_STATUS = 63,
    CRABC_RAW_COPY_CLONE_STACK_SIZE = 64 * 1024,
};

static unsigned char raw_copy_clone_stack[CRABC_RAW_COPY_CLONE_STACK_SIZE];

static int raw_copy_clone_child(void *opaque)
{
    (void)opaque;
    return CRABC_RAW_COPY_CLONE_STATUS;
}

static int wait_for_raw_copy_child(pid_t child, int expected_status)
{
    int status;

    if (child < 0)
        return -1;
    if (waitpid(child, &status, 0) != child)
        return -1;
    return WIFEXITED(status) && WEXITSTATUS(status) == expected_status ? 0 : -1;
}

static int run_raw_copy_completion_paths(void)
{
    pid_t child;

    child = fork();
    if (child == 0)
        _Exit(CRABC_RAW_COPY_FORK_STATUS);
    if (wait_for_raw_copy_child(child, CRABC_RAW_COPY_FORK_STATUS) != 0)
        return 1;

    child = _Fork();
    if (child == 0)
        _Exit(CRABC_RAW_COPY_UNDERSCORE_FORK_STATUS);
    if (wait_for_raw_copy_child(child, CRABC_RAW_COPY_UNDERSCORE_FORK_STATUS) != 0)
        return 2;

    child = clone(raw_copy_clone_child,
        raw_copy_clone_stack + CRABC_RAW_COPY_CLONE_STACK_SIZE, SIGCHLD, 0);
    return wait_for_raw_copy_child(child, CRABC_RAW_COPY_CLONE_STATUS) == 0 ? 0 : 3;
}

/* This candidate-only round mirrors the pinned process-done source probe.
 * A private test seam transitions the selected process into the source's
 * post-`mi_process_done` shape while the initial task remains alive. The
 * producer retains two ordinary medium clients from one nonfull page. Its
 * consumer first creates a distinct current owner, then frees that former
 * page under a recycled raw TP scalar. This is separate from the pinned-C
 * full-page observation, where ordinary `allow_page_abandon` transitions the
 * exhausted page to unmapped abandonment before process-done retention.
 * Neither result permits a Rust-only generation rejection. */
enum process_done_allocation_kind {
    PROCESS_DONE_ALLOCATION_NORMAL,
    PROCESS_DONE_ALLOCATION_ALIGNED_FAST,
    PROCESS_DONE_ALLOCATION_ALIGNED_INTERIOR,
};

struct process_done_client_page {
    void *clients[CRABC_PROCESS_DONE_CLIENT_COUNT];
    size_t client_count;
    enum process_done_allocation_kind allocation_kind;
};

struct process_done_round {
    const struct process_done_client_page *previous;
    struct process_done_client_page current;
    int retain_current;
    volatile int failure;
};

/* The runner writes only after `/proc` reports the bootstrapped task as a
 * zombie. Releasing a worker from an application flag before `pthread_exit`
 * has withdrawn the initial task would race the final-task decision. This
 * private test pipe adopts the existing last-thread evidence convention; it
 * does not select a public task-ID API or a dynamic runtime path. */
static volatile int final_worker_ready;

#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
extern size_t __crabc_x86_native_mimalloc_active_later_thread_count_test_audit(void);
extern size_t __crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit(void);
extern size_t __crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit(void);
extern int __crabc_x86_native_mimalloc_process_done_retained_worker_matches_current_thread_test_audit(void);
extern int __crabc_x86_native_mimalloc_process_done_retained_local_preflight_test_audit(void *block);
struct process_done_local_page_audit {
    size_t in_full;
    size_t has_interior_pointers;
    size_t used;
    size_t capacity;
    size_t reserved;
    size_t regular_queue_count;
    size_t full_queue_count;
    size_t theap_page_count;
    size_t member_link_coherent;
};
extern int __crabc_x86_native_mimalloc_current_local_page_test_audit(
    void *block, struct process_done_local_page_audit *output);
extern int __crabc_x86_native_mimalloc_current_local_page_same_test_audit(
    void *first, void *second);
extern int __crabc_x86_native_mimalloc_process_done_retained_local_page_test_audit(
    void *block, struct process_done_local_page_audit *output);
extern int __crabc_x86_native_mimalloc_process_done_retained_page_retired_test_audit(
    void *former_client, size_t expected_reserved);
extern int __crabc_x86_native_mimalloc_process_done_test_audit(void);
extern int __crabc_x86_native_mimalloc_process_destroy_test_audit(void);
extern int __crabc_x86_native_mimalloc_process_done_retained_page_test_audit(
    void *first, void *second, int remote_free_published);
#endif

#ifdef CRABC_NATIVE_INTERNAL_MALLOC_OVERRIDE
/* The replacement is intentionally strong. The candidate calls
 * pthread_atfork below, whose node allocation must remain on libc's direct
 * native internal seam and must therefore neither call this spelling nor
 * return its null refusal to the atfork registration. */
static volatile unsigned int replacement_malloc_calls;

void *malloc(size_t size)
{
    (void)size;
    __atomic_fetch_add(&replacement_malloc_calls, 1, __ATOMIC_RELEASE);
    return 0;
}
#endif

static void spin_pause(void)
{
    __asm__ volatile("pause" ::: "memory");
}

static int wait_for_nonzero(const volatile int *value)
{
    unsigned int spin;

    for (spin = 0; spin != CRABC_WAIT_LIMIT; ++spin) {
        if (__atomic_load_n(value, __ATOMIC_ACQUIRE) != 0)
            return 0;
        spin_pause();
    }
    return -1;
}

static void record_failure(struct teardown_round *round, int value)
{
    __atomic_store_n(&round->failure, value, __ATOMIC_RELEASE);
}

/* This runs while libc still owns the attached worker's native TLS owner.
 * If the native finish moved before selected TSD destructors, its allocation
 * would fail (or fail-stop) and the candidate process could not pass. */
static void native_allocation_tsd_destructor(void *opaque)
{
    struct teardown_round *round = opaque;
    void *allocation;

    if (pthread_getspecific(teardown_key) != 0) {
        record_failure(round, 101);
        return;
    }
    /* This selected-native round performs no public allocation in its user
     * start routine. Its TSD callback therefore supplies its first public
     * allocator attempt. The impossible request must be rejected at the C
     * boundary without preventing the following first successful selected
     * native allocation. This observes neither a generic `mi_tld_create`
     * matrix nor whether pthread attachment used unrelated internal storage. */
    if (__atomic_load_n(&round->first_public_allocation_from_tsd,
            __ATOMIC_ACQUIRE) != 0) {
        if (__atomic_load_n(&round->user_start_returned,
                __ATOMIC_ACQUIRE) != 1) {
            record_failure(round, 103);
            return;
        }
        errno = 0;
        if (malloc(SIZE_MAX) != 0 || errno != ENOMEM) {
            record_failure(round, 104);
            return;
        }
        __atomic_store_n(&round->rejected_first_request, 1,
            __ATOMIC_RELEASE);
    }
    allocation = malloc(97);
    if (allocation == 0) {
        record_failure(round, 102);
        return;
    }
    ((volatile unsigned char *)allocation)[0] = 0x5a;
    free(allocation);
    __atomic_store_n(&round->tsd_finished, 1, __ATOMIC_RELEASE);
}

/* Installing a user TSD value changes only the selected pthread value table;
 * it intentionally contains no public allocation call. */
static int install_worker_teardown_tsd(struct teardown_round *round)
{
    return pthread_setspecific(teardown_key, round) == 0 ? 0 : 1;
}

static int prepare_worker_teardown(struct teardown_round *round)
{
    void *allocation = malloc(10241);

    if (allocation == 0)
        return 1;
    ((volatile unsigned char *)allocation)[0] = 0xa5;
    free(allocation);
    return install_worker_teardown_tsd(round) == 0 ? 0 : 2;
}

/* This private scalar cannot reveal a descriptor address or source owner. It
 * proves the real worker's allocator-TLS record was published before the
 * callback and stays registered through normal return, pthread_exit, and
 * deferred cancellation until clear-child-tid plus pthread_join reclaim it. */
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
static int native_worker_descriptor_is_registered(void)
{
    return __crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit() == 2;
}
#endif

static void *normal_return_worker(void *opaque)
{
    struct teardown_round *round = opaque;

    if (prepare_worker_teardown(round) != 0
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
            || !native_worker_descriptor_is_registered()
#endif
    ) {
        record_failure(round, 1);
        return 0;
    }
    return (void *)round->marker;
}

static void *explicit_exit_worker(void *opaque)
{
    struct teardown_round *round = opaque;

    if (prepare_worker_teardown(round) != 0
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
            || !native_worker_descriptor_is_registered()
#endif
    ) {
        record_failure(round, 2);
        return 0;
    }
    pthread_exit((void *)round->marker);
}

/* The native attachment already exists before this user routine, but this
 * routine intentionally makes no public allocation call. Its TSD callback
 * therefore owns the first public allocation attempt and first successful
 * selected-native allocation for this worker. */
static void *first_public_allocation_in_tsd_worker(void *opaque)
{
    struct teardown_round *round = opaque;

    if (install_worker_teardown_tsd(round) != 0) {
        record_failure(round, 4);
        return 0;
    }
    __atomic_store_n(&round->user_start_returned, 1, __ATOMIC_RELEASE);
    return (void *)round->marker;
}

/* Pinned `src/alloc.c:361-404` only consumes `p` after a successful
 * replacement. Keep this a current-worker ordinary non-direct-small client:
 * it does not probe foreign/post-exit reallocation or an implementation-
 * specific OOM path. */
static void *realloc_failure_preserving_worker(void *opaque)
{
    struct teardown_round *round = opaque;
    volatile unsigned char *allocation = malloc(1025);

    if (allocation == 0) {
        record_failure(round, 5);
        return 0;
    }
    allocation[0] = 0x4d;
    allocation[1024] = 0xb2;
    errno = 0;
    if (realloc((void *)allocation, SIZE_MAX) != 0 || errno != ENOMEM) {
        record_failure(round, 6);
        return 0;
    }
    if (allocation[0] != 0x4d || allocation[1024] != 0xb2) {
        record_failure(round, 7);
        return 0;
    }
    free((void *)allocation);
    __atomic_store_n(&round->realloc_failure_preserved, 1, __ATOMIC_RELEASE);
    if (install_worker_teardown_tsd(round) != 0) {
        record_failure(round, 8);
        return 0;
    }
    return (void *)round->marker;
}

static void *deferred_cancel_worker(void *opaque)
{
    struct teardown_round *round = opaque;

    if (prepare_worker_teardown(round) != 0
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
            || !native_worker_descriptor_is_registered()
#endif
    ) {
        record_failure(round, 3);
        return 0;
    }
    __atomic_store_n(&round->ready, 1, __ATOMIC_RELEASE);
    for (;;)
        pthread_testcancel();
}

#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
static void *process_done_allocate(enum process_done_allocation_kind kind)
{
    void *client;

    switch (kind) {
    case PROCESS_DONE_ALLOCATION_NORMAL:
        return malloc(10241);
    case PROCESS_DONE_ALLOCATION_ALIGNED_FAST:
        return aligned_alloc(256, 10240);
    case PROCESS_DONE_ALLOCATION_ALIGNED_INTERIOR:
        /* `posix_memalign` has no size-multiple restriction. With this
         * source-shaped pair, the second 8192-aligned client adjusts a
         * 20480-byte base block and sets the page-wide interior marker. */
        client = 0;
        return posix_memalign(&client, 8192, 10240) == 0 ? client : 0;
    }
    return 0;
}

static int process_done_is_interior(
    enum process_done_allocation_kind kind)
{
    return kind == PROCESS_DONE_ALLOCATION_ALIGNED_INTERIOR;
}

static size_t process_done_expected_reserved(
    enum process_done_allocation_kind kind)
{
    return process_done_is_interior(kind) ? 25u : 42u;
}

static int process_done_expected_interior_after_allocation(
    enum process_done_allocation_kind kind, size_t client_count)
{
    return process_done_is_interior(kind)
        && client_count == CRABC_PROCESS_DONE_CLIENT_COUNT;
}

static int process_done_current_page_snapshot(
    void *client, struct process_done_local_page_audit *audit)
{
    return __crabc_x86_native_mimalloc_current_local_page_test_audit(client, audit);
}

static int process_done_retained_page_snapshot(
    void *client, struct process_done_local_page_audit *audit)
{
    return __crabc_x86_native_mimalloc_process_done_retained_local_page_test_audit(
        client, audit);
}

static int process_done_allocate_nonfull_page(struct process_done_client_page *page)
{
    struct process_done_local_page_audit audit;
    void *client;
    int result;

    page->client_count = 0;
    while (page->client_count != CRABC_PROCESS_DONE_CLIENT_COUNT) {
        client = process_done_allocate(page->allocation_kind);
        if (client == 0)
            return 11;
        if (page->allocation_kind == PROCESS_DONE_ALLOCATION_ALIGNED_FAST
                && ((uintptr_t)client & 255u) != 0)
            return 12;
        if (page->allocation_kind == PROCESS_DONE_ALLOCATION_ALIGNED_INTERIOR
                && ((uintptr_t)client & 8191u) != 0)
            return 13;
        page->clients[page->client_count++] = client;
        ((volatile unsigned char *)client)[0] = 0x6d;
        result = process_done_current_page_snapshot(page->clients[0], &audit);
        if (result != 1)
            return 20 - result;
        if (audit.has_interior_pointers != process_done_expected_interior_after_allocation(
                    page->allocation_kind, page->client_count)
                || audit.member_link_coherent != 1
                || audit.used != page->client_count
                || audit.capacity < audit.used
                || audit.reserved < audit.used)
            return 30;
    }

    if (__crabc_x86_native_mimalloc_current_local_page_same_test_audit(
            page->clients[0], page->clients[1]) != 1)
        return 32;
    result = process_done_current_page_snapshot(page->clients[0], &audit);
    if (result != 1)
        return 40 - result;
    /* Pinned release C observes two distinct aligned outcomes. The public
     * 256-byte request reaches `src/alloc-aligned.c`'s overallocate helper
     * but needs no pointer adjustment, so its page marker remains clear.
     * The separate 8192-byte `posix_memalign` pair has a second base at a
     * 4096-byte offset: `aligned_p != p` sets the page-wide interior marker
     * in `mi_theap_malloc_zero_aligned_at_overalloc`. Each pair stays
     * nonfull on one regular page. The C source oracle separately observes
     * the ordinary full-page `src/page.c:mi_page_to_full` abandonment branch.
     */
    if (audit.in_full != 0
            || audit.has_interior_pointers != process_done_is_interior(
                page->allocation_kind)
            || audit.used != CRABC_PROCESS_DONE_CLIENT_COUNT
            || audit.capacity != 2
            || audit.reserved != process_done_expected_reserved(
                page->allocation_kind)
            || audit.regular_queue_count != 1
            || audit.full_queue_count != 0
            || audit.theap_page_count != 1
            || audit.member_link_coherent != 1) {
        return 50;
    }
    return 0;
}

static int process_done_free_retained_source_page(
    const struct process_done_client_page *previous)
{
    struct process_done_local_page_audit audit;
    size_t first_index = process_done_is_interior(previous->allocation_kind) ? 1u : 0u;
    size_t sibling_index = first_index ^ 1u;
    int result;

    if (previous->client_count != CRABC_PROCESS_DONE_CLIENT_COUNT)
        return 80;
    if (__crabc_x86_native_mimalloc_process_done_retained_worker_matches_current_thread_test_audit() != 1)
        return 81;
    /* The interior case frees the adjusted second client first. Pinned
     * `src/free.c:148-166,223-247` must recover its canonical base from the
     * old retained page, rather than substitute the new worker's Theap. */
    if (__crabc_x86_native_mimalloc_process_done_retained_local_preflight_test_audit(
            previous->clients[first_index]) != 1)
        return 82;
    free(previous->clients[first_index]);
    result = process_done_retained_page_snapshot(
        previous->clients[sibling_index], &audit);
    if (result != 1)
        return 90 - result;
    if (audit.in_full != 0
            || audit.has_interior_pointers != process_done_is_interior(
                previous->allocation_kind)
            || audit.used != 1
            || audit.capacity != 2
            || audit.reserved != process_done_expected_reserved(
                previous->allocation_kind)
            || audit.regular_queue_count != 1
            || audit.full_queue_count != 0
            || audit.theap_page_count != 1
            || audit.member_link_coherent != 1)
        return 100;
    free(previous->clients[sibling_index]);
    /* `src/free.c:28-56` reaches `_mi_page_retire`; with this sole regular
     * medium page, `src/page.c:424-456` keeps PageMap publication and sets
     * the release countdown to `MI_RETIRE_CYCLES / 4`, rather than releasing
     * the page on this local free. */
    if (__crabc_x86_native_mimalloc_process_done_retained_page_retired_test_audit(
            previous->clients[sibling_index],
            process_done_expected_reserved(previous->allocation_kind)) != 1)
        return 101;
    return 0;
}

static int process_done_free_current_page(struct process_done_client_page *current)
{
    size_t index;

    if (current->client_count != CRABC_PROCESS_DONE_CLIENT_COUNT)
        return 102;
    for (index = 0; index < current->client_count; ++index)
        free(current->clients[index]);
    current->client_count = 0;
    return 0;
}

static void *process_done_worker(void *opaque)
{
    struct process_done_round *round = opaque;
    int result;

    result = process_done_allocate_nonfull_page(&round->current);
    if (result != 0) {
        __atomic_store_n(&round->failure, result, __ATOMIC_RELEASE);
        return 0;
    }
    if (round->previous != 0) {
        result = process_done_free_retained_source_page(round->previous);
        if (result == 0)
            result = process_done_free_current_page(&round->current);
        if (result != 0) {
            __atomic_store_n(&round->failure, result, __ATOMIC_RELEASE);
            return 0;
        }
    } else if (!round->retain_current) {
        __atomic_store_n(&round->failure, 103, __ATOMIC_RELEASE);
    }
    return 0;
}

static int run_process_done_worker_round(
    const struct process_done_client_page *previous,
    struct process_done_client_page *current,
    size_t baseline_later_thread_count,
    enum process_done_allocation_kind allocation_kind, int retain_current)
{
    pthread_t thread;
    struct process_done_round round = {
        .previous = previous,
        .current = {
            .clients = {0},
            .client_count = 0,
            .allocation_kind = allocation_kind,
        },
        .retain_current = retain_current,
        .failure = 0,
    };

    if (pthread_create(&thread, 0, process_done_worker, &round) != 0)
        return 1;
    if (pthread_join(thread, 0) != 0)
        return 2;
    if (__atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0)
        return __atomic_load_n(&round.failure, __ATOMIC_ACQUIRE);
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 3;
    if (retain_current) {
        struct process_done_local_page_audit audit;
        int result;

        if (round.current.client_count != CRABC_PROCESS_DONE_CLIENT_COUNT)
            return 4;
        result = process_done_retained_page_snapshot(round.current.clients[0], &audit);
        if (result != 1)
            return 110 - result;
        if (audit.in_full != 0
                || audit.has_interior_pointers != process_done_is_interior(
                    round.current.allocation_kind)
                || audit.used != round.current.client_count
                || audit.capacity != 2
                || audit.reserved != process_done_expected_reserved(
                    round.current.allocation_kind)
                || audit.regular_queue_count != 1
                || audit.full_queue_count != 0
                || audit.theap_page_count != 1
                || audit.member_link_coherent != 1)
            return 120;
        *current = round.current;
    } else if (round.current.client_count != 0) {
        return 5;
    }
    return 0;
}
#endif

/* Before process done, the selected R/E paths finish `_mi_thread_done` before
 * libc's locked final-task decision and reinitialize a completed owner for
 * ordinary-exit callbacks. This probe also exercises the distinct post-done
 * branch: the deleted private automatic key makes finish return pending, and
 * the final-task decision deliberately preserves this same active owner
 * through atexit. The callback allocates and frees both a new block and its
 * worker-created live block under that retained source Theap. */
static void final_worker_atexit_allocation(void)
{
    void *allocation = malloc(257);
    void *pre_teardown_allocation = final_worker_pre_teardown_allocation;

    if (allocation == 0)
        _Exit(51);
    ((volatile unsigned char *)allocation)[0] = 0x3c;
    free(allocation);
    if (pre_teardown_allocation == 0)
        _Exit(53);
    free(pre_teardown_allocation);
    final_worker_pre_teardown_allocation = 0;
}

static void *final_worker_after_initial_pthread_exit(void *opaque)
{
    char release;
    void *allocation;

    (void)opaque;
    allocation = malloc(193);
    if (allocation == 0)
        _Exit(54);
    ((volatile unsigned char *)allocation)[0] = 0xc3;
    final_worker_pre_teardown_allocation = allocation;
    __atomic_store_n(&final_worker_ready, 1, __ATOMIC_RELEASE);
    if (read(STDIN_FILENO, &release, 1) != 1)
        _Exit(52);
    if (release == 'E')
        pthread_exit(0);
    if (release != 'R')
        _Exit(52);
    return 0;
}

static int run_return_round(
    void *(*worker)(void *), uintptr_t marker, int failure_base)
{
    pthread_t thread;
    void *result = 0;
    struct teardown_round round = {
        .ready = 0,
        .tsd_finished = 0,
        .failure = 0,
        .marker = marker,
    };

    if (pthread_create(&thread, 0, worker, &round) != 0)
        return failure_base + 1;
    if (pthread_join(thread, &result) != 0)
        return failure_base + 2;
    if (result != (void *)marker)
        return failure_base + 3;
    if (__atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0)
        return failure_base + 4;
    if (__atomic_load_n(&round.tsd_finished, __ATOMIC_ACQUIRE) != 1)
        return failure_base + 5;
    return 0;
}

static int run_deferred_cancellation_round(void)
{
    pthread_t thread;
    void *result = 0;
    struct teardown_round round = {
        .ready = 0,
        .tsd_finished = 0,
        .failure = 0,
        .marker = 0,
    };

    if (pthread_create(&thread, 0, deferred_cancel_worker, &round) != 0)
        return 31;
    if (wait_for_nonzero(&round.ready) != 0)
        return 32;
    if (pthread_cancel(thread) != 0)
        return 33;
    if (pthread_join(thread, &result) != 0)
        return 34;
    if (result != PTHREAD_CANCELED)
        return 35;
    if (__atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0)
        return 36;
    if (__atomic_load_n(&round.tsd_finished, __ATOMIC_ACQUIRE) != 1)
        return 37;
    return 0;
}

static void *prestart_callback(void *opaque)
{
    (void)opaque;
    __atomic_fetch_add(&prestart_callback_count, 1, __ATOMIC_RELEASE);
    return 0;
}

/* Called by the candidate-only entry shim after libc's static TLS bootstrap
 * but before __libc_start_main installs the native process owner. Inactive is
 * the one recoverable attach result: the parent must return EAGAIN only after
 * the child has stopped, without exposing a callback or pthread handle. */
int crabc_x86_64_native_mimalloc_shadow_prestart_rejection(void)
{
    pthread_t thread;
    int result;

    __atomic_store_n(&prestart_callback_count, 0, __ATOMIC_RELEASE);
    result = pthread_create(&thread, 0, prestart_callback, 0);
    if (result != EAGAIN)
        return 1;
    if (__atomic_load_n(&prestart_callback_count, __ATOMIC_ACQUIRE) != 0)
        return 2;
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    /* The rejected child published a descriptor before attach. The native
     * inactive path must retire it, then the parent must unmap all three
     * child mappings before this pre-start caller continues. */
    if (__crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit()
            != 1)
        return 3;
#endif
    return 0;
}

#if defined(CRABC_NATIVE_MIMALLOC_SHADOW_PHYSICAL_PROCESS_DESTROY_PROBE)
/* This private selected-native probe invokes the dedicated test-only explicit
 * physical process-destroy spelling after process startup. Its runner supplies signed
 * nonzero `mimalloc_destroy_on_exit` values. The process-destroy adapter must
 * transfer the initial descriptor while the existing worker registry pins it,
 * return from that callback, and only then release the physical source graph.
 * A second observation must be the source once no-op and must not reopen the
 * sealed VM/source state. Do not free or otherwise touch `client` after the
 * destroy; it names memory which the physical branch may have unmapped. */
#ifndef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
#error "physical process-destroy probe requires its private audit feature"
#endif
int main(void)
{
    void *client = malloc(431);

    if (client == 0)
        _Exit(83);
    ((volatile unsigned char *)client)[0] = 0x9a;
    if (__crabc_x86_native_mimalloc_process_destroy_test_audit() != 0)
        _Exit(84);
    if (__crabc_x86_native_mimalloc_process_destroy_test_audit() != 1)
        _Exit(85);
    /* The production automatic finalizer is intentionally still disabled for
     * physical destruction. Exit directly so this focused explicit probe does
     * not exercise that retaining `.fini_array` caller after the terminal
     * process image has been destroyed. */
    _Exit(0);
}
#elif defined(CRABC_NATIVE_MIMALLOC_SHADOW_NORMAL_MAIN_RETURN_PROBE)
/* The ordinary static-startup return path registers executable fini before
 * application code. A later application `atexit` therefore runs first; the
 * CRT then walks fini-array entries in reverse. Pinned `src/prim/prim.c`
 * puts its automatic process-done destructor in that same array before
 * regular application destructors. This separate small main records the
 * resulting `A` (atexit), `M` (selected replacement), `D` (application fini)
 * order while every callback allocates and frees. Its initial-task TSD
 * destructor is deliberately fatal: ordinary process exit must not run it. */
static pthread_key_t normal_main_return_key;
static volatile int normal_main_user_atexit_seen;

#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_PROCESS_DONE_EXIT_TEST_AUDIT
extern int __crabc_x86_native_mimalloc_process_done_fini_array_test_audit(void);

struct process_done_terminal_purge_audit {
    size_t terminal_preloading;
    size_t purge_decommits_enabled;
    size_t mapping_retained_before_release;
    size_t purge_needs_recommit;
    size_t purge_calls_delta;
    size_t purged_bytes_delta;
    size_t reset_calls_delta;
    size_t reset_bytes_delta;
    size_t release_succeeded;
};

extern int __crabc_x86_native_mimalloc_process_done_terminal_purge_test_audit(
    struct process_done_terminal_purge_audit *output);
#endif

int crabc_x86_64_native_mimalloc_shadow_normal_main_user_atexit_observed(void)
{
    return __atomic_load_n(&normal_main_user_atexit_seen, __ATOMIC_ACQUIRE);
}

void crabc_x86_64_native_mimalloc_shadow_normal_main_process_done_fini_observed(void)
{
    const char marker = 'M';

    if (write(STDERR_FILENO, &marker, 1) != 1)
        _Exit(72);
}

static void normal_main_return_tsd_destructor(void *opaque)
{
    (void)opaque;
    _Exit(71);
}

static void normal_main_return_atexit(void)
{
    const char marker = 'A';
    void *allocation = malloc(353);

    if (allocation == 0)
        _Exit(73);
    ((volatile unsigned char *)allocation)[0] = 0x3d;
    free(allocation);
    __atomic_store_n(&normal_main_user_atexit_seen, 1, __ATOMIC_RELEASE);
    if (write(STDERR_FILENO, &marker, 1) != 1)
        _Exit(74);
}

__attribute__((destructor))
static void normal_main_return_application_fini(void)
{
    const char marker = 'D';
    void *allocation;

    allocation = malloc(359);
    if (allocation == 0)
        _Exit(76);
    ((volatile unsigned char *)allocation)[0] = 0xe3;
    free(allocation);
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_PROCESS_DONE_EXIT_TEST_AUDIT
    struct process_done_terminal_purge_audit purge = { 0 };

    /* The allocation/free itself must remain valid after the selected fini
     * bridge. The following source-shaped purge receipt additionally proves
     * its `init.c:647` terminal preloading state reaches `os.c` while the
     * transient mapping remains owned and releasable. */
    if (__crabc_x86_native_mimalloc_process_done_fini_array_test_audit() != 1)
        _Exit(75);
    if (__crabc_x86_native_mimalloc_process_done_terminal_purge_test_audit(&purge) != 0)
        _Exit(81);
    if (purge.terminal_preloading != 1 || purge.purge_decommits_enabled != 1
            || purge.mapping_retained_before_release != 1
            || purge.purge_needs_recommit != 0 || purge.purge_calls_delta != 1
            || purge.purged_bytes_delta == 0 || purge.reset_calls_delta != 1
            || purge.reset_bytes_delta != purge.purged_bytes_delta
            || purge.release_succeeded != 1)
        _Exit(82);
#endif
    if (write(STDERR_FILENO, &marker, 1) != 1)
        _Exit(77);
}

int main(void)
{
    int token = 1;

    if (pthread_key_create(&normal_main_return_key,
            normal_main_return_tsd_destructor) != 0)
        return 78;
    if (pthread_setspecific(normal_main_return_key, &token) != 0)
        return 79;
    if (atexit(normal_main_return_atexit) != 0)
        return 80;
    return 0;
}
#else
int main(void)
{
    int result;

#ifdef CRABC_NATIVE_INTERNAL_MALLOC_OVERRIDE
    if (pthread_atfork(0, 0, 0) != 0)
        return 41;
    return __atomic_load_n(&replacement_malloc_calls, __ATOMIC_ACQUIRE) == 0
        ? 0 : 42;
#else
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    const size_t baseline_later_thread_count =
        __crabc_x86_native_mimalloc_active_later_thread_count_test_audit();
    const size_t baseline_native_descriptor_count =
        __crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit();
    const size_t baseline_native_descriptor_reclaim_count =
        __crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit();
    struct process_done_client_page normal_source_page;
    struct process_done_client_page aligned_fast_source_page;
    struct process_done_client_page aligned_interior_source_page;
    struct process_done_client_page discarded_current_page;

    /* The rejected pre-start worker never installed an admission; ordinary
     * startup must therefore begin these three attached rounds at zero. */
    if (baseline_later_thread_count != 0)
        return 9;
    if (baseline_native_descriptor_count != 1)
        return 10;
    if (baseline_native_descriptor_reclaim_count != 1)
        return 11;
#endif
    if (pthread_key_create(&teardown_key, native_allocation_tsd_destructor) != 0)
        return 10;
    result = run_raw_copy_completion_paths();
    if (result != 0)
        return 90 + result;
    result = run_return_round(normal_return_worker, CRABC_NORMAL_MARKER, 10);
    if (result != 0)
        return result;
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 18;
    if (__crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit() !=
            baseline_native_descriptor_count)
        return 19;
    if (__crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit() !=
            baseline_native_descriptor_reclaim_count + 1)
        return 17;
#endif
    result = run_return_round(explicit_exit_worker, CRABC_EXPLICIT_MARKER, 20);
    if (result != 0)
        return result;
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 28;
    if (__crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit() !=
            baseline_native_descriptor_count)
        return 29;
    if (__crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit() !=
            baseline_native_descriptor_reclaim_count + 2)
        return 27;
#endif
    {
        pthread_t thread;
        void *worker_result = 0;
        struct teardown_round round = {
            .ready = 0,
            .tsd_finished = 0,
            .failure = 0,
            .first_public_allocation_from_tsd = 1,
            .user_start_returned = 0,
            .rejected_first_request = 0,
            .marker = CRABC_TSD_FIRST_MARKER,
        };

        if (pthread_create(&thread, 0, first_public_allocation_in_tsd_worker,
                &round) != 0)
            return 29;
        if (pthread_join(thread, &worker_result) != 0)
            return 30;
        if (worker_result != (void *)CRABC_TSD_FIRST_MARKER
                || __atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0
                || __atomic_load_n(&round.tsd_finished, __ATOMIC_ACQUIRE) != 1
                || __atomic_load_n(&round.user_start_returned,
                    __ATOMIC_ACQUIRE) != 1
                || __atomic_load_n(&round.rejected_first_request,
                    __ATOMIC_ACQUIRE) != 1)
            return 31;
    }
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 32;
#endif
    {
        pthread_t thread;
        void *worker_result = 0;
        struct teardown_round round = {
            .ready = 0,
            .tsd_finished = 0,
            .failure = 0,
            .realloc_failure_preserved = 0,
            .marker = CRABC_REALLOC_FAILURE_MARKER,
        };

        if (pthread_create(&thread, 0, realloc_failure_preserving_worker,
                &round) != 0)
            return 33;
        if (pthread_join(thread, &worker_result) != 0)
            return 34;
        if (worker_result != (void *)CRABC_REALLOC_FAILURE_MARKER
                || __atomic_load_n(&round.failure, __ATOMIC_ACQUIRE) != 0
                || __atomic_load_n(&round.realloc_failure_preserved,
                    __ATOMIC_ACQUIRE) != 1
                || __atomic_load_n(&round.tsd_finished, __ATOMIC_ACQUIRE) != 1)
            return 35;
    }
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 36;
#endif
    result = run_deferred_cancellation_round();
    if (result != 0)
        return result;
#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 38;
    if (__crabc_x86_native_mimalloc_registered_thread_descriptor_count_test_audit() !=
            baseline_native_descriptor_count)
        return 39;
    if (__crabc_x86_native_mimalloc_reclaimed_worker_descriptor_count_test_audit() !=
            /* normal, explicit-exit, TSD-first, realloc, and cancellation */
            baseline_native_descriptor_reclaim_count + 5)
        return 37;
#endif
    if (pthread_key_delete(teardown_key) != 0)
        return 40;

#ifdef CRABC_NATIVE_MIMALLOC_SHADOW_TEST_AUDIT
    /* The test-only process finalizer has no public C spelling.  It models
     * pinned `mi_process_done_once` only for this selected-native fixture;
     * the ordinary product route reaches its replacement `.fini_array` entry
     * after the executable's user `atexit` dispatch. */
    if (__crabc_x86_native_mimalloc_process_done_test_audit() != 0)
        return 44;
    result = run_process_done_worker_round(0, &normal_source_page,
        baseline_later_thread_count, PROCESS_DONE_ALLOCATION_NORMAL, 1);
    if (result != 0)
        return 45 + result;
    /* The second worker establishes its own page owner before it frees both
     * clients of the first worker's retained regular page. This takes pinned
     * pointer-first local free under an actually recycled TLS/TCB TP, without
     * treating that scalar reuse as a Rust lifetime generation. */
    result = run_process_done_worker_round(
        &normal_source_page, &discarded_current_page,
        baseline_later_thread_count, PROCESS_DONE_ALLOCATION_NORMAL, 0);
    if (result != 0)
        return 55 + result;
    result = run_process_done_worker_round(0, &aligned_fast_source_page,
        baseline_later_thread_count, PROCESS_DONE_ALLOCATION_ALIGNED_FAST, 1);
    if (result != 0)
        return 67 + result;
    result = run_process_done_worker_round(
        &aligned_fast_source_page, &discarded_current_page,
        baseline_later_thread_count, PROCESS_DONE_ALLOCATION_ALIGNED_FAST, 0);
    if (result != 0)
        return 77 + result;
    result = run_process_done_worker_round(0, &aligned_interior_source_page,
        baseline_later_thread_count, PROCESS_DONE_ALLOCATION_ALIGNED_INTERIOR, 1);
    if (result != 0)
        return 89 + result;
    result = run_process_done_worker_round(
        &aligned_interior_source_page, &discarded_current_page,
        baseline_later_thread_count, PROCESS_DONE_ALLOCATION_ALIGNED_INTERIOR, 0);
    if (result != 0)
        return 99 + result;
    if (__crabc_x86_native_mimalloc_active_later_thread_count_test_audit() !=
            baseline_later_thread_count)
        return 110;
#endif

    /* Main pthread_exit must leave this worker as the final ordinary-exit
     * owner. Because this fixture already crossed logical process done, its
     * finish is pending until the locked decision preserves the same owner
     * for the callback. The task-ID handshake prevents an early return. */
    {
        pthread_t final_worker;

        __atomic_store_n(&final_worker_ready, 0, __ATOMIC_RELEASE);
        if (atexit(final_worker_atexit_allocation) != 0)
            return 41;
        if (pthread_create(&final_worker, 0,
                final_worker_after_initial_pthread_exit, 0) != 0)
            return 42;
        if (wait_for_nonzero(&final_worker_ready) != 0)
            return 43;
    }
    pthread_exit(0);
#endif
}
#endif

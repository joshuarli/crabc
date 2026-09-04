/*
 * Deterministic selected-shadow allocator smoke.
 *
 * This fixture deliberately uses only production C allocation entry points.
 * Each owner returns normally with the same mixed 85-block image as the
 * independent-releaser C regression
 * (`tests/fixtures/native_mimalloc_concurrent_post_exit_release_test.c`):
 * eighty direct-small clients followed by non-direct-small, medium, large,
 * arena-singleton, and OS-singleton tails.
 * The initial thread joins that owner, starts four fresh independent releasers,
 * and opens their common barrier only once each has reached it. Each releaser
 * validates and frees its fixed-stride disjoint subset of those exact C
 * addresses. The post-owner-exit release epoch is deliberately isolated from
 * other ownership transitions so it stays equivalent to the independent-
 * releaser C regression. It never receives an allocator-private capability.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <malloc.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum {
    DIRECT_SMALL_BLOCK_COUNT = 80,
    NON_DIRECT_SMALL_INDEX = DIRECT_SMALL_BLOCK_COUNT,
    MEDIUM_INDEX = NON_DIRECT_SMALL_INDEX + 1,
    LARGE_INDEX = MEDIUM_INDEX + 1,
    ARENA_SINGLETON_INDEX = LARGE_INDEX + 1,
    OS_SINGLETON_INDEX = ARENA_SINGLETON_INDEX + 1,
    EXIT_BLOCK_COUNT = OS_SINGLETON_INDEX + 1,
    POST_EXIT_RELEASER_COUNT = 4,
};

static size_t exit_request(unsigned index)
{
    if (index < DIRECT_SMALL_BLOCK_COUNT)
        return 1024;
    switch (index) {
    case NON_DIRECT_SMALL_INDEX:
        return 1025;
    case MEDIUM_INDEX:
        return 64 * 1024;
    case LARGE_INDEX:
        return 128 * 1024;
    case ARENA_SINGLETON_INDEX:
        return 1024 * 1024;
    default:
        return 7;
    }
}

struct smoke_state {
    pthread_mutex_t lock;
    pthread_barrier_t post_exit_release_barrier;
    unsigned char *exiting[EXIT_BLOCK_COUNT];
    uint64_t epoch_seed;
    uint64_t first_fixture_epoch_seed;
    uint64_t last_fixture_epoch_seed;
    unsigned post_exit_release_started;
    unsigned post_exit_releasers_completed_epoch;
    unsigned failed;
    unsigned fail_code;
    unsigned current_epoch;
    int failure_subject_index;
    const char *failure_transition;
    uint64_t requested_total;
    uint64_t requested_live;
    uint64_t requested_live_high_water;
    uint64_t usable_live;
    uint64_t usable_live_high_water;
    uint64_t live_blocks;
    uint64_t live_blocks_high_water;
    uint64_t rss_initial_bytes;
    uint64_t rss_final_bytes;
    uint64_t rss_high_water_bytes;
    uint64_t rss_warm_quiescent_bytes;
    uint64_t rss_last_quiescent_bytes;
    uint64_t rss_samples;
    uint64_t owner_exits_with_live_blocks;
    uint64_t post_exit_concurrent_release_epochs;
    uint64_t post_exit_independent_releasers_completed;
    uint64_t post_exit_concurrent_release_frees;
    uint64_t post_exit_retained_valid_frees;
    uint64_t post_exit_aborted_valid_frees;
    uint64_t post_exit_release_frees_epoch;
    uint64_t state_audit_snapshots;
    uint64_t state_audit_warm_requested_live_bytes;
    uint64_t state_audit_warm_usable_live_bytes;
    uint64_t state_audit_warm_live_blocks;
    unsigned state_audit_warm_post_exit_release_started;
    unsigned state_audit_warm_post_exit_releasers_completed_epoch;
    uint64_t state_audit_warm_post_exit_release_frees_epoch;
};

static struct smoke_state state = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .failure_subject_index = -1,
};

static uint64_t next_random(uint64_t *state_value)
{
    uint64_t value = *state_value;

    value ^= value << 13;
    value ^= value >> 7;
    value ^= value << 17;
    *state_value = value;
    return value;
}

static unsigned char tag_for(uint64_t seed, unsigned slot, unsigned edge)
{
    uint64_t mixed = seed ^ ((uint64_t)slot << 24) ^ ((uint64_t)edge << 40);

    mixed = next_random(&mixed);
    return (unsigned char)(mixed | 1U);
}

static uint64_t read_rss_bytes(void)
{
    char buffer[4096];
    ssize_t length;
    int descriptor;
    size_t index;

    descriptor = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
    if (descriptor < 0)
        return 0;
    length = read(descriptor, buffer, sizeof(buffer) - 1);
    (void)close(descriptor);
    if (length <= 0)
        return 0;
    buffer[length] = '\0';
    for (index = 0; index + 6 < (size_t)length; index++) {
        uint64_t kibibytes = 0;
        size_t cursor;

        if (memcmp(buffer + index, "VmRSS:", 6) != 0)
            continue;
        cursor = index + 6;
        while (cursor < (size_t)length
                && (buffer[cursor] == ' ' || buffer[cursor] == '\t'))
            cursor++;
        while (cursor < (size_t)length
                && buffer[cursor] >= '0' && buffer[cursor] <= '9') {
            kibibytes = kibibytes * 10 + (uint64_t)(buffer[cursor] - '0');
            cursor++;
        }
        return kibibytes * 1024;
    }
    return 0;
}

static uint64_t observe_rss_locked(void)
{
    uint64_t rss = read_rss_bytes();

    state.rss_samples += 1;
    if (rss > state.rss_high_water_bytes)
        state.rss_high_water_bytes = rss;
    return rss;
}

static void record_allocation(size_t request, size_t usable)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    state.requested_total += request;
    state.requested_live += request;
    state.usable_live += usable;
    state.live_blocks += 1;
    if (state.requested_live > state.requested_live_high_water)
        state.requested_live_high_water = state.requested_live;
    if (state.usable_live > state.usable_live_high_water)
        state.usable_live_high_water = state.usable_live;
    if (state.live_blocks > state.live_blocks_high_water)
        state.live_blocks_high_water = state.live_blocks;
    observe_rss_locked();
    (void)pthread_mutex_unlock(&state.lock);
}

static void mark_failed_locked(unsigned code, const char *transition,
    int subject_index)
{
    if (!state.failed) {
        state.failed = 1;
        state.fail_code = code;
        state.failure_transition = transition;
        state.failure_subject_index = subject_index;
    }
}

static void record_free(size_t request, size_t usable)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    if (state.requested_live < request || state.usable_live < usable
            || state.live_blocks == 0) {
        mark_failed_locked(90, "tracked_free_accounting", -1);
    } else {
        state.requested_live -= request;
        state.usable_live -= usable;
        state.live_blocks -= 1;
    }
    observe_rss_locked();
    (void)pthread_mutex_unlock(&state.lock);
}

static unsigned char *tracked_malloc(size_t request)
{
    unsigned char *block = malloc(request);

    if (block != NULL)
        record_allocation(request, malloc_usable_size(block));
    return block;
}

static unsigned char *tracked_aligned_allocation(size_t alignment, size_t request)
{
    void *raw = NULL;

    if (posix_memalign(&raw, alignment, request) != 0)
        return NULL;
    record_allocation(request, malloc_usable_size(raw));
    return raw;
}

static int tracked_free(unsigned char *block, size_t request)
{
    size_t usable;

    if (block == NULL)
        return 0;
    usable = malloc_usable_size(block);
    if (usable < request)
        return 0;
    free(block);
    record_free(request, usable);
    return 1;
}

static void fill_block(unsigned char *block, size_t request, unsigned char tag)
{
    block[0] = tag;
    block[request - 1] = (unsigned char)(tag ^ 0xa5U);
}

static int block_matches(const unsigned char *block, size_t request, unsigned char tag)
{
    return block != NULL && block[0] == tag
        && block[request - 1] == (unsigned char)(tag ^ 0xa5U)
        && malloc_usable_size((void *)block) >= request;
}

static void mark_failed(unsigned code, const char *transition, int subject_index)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    mark_failed_locked(code, transition, subject_index);
    (void)pthread_mutex_unlock(&state.lock);
}

static void *owner_worker(void *opaque)
{
    unsigned index;

    (void)opaque;
    for (index = 0; index < EXIT_BLOCK_COUNT; index++) {
        size_t request = exit_request(index);

        if (index == OS_SINGLETON_INDEX) {
            state.exiting[index] = tracked_aligned_allocation(128 * 1024,
                request);
        } else {
            state.exiting[index] = tracked_malloc(request);
        }
        if (state.exiting[index] == NULL) {
            mark_failed(30, "owner_exit_allocation", (int)index);
            return (void *)(uintptr_t)30;
        }
        fill_block(state.exiting[index], request,
            tag_for(state.epoch_seed, index, 2));
    }

    return NULL;
}

static int prepare_epoch(unsigned epoch, uint64_t epoch_seed)
{
    state.current_epoch = epoch;
    state.epoch_seed = epoch_seed;
    if (epoch == 1)
        state.first_fixture_epoch_seed = epoch_seed;
    state.last_fixture_epoch_seed = epoch_seed;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 0;
    state.failed = 0;
    state.fail_code = 0;
    state.failure_transition = NULL;
    state.failure_subject_index = -1;
    if (state.live_blocks != 0) {
        mark_failed_locked(50, "pre_epoch_liveness", -1);
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    memset(state.exiting, 0, sizeof(state.exiting));
    state.post_exit_release_started = 0;
    state.post_exit_releasers_completed_epoch = 0;
    state.post_exit_release_frees_epoch = 0;
    observe_rss_locked();
    return pthread_mutex_unlock(&state.lock) == 0;
}

static void mark_post_exit_valid_free_failure(unsigned code, const char *transition,
    unsigned index, int retained, int aborted)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    if (retained)
        state.post_exit_retained_valid_frees += 1;
    if (aborted)
        state.post_exit_aborted_valid_frees += 1;
    mark_failed_locked(code, transition, (int)index);
    (void)pthread_mutex_unlock(&state.lock);
}

static void *post_exit_releaser_worker(void *opaque)
{
    unsigned releaser = (unsigned)(uintptr_t)opaque;
    unsigned index;

    if (releaser >= POST_EXIT_RELEASER_COUNT) {
        mark_failed(100, "post_exit_releaser_index", (int)releaser);
        return (void *)(uintptr_t)100;
    }
    {
        int barrier = pthread_barrier_wait(&state.post_exit_release_barrier);

        if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) {
            mark_failed(101, "post_exit_releaser_start_barrier", (int)releaser);
            return (void *)(uintptr_t)101;
        }
    }

    for (index = releaser; index < EXIT_BLOCK_COUNT;
            index += POST_EXIT_RELEASER_COUNT) {
        unsigned char *block;
        size_t request = exit_request(index);

        if (pthread_mutex_lock(&state.lock) != 0) {
            mark_failed(102, "post_exit_releaser_claim_lock", (int)releaser);
            return (void *)(uintptr_t)102;
        }
        if (state.failed) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)103;
        }
        block = state.exiting[index];
        if (block == NULL) {
            state.post_exit_aborted_valid_frees += 1;
            mark_failed_locked(104, "post_exit_concurrent_free_aborted", (int)index);
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)104;
        }
        if (pthread_mutex_unlock(&state.lock) != 0) {
            mark_failed(105, "post_exit_releaser_claim_unlock", (int)index);
            return (void *)(uintptr_t)105;
        }
        if (!block_matches(block, request,
                tag_for(state.epoch_seed, index, 2))) {
            mark_post_exit_valid_free_failure(106,
                "post_exit_concurrent_valid_free_retained", index, 1, 0);
            return (void *)(uintptr_t)106;
        }
        if (!tracked_free(block, request)) {
            mark_post_exit_valid_free_failure(107,
                "post_exit_concurrent_valid_free_retained", index, 1, 0);
            return (void *)(uintptr_t)107;
        }
        if (pthread_mutex_lock(&state.lock) != 0) {
            mark_failed(108, "post_exit_releaser_accounting_lock", (int)index);
            return (void *)(uintptr_t)108;
        }
        if (state.exiting[index] != block) {
            state.post_exit_aborted_valid_frees += 1;
            mark_failed_locked(109, "post_exit_concurrent_free_state", (int)index);
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)109;
        }
        state.exiting[index] = NULL;
        state.post_exit_concurrent_release_frees += 1;
        state.post_exit_release_frees_epoch += 1;
        observe_rss_locked();
        if (pthread_mutex_unlock(&state.lock) != 0) {
            mark_failed(110, "post_exit_releaser_accounting_unlock", (int)index);
            return (void *)(uintptr_t)110;
        }
    }

    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed(111, "post_exit_releaser_completion_lock", (int)releaser);
        return (void *)(uintptr_t)111;
    }
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)112;
    }
    state.post_exit_releasers_completed_epoch += 1;
    state.post_exit_independent_releasers_completed += 1;
    if (pthread_mutex_unlock(&state.lock) != 0) {
        mark_failed(113, "post_exit_releaser_completion_unlock", (int)releaser);
        return (void *)(uintptr_t)113;
    }
    return NULL;
}

static int run_post_exit_concurrent_release(void)
{
    pthread_t releasers[POST_EXIT_RELEASER_COUNT];
    unsigned created = 0;
    unsigned releaser;
    void *result = (void *)(uintptr_t)1;

    for (releaser = 0; releaser < POST_EXIT_RELEASER_COUNT; releaser++) {
        if (pthread_create(&releasers[releaser], NULL, post_exit_releaser_worker,
                (void *)(uintptr_t)releaser) != 0) {
            mark_failed(120, "post_exit_releaser_create", (int)releaser);
            return 0;
        }
        created += 1;
    }
    {
        int barrier = pthread_barrier_wait(&state.post_exit_release_barrier);

        if (barrier != 0 && barrier != PTHREAD_BARRIER_SERIAL_THREAD) {
            mark_failed(121, "post_exit_release_start_barrier", -1);
            goto join_releasers;
        }
    }
    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed(122, "post_exit_release_start_lock", -1);
        goto join_releasers;
    }
    state.post_exit_release_started = 1;
    if (pthread_mutex_unlock(&state.lock) != 0) {
        mark_failed(123, "post_exit_release_start_unlock", -1);
        goto join_releasers;
    }

join_releasers:
    for (releaser = 0; releaser < created; releaser++) {
        result = (void *)(uintptr_t)1;
        if (pthread_join(releasers[releaser], &result) != 0) {
            mark_failed(124, "post_exit_releaser_join", (int)releaser);
            continue;
        }
        if (result != NULL)
            mark_failed((unsigned)(uintptr_t)result, "post_exit_releaser_exit", (int)releaser);
    }
    if (created != POST_EXIT_RELEASER_COUNT)
        return 0;
    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed(125, "post_exit_release_completion_lock", -1);
        return 0;
    }
    if (state.failed
            || state.post_exit_releasers_completed_epoch != POST_EXIT_RELEASER_COUNT
            || state.post_exit_release_frees_epoch != EXIT_BLOCK_COUNT
            || state.post_exit_retained_valid_frees != 0
            || state.post_exit_aborted_valid_frees != 0) {
        if (!state.failed)
            mark_failed_locked(126, "post_exit_concurrent_release_completion", -1);
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    state.post_exit_concurrent_release_epochs += 1;
    if (pthread_mutex_unlock(&state.lock) != 0) {
        mark_failed(127, "post_exit_release_completion_unlock", -1);
        return 0;
    }
    return 1;
}

static int run_epoch(uint64_t *random_state, unsigned epoch)
{
    pthread_t owner;
    void *result = (void *)(uintptr_t)1;
    uint64_t epoch_seed = next_random(random_state);
    int join_status;

    if (!prepare_epoch(epoch, epoch_seed))
        return 0;
    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0) {
        mark_failed(58, "owner_thread_create", -1);
        return 0;
    }
    result = (void *)(uintptr_t)2;
    join_status = pthread_join(owner, &result);
    if (join_status != 0) {
        mark_failed(62, "owner_thread_join", -1);
        return 0;
    }
    if (result != NULL) {
        if (!state.failed)
            mark_failed((unsigned)(uintptr_t)result, "owner_worker_exit", -1);
        return 0;
    }
    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed(63, "owner_exit_accounting_lock", -1);
        return 0;
    }
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    state.owner_exits_with_live_blocks += 1;
    observe_rss_locked();
    if (pthread_mutex_unlock(&state.lock) != 0) {
        mark_failed(64, "owner_exit_accounting_unlock", -1);
        return 0;
    }
    return run_post_exit_concurrent_release();
}

static int audit_quiescent_epoch(unsigned epoch)
{
    unsigned index;
    int pointers_clear = 1;
    uint64_t quiescent_rss;

    if (pthread_mutex_lock(&state.lock) != 0) {
        mark_failed(80, "quiescent_state_audit_lock", -1);
        return 0;
    }
    for (index = 0; index < EXIT_BLOCK_COUNT; index++) {
        if (state.exiting[index] != NULL)
            pointers_clear = 0;
    }
    if (state.failed || !pointers_clear || state.requested_live != 0
            || state.usable_live != 0 || state.live_blocks != 0
            || state.owner_exits_with_live_blocks != epoch
            || state.post_exit_concurrent_release_epochs != epoch
            || state.post_exit_independent_releasers_completed
                != (uint64_t)epoch * POST_EXIT_RELEASER_COUNT
            || state.post_exit_concurrent_release_frees
                != (uint64_t)epoch * EXIT_BLOCK_COUNT
            || state.post_exit_retained_valid_frees != 0
            || state.post_exit_aborted_valid_frees != 0
            || !state.post_exit_release_started
            || state.post_exit_releasers_completed_epoch != POST_EXIT_RELEASER_COUNT
            || state.post_exit_release_frees_epoch != EXIT_BLOCK_COUNT) {
        mark_failed_locked(81, "quiescent_state_audit", -1);
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    if (state.state_audit_snapshots == 0) {
        state.state_audit_warm_requested_live_bytes = state.requested_live;
        state.state_audit_warm_usable_live_bytes = state.usable_live;
        state.state_audit_warm_live_blocks = state.live_blocks;
        state.state_audit_warm_post_exit_release_started = state.post_exit_release_started;
        state.state_audit_warm_post_exit_releasers_completed_epoch
            = state.post_exit_releasers_completed_epoch;
        state.state_audit_warm_post_exit_release_frees_epoch
            = state.post_exit_release_frees_epoch;
    } else if (state.requested_live != state.state_audit_warm_requested_live_bytes
            || state.usable_live != state.state_audit_warm_usable_live_bytes
            || state.live_blocks != state.state_audit_warm_live_blocks) {
        mark_failed_locked(82, "post_warm_liveness_plateau", -1);
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    } else if (state.post_exit_releasers_completed_epoch
                != state.state_audit_warm_post_exit_releasers_completed_epoch
            || state.post_exit_release_frees_epoch
                != state.state_audit_warm_post_exit_release_frees_epoch) {
        mark_failed_locked(83, "post_warm_post_exit_concurrent_release_count_growth", -1);
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    } else if (state.post_exit_release_started
            != state.state_audit_warm_post_exit_release_started) {
        mark_failed_locked(84, "post_warm_post_exit_concurrent_release_state_growth", -1);
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    quiescent_rss = observe_rss_locked();
    if (state.state_audit_snapshots == 0)
        state.rss_warm_quiescent_bytes = quiescent_rss;
    state.rss_last_quiescent_bytes = quiescent_rss;
    state.state_audit_snapshots += 1;
    return pthread_mutex_unlock(&state.lock) == 0;
}

static const char *failure_domain(unsigned code)
{
    if ((code >= 20 && code <= 24) || (code >= 40 && code <= 43)
            || (code >= 58 && code <= 64) || code == 76 || code == 77
            || code == 80 || code == 101 || code == 102 || code == 103
            || code == 105 || code == 108 || (code >= 110 && code <= 128)
            || code == 130)
        return "thread_runtime";
    if ((code >= 10 && code <= 39) || code == 44
            || (code >= 70 && code <= 75) || code == 104
            || code == 106 || code == 107 || code == 109)
        return "allocator_runtime";
    return "fixture_invariant";
}

static void print_epoch_failure(uint64_t seed, unsigned cycles,
    unsigned completed_epochs)
{
    printf("{\"schema\":\"crabc-mimalloc-native-churn-rss-smoke-fixture-v2\","
           "\"status\":\"failed\",\"seed\":%" PRIu64 ",\"cycles\":%u,"
           "\"completed_epochs\":%u,\"root_failure\":{"
           "\"domain\":\"%s\",\"exit_status\":68,"
           "\"epoch\":%u,\"epoch_seed\":%" PRIu64 ","
           "\"transition\":\"%s\",\"code\":%u,\"subject_index\":",
        seed, cycles, completed_epochs,
        failure_domain(state.fail_code == 0 ? 99 : state.fail_code),
        state.current_epoch, state.epoch_seed,
        state.failure_transition == NULL ? "unclassified_epoch_failure"
                                         : state.failure_transition,
        state.fail_code == 0 ? 99 : state.fail_code);
    if (state.failure_subject_index < 0)
        fputs("null", stdout);
    else
        printf("%d", state.failure_subject_index);
    printf("},\"state_auditor\":{\"status\":\"failed\","
           "\"scope\":\"production-general-churn\","
           "\"snapshot_count\":%" PRIu64 "}}\n",
        state.state_audit_snapshots);
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || text == end || *end != '\0')
        return 0;
    *value = parsed;
    return 1;
}

static int parse_unsigned(const char *text, unsigned *value)
{
    uint64_t parsed;

    if (!parse_u64(text, &parsed) || parsed == 0 || parsed > UINT32_MAX)
        return 0;
    *value = (unsigned)parsed;
    return 1;
}

int main(int argc, char **argv)
{
    uint64_t seed;
    uint64_t random_state;
    unsigned cycles;
    unsigned cycle;

    if (argc != 3 || !parse_u64(argv[1], &seed) || !parse_unsigned(argv[2], &cycles))
        return 64;
    random_state = seed == 0 ? UINT64_C(0x9e3779b97f4a7c15) : seed;
    if (pthread_barrier_init(&state.post_exit_release_barrier, NULL,
            POST_EXIT_RELEASER_COUNT + 1) != 0)
        return 74;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 65;
    state.rss_initial_bytes = read_rss_bytes();
    state.rss_high_water_bytes = state.rss_initial_bytes;
    state.rss_samples = 1;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 66;

    for (cycle = 0; cycle < cycles; cycle++) {
        if (!run_epoch(&random_state, cycle + 1)) {
            print_epoch_failure(seed, cycles, cycle);
            return 68;
        }
        if (!audit_quiescent_epoch(cycle + 1)) {
            print_epoch_failure(seed, cycles, cycle);
            return 68;
        }
    }
    if (pthread_barrier_destroy(&state.post_exit_release_barrier) != 0)
        return 74;

    if (pthread_mutex_lock(&state.lock) != 0)
        return 70;
    state.rss_final_bytes = read_rss_bytes();
    if (state.rss_final_bytes > state.rss_high_water_bytes)
        state.rss_high_water_bytes = state.rss_final_bytes;
    state.rss_samples += 1;
    if (state.failed || state.live_blocks != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return 71;
    }
    printf("{\"schema\":\"crabc-mimalloc-native-churn-rss-smoke-fixture-v2\","
           "\"status\":\"passed\",\"seed\":%" PRIu64 ",\"cycles\":%u,"
           "\"completed_epochs\":%u,"
           "\"first_fixture_epoch_seed\":%" PRIu64 ","
           "\"last_fixture_epoch_seed\":%" PRIu64 ","
           "\"thread_fanout\":{\"initial_threads\":1,"
           "\"owner_workers_per_epoch\":1,"
           "\"post_exit_independent_releasers_per_epoch\":4,"
           "\"worker_threads_per_epoch\":5,\"peak_threads\":5,"
           "\"worker_threads_created\":%u},"
           "\"owner_exits_with_live_blocks\":%" PRIu64 ","
           "\"post_owner_exit_concurrent_release\":{"
           "\"measurement_classification\":\"non-promotional-workload-liveness\","
           "\"performance_qualified\":false,"
           "\"independent_releasers_per_epoch\":4,"
           "\"completed_epochs\":%" PRIu64 ","
           "\"releasers_completed\":%" PRIu64 ","
           "\"successful_frees\":%" PRIu64 ","
           "\"retained_valid_frees\":%" PRIu64 ","
           "\"aborted_valid_frees\":%" PRIu64 ","
           "\"count_growth_after_warmup\":false,"
           "\"state_growth_after_warmup\":false},"
           "\"requested_bytes_total\":%" PRIu64 ","
           "\"requested_bytes_live_final\":%" PRIu64 ","
           "\"requested_bytes_live_high_water\":%" PRIu64 ","
           "\"usable_bytes_live_final\":%" PRIu64 ","
           "\"usable_bytes_live_high_water\":%" PRIu64 ","
           "\"live_blocks_final\":%" PRIu64 ","
           "\"live_blocks_high_water\":%" PRIu64 ","
           "\"rss_initial_bytes\":%" PRIu64 ","
           "\"rss_final_bytes\":%" PRIu64 ","
           "\"rss_high_water_bytes\":%" PRIu64 ","
           "\"rss_warm_quiescent_bytes\":%" PRIu64 ","
           "\"rss_last_quiescent_bytes\":%" PRIu64 ","
           "\"rss_samples\":%" PRIu64 ","
           "\"live_owner_registry_high_water_entries\":null,"
           "\"live_owner_registry_plateau_after_warmup\":null,"
           "\"post_exit_registry_high_water_entries\":null,"
           "\"post_exit_registry_plateau_after_warmup\":null,"
           "\"client_ledger_high_water_entries\":null,"
           "\"client_ledger_plateau_after_warmup\":null,"
           "\"allocator_metadata_high_water_bytes\":null,"
           "\"allocator_metadata_plateau_after_warmup\":null,"
           "\"page_map_registered_high_water_entries\":null,"
           "\"page_map_plateau_after_warmup\":null,"
           "\"arena_registry_high_water_entries\":null,"
           "\"arena_plateau_after_warmup\":null,"
           "\"abandoned_page_high_water_count\":null,"
           "\"abandoned_page_plateau_after_warmup\":null,"
           "\"tld_high_water_count\":null,"
           "\"tld_plateau_after_warmup\":null,"
           "\"theap_high_water_count\":null,"
           "\"theap_plateau_after_warmup\":null,"
           "\"allocator_metadata_observation\":\"not-exposed-by-production-shadow-c-api\","
           "\"state_auditor\":{\"status\":\"incomplete\","
           "\"scope\":\"production-general-churn\","
           "\"workload_liveness\":{\"status\":\"passed\","
           "\"snapshot_count\":%" PRIu64 ",\"warmup_epoch\":1,"
           "\"post_warm_snapshot_count\":%u,"
           "\"plateau_after_warmup\":true},"
           "\"post_owner_exit_concurrent_release\":{\"status\":\"passed\","
           "\"measurement_classification\":\"non-promotional-workload-liveness\","
           "\"performance_qualified\":false,"
           "\"snapshot_count\":%" PRIu64 ",\"warmup_epoch\":1,"
           "\"post_warm_snapshot_count\":%u,"
           "\"count_growth_after_warmup\":false,"
           "\"state_growth_after_warmup\":false},"
           "\"allocator_state\":{\"status\":\"unavailable\","
           "\"observation\":\"not-exposed-by-production-shadow-c-api\"}}}\n",
        seed, cycles, cycles, state.first_fixture_epoch_seed,
        state.last_fixture_epoch_seed, cycles * (1 + POST_EXIT_RELEASER_COUNT),
        state.owner_exits_with_live_blocks,
        state.post_exit_concurrent_release_epochs,
        state.post_exit_independent_releasers_completed,
        state.post_exit_concurrent_release_frees,
        state.post_exit_retained_valid_frees,
        state.post_exit_aborted_valid_frees,
        state.requested_total,
        state.requested_live, state.requested_live_high_water,
        state.usable_live, state.usable_live_high_water, state.live_blocks,
        state.live_blocks_high_water, state.rss_initial_bytes,
        state.rss_final_bytes, state.rss_high_water_bytes,
        state.rss_warm_quiescent_bytes, state.rss_last_quiescent_bytes,
        state.rss_samples,
        state.state_audit_snapshots, cycles - 1,
        state.state_audit_snapshots, cycles - 1);
    return pthread_mutex_unlock(&state.lock) == 0 ? 0 : 72;
}

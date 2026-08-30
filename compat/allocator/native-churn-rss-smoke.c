/*
 * Deterministic selected-shadow allocator smoke.
 *
 * This fixture deliberately uses only production C allocation entry points.
 * Each owner returns normally with six still-live blocks.  The initial thread
 * joins that owner and then validates and frees those exact C addresses; a
 * fresh helper frees one randomly selected live-owner handoff before the
 * owner resumes.  Neither path receives an allocator-private capability.
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
    HANDOFF_BLOCK_COUNT = 2,
    EXIT_BLOCK_COUNT = 6,
};

static const size_t handoff_requests[HANDOFF_BLOCK_COUNT] = { 37, 53 };
static const size_t exit_requests[EXIT_BLOCK_COUNT] = {
    37,
    1025,
    64 * 1024,
    128 * 1024,
    1024 * 1024,
    128 * 1024,
};

struct smoke_state {
    pthread_mutex_t lock;
    pthread_cond_t changed;
    unsigned char *handoff[HANDOFF_BLOCK_COUNT];
    unsigned char *exiting[EXIT_BLOCK_COUNT];
    uint64_t epoch_seed;
    unsigned handoff_slot;
    unsigned owner_ready;
    unsigned handoff_complete;
    unsigned failed;
    unsigned fail_code;
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
    uint64_t rss_samples;
    uint64_t owner_exits_with_live_blocks;
    uint64_t successful_cross_thread_handoffs;
    uint64_t post_exit_initial_thread_frees;
};

static struct smoke_state state = {
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .changed = PTHREAD_COND_INITIALIZER,
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

static void observe_rss_locked(void)
{
    uint64_t rss = read_rss_bytes();

    state.rss_samples += 1;
    if (rss > state.rss_high_water_bytes)
        state.rss_high_water_bytes = rss;
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

static void record_free(size_t request, size_t usable)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    if (state.requested_live < request || state.usable_live < usable
            || state.live_blocks == 0) {
        state.failed = 1;
        state.fail_code = 90;
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

static void mark_failed(unsigned code)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return;
    if (!state.failed) {
        state.failed = 1;
        state.fail_code = code;
    }
    (void)pthread_cond_broadcast(&state.changed);
    (void)pthread_mutex_unlock(&state.lock);
}

static void *owner_worker(void *opaque)
{
    unsigned char *local_handoff;
    unsigned index;

    (void)opaque;
    for (index = 0; index < HANDOFF_BLOCK_COUNT; index++) {
        state.handoff[index] = tracked_malloc(handoff_requests[index]);
        if (state.handoff[index] == NULL) {
            mark_failed(10 + index);
            return (void *)(uintptr_t)(10 + index);
        }
        fill_block(state.handoff[index], handoff_requests[index],
            tag_for(state.epoch_seed, index, 1));
    }

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)20;
    state.owner_ready = 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)21;
    }
    while (!state.handoff_complete && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)22;
        }
    }
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)23;
    }
    local_handoff = state.handoff[(state.handoff_slot + 1) % HANDOFF_BLOCK_COUNT];
    state.handoff[(state.handoff_slot + 1) % HANDOFF_BLOCK_COUNT] = NULL;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)24;

    if (!block_matches(local_handoff,
            handoff_requests[(state.handoff_slot + 1) % HANDOFF_BLOCK_COUNT],
            tag_for(state.epoch_seed,
                (state.handoff_slot + 1) % HANDOFF_BLOCK_COUNT, 1))
            || !tracked_free(local_handoff,
                handoff_requests[(state.handoff_slot + 1) % HANDOFF_BLOCK_COUNT])) {
        mark_failed(25);
        return (void *)(uintptr_t)25;
    }

    for (index = 0; index < EXIT_BLOCK_COUNT; index++) {
        if (index + 1 == EXIT_BLOCK_COUNT) {
            state.exiting[index] = tracked_aligned_allocation(128 * 1024,
                exit_requests[index]);
        } else {
            state.exiting[index] = tracked_malloc(exit_requests[index]);
        }
        if (state.exiting[index] == NULL) {
            mark_failed(30 + index);
            return (void *)(uintptr_t)(30 + index);
        }
        fill_block(state.exiting[index], exit_requests[index],
            tag_for(state.epoch_seed, index, 2));
    }

    return NULL;
}

static void *handoff_worker(void *opaque)
{
    unsigned char *handoff;
    unsigned slot;

    (void)opaque;
    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)40;
    while (!state.owner_ready && !state.failed) {
        if (pthread_cond_wait(&state.changed, &state.lock) != 0) {
            (void)pthread_mutex_unlock(&state.lock);
            return (void *)(uintptr_t)41;
        }
    }
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)42;
    }
    slot = state.handoff_slot;
    handoff = state.handoff[slot];
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)43;

    if (!block_matches(handoff, handoff_requests[slot],
            tag_for(state.epoch_seed, slot, 1))
            || !tracked_free(handoff, handoff_requests[slot])) {
        mark_failed(44);
        return (void *)(uintptr_t)44;
    }

    if (pthread_mutex_lock(&state.lock) != 0)
        return (void *)(uintptr_t)45;
    state.handoff[slot] = NULL;
    state.handoff_complete = 1;
    state.successful_cross_thread_handoffs += 1;
    if (pthread_cond_broadcast(&state.changed) != 0) {
        (void)pthread_mutex_unlock(&state.lock);
        return (void *)(uintptr_t)46;
    }
    if (pthread_mutex_unlock(&state.lock) != 0)
        return (void *)(uintptr_t)47;
    return NULL;
}

static int prepare_epoch(uint64_t epoch_seed)
{
    if (pthread_mutex_lock(&state.lock) != 0)
        return 0;
    if (state.live_blocks != 1) {
        state.failed = 1;
        state.fail_code = 50;
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    memset(state.handoff, 0, sizeof(state.handoff));
    memset(state.exiting, 0, sizeof(state.exiting));
    state.epoch_seed = epoch_seed;
    state.handoff_slot = (unsigned)(next_random(&epoch_seed) % HANDOFF_BLOCK_COUNT);
    state.owner_ready = 0;
    state.handoff_complete = 0;
    state.failed = 0;
    state.fail_code = 0;
    observe_rss_locked();
    return pthread_mutex_unlock(&state.lock) == 0;
}

static int free_exiting_blocks_from_initial_thread(uint64_t *random_state)
{
    unsigned order[EXIT_BLOCK_COUNT] = { 0, 1, 2, 3, 4, 5 };
    unsigned position;

    for (position = EXIT_BLOCK_COUNT; position > 1; position--) {
        unsigned other = (unsigned)(next_random(random_state) % position);
        unsigned temporary = order[position - 1];

        order[position - 1] = order[other];
        order[other] = temporary;
    }
    for (position = 0; position < EXIT_BLOCK_COUNT; position++) {
        unsigned index = order[position];
        unsigned char *block = state.exiting[index];

        if (!block_matches(block, exit_requests[index],
                tag_for(state.epoch_seed, index, 2))
                || !tracked_free(block, exit_requests[index]))
            return 0;
        state.exiting[index] = NULL;
        if (pthread_mutex_lock(&state.lock) != 0)
            return 0;
        state.post_exit_initial_thread_frees += 1;
        observe_rss_locked();
        if (pthread_mutex_unlock(&state.lock) != 0)
            return 0;
    }
    return 1;
}

static int run_epoch(uint64_t *random_state)
{
    pthread_t owner;
    pthread_t handoff;
    void *result = (void *)(uintptr_t)1;
    uint64_t epoch_seed = next_random(random_state);

    if (!prepare_epoch(epoch_seed))
        return 0;
    if (pthread_create(&owner, NULL, owner_worker, NULL) != 0)
        return 0;
    if (pthread_create(&handoff, NULL, handoff_worker, NULL) != 0) {
        mark_failed(60);
        (void)pthread_join(owner, &result);
        return 0;
    }
    if (pthread_join(handoff, &result) != 0 || result != NULL)
        return 0;
    result = (void *)(uintptr_t)2;
    if (pthread_join(owner, &result) != 0 || result != NULL)
        return 0;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 0;
    if (state.failed) {
        (void)pthread_mutex_unlock(&state.lock);
        return 0;
    }
    state.owner_exits_with_live_blocks += 1;
    observe_rss_locked();
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 0;
    return free_exiting_blocks_from_initial_thread(random_state);
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
    unsigned char *initial;

    if (argc != 3 || !parse_u64(argv[1], &seed) || !parse_unsigned(argv[2], &cycles))
        return 64;
    random_state = seed == 0 ? UINT64_C(0x9e3779b97f4a7c15) : seed;
    if (pthread_mutex_lock(&state.lock) != 0)
        return 65;
    state.rss_initial_bytes = read_rss_bytes();
    state.rss_high_water_bytes = state.rss_initial_bytes;
    state.rss_samples = 1;
    if (pthread_mutex_unlock(&state.lock) != 0)
        return 66;

    initial = tracked_malloc(79);
    if (initial == NULL)
        return 67;
    fill_block(initial, 79, tag_for(seed, 0, 3));
    for (cycle = 0; cycle < cycles; cycle++) {
        if (!run_epoch(&random_state))
            return 68;
    }
    if (!block_matches(initial, 79, tag_for(seed, 0, 3)) || !tracked_free(initial, 79))
        return 69;

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
    printf("{\"schema\":\"crabc-mimalloc-native-churn-rss-smoke-fixture-v1\","
           "\"seed\":%" PRIu64 ",\"cycles\":%u,"
           "\"owner_exits_with_live_blocks\":%" PRIu64 ","
           "\"successful_cross_thread_handoffs\":%" PRIu64 ","
           "\"post_exit_initial_thread_frees\":%" PRIu64 ","
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
           "\"rss_samples\":%" PRIu64 ","
           "\"allocator_metadata_high_water_bytes\":null,"
           "\"allocator_metadata_observation\":\"not-exposed-by-production-shadow-c-api\"}\n",
        seed, cycles, state.owner_exits_with_live_blocks,
        state.successful_cross_thread_handoffs,
        state.post_exit_initial_thread_frees, state.requested_total,
        state.requested_live, state.requested_live_high_water,
        state.usable_live, state.usable_live_high_water, state.live_blocks,
        state.live_blocks_high_water, state.rss_initial_bytes,
        state.rss_final_bytes, state.rss_high_water_bytes, state.rss_samples);
    return pthread_mutex_unlock(&state.lock) == 0 ? 0 : 72;
}

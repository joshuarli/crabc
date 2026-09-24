/*
 * Seeded, watchdog-bound allocator lifecycle soak.
 *
 * usage: soak SEED ROUNDS WORKERS CHECKPOINT_INTERVAL WATCHDOG_SECONDS
 *
 * Each round starts WORKERS independent pthread owners that run concurrently
 * with the initial thread. Every owner allocates across the small, medium,
 * large, and huge (> 4 MiB) size classes, frees locally, reallocates, and
 * exchanges blocks through a shared transfer table, so frees are remote and
 * multi-producer and ownership moves randomly. Owners finish at staggered
 * times while others still free their blocks, and leave live blocks behind
 * (exit before free), which later owners and the initial thread free or
 * reclaim. Each owner registers a cleanup handler and a TSD destructor that
 * both allocate and free, and exits by return, pthread_exit, or deferred
 * cancellation. A constructor allocates before main. The initial thread also
 * publishes one batch of small blocks per round that every worker frees
 * concurrently.
 *
 * Every block carries its size and a tag and is filled with a pattern that
 * is verified before free; any mismatch aborts. Every CHECKPOINT_INTERVAL
 * rounds the initial thread drains the table, so every block is freed, and
 * prints one checkpoint line (current RSS from /proc when mounted, -1
 * otherwise, and the getrusage high-water). With CRABC_NATIVE_ALLOCATOR_AUDIT the line adds
 * the allocator's process-wide PageMap/arena/metadata/TLD/Theap/abandoned
 * counts. The runner checks the counts plateau across equivalent churn.
 * Output is line-oriented `key=value` text; nothing depends on addresses.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#define CHECK(condition) do { if (!(condition)) { \
    fprintf(stderr, "soak: check failed at line %d: %s\n", __LINE__, #condition); abort(); } } while (0)

#ifdef CRABC_NATIVE_ALLOCATOR_AUDIT
struct process_audit {
    size_t page_map_registered_entries, page_map_published_submaps, arena_registry_count,
        live_thread_count, metadata_live_capabilities, metadata_high_water_capabilities,
        shared_later_theaps, main_heap_abandoned_pages;
};
struct owner_audit {
    size_t owner_installed, page_engine_active, attached_worker_owners, reclaimed_worker_descriptors;
};
int __crabc_x86_owned_allocator_process_test_audit(struct process_audit *);
int __crabc_x86_owned_allocator_worker_owner_test_audit(struct owner_audit *);
#endif

enum { SLOTS = 2048, LOCAL = 128, BATCH = 1024, BATCH_SIZE = 48, CLASSES = 5, MAX_WORKERS = 64 };
enum exit_mode { EXIT_RETURN, EXIT_PTHREAD_EXIT, EXIT_CANCEL, EXIT_MODES };

static const char *const class_names[CLASSES] = { "small", "medium", "large", "singleton", "huge" };

struct header {
    uint64_t tag;
    size_t size;
};

static _Atomic(struct header *) slots[SLOTS];
static _Atomic(void *) batch[BATCH];
static atomic_size_t class_counts[CLASSES];
static atomic_size_t allocations, frees, remote_frees, transfers, reallocations, aligned_allocations;
static atomic_size_t cleanup_runs, tsd_runs, exits[EXIT_MODES];
static atomic_size_t workers_running;
static pthread_key_t tsd_key;
static uint64_t soak_seed;
static struct header *constructor_block;

static uint64_t next(uint64_t *state) {
    uint64_t z = (*state += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static uint64_t below(uint64_t *state, uint64_t bound) { return next(state) % bound; }

static unsigned char pattern(uint64_t tag, size_t offset) {
    return (unsigned char)((tag >> (offset % 56)) ^ offset);
}

static void check_or_fill(unsigned char *bytes, uint64_t tag, size_t offset, int verify, size_t size) {
    if (!verify) { bytes[offset] = pattern(tag, offset); return; }
    if (bytes[offset] != pattern(tag, offset)) {
        fprintf(stderr, "soak: corruption tag=%llx offset=%zu size=%zu\n",
                (unsigned long long)tag, offset, size);
        abort();
    }
}

/* Fills or verifies the first and last 64 bytes and one byte per 4 KiB. */
static void visit_pattern(struct header *block, int verify) {
    unsigned char *bytes = (unsigned char *)block;
    size_t size = block->size, start = sizeof *block;
    size_t head_end = size < start + 64 ? size : start + 64;
    size_t tail_start = size > head_end + 64 ? size - 64 : head_end;
    for (size_t offset = start; offset < head_end; offset++) check_or_fill(bytes, block->tag, offset, verify, size);
    for (size_t offset = head_end; offset < tail_start; offset += 4096) check_or_fill(bytes, block->tag, offset, verify, size);
    for (size_t offset = tail_start; offset < size; offset++) check_or_fill(bytes, block->tag, offset, verify, size);
}

static size_t pick_size(uint64_t *state, size_t *class) {
    uint64_t choice = below(state, 1000);
    if (choice < 700) { *class = 0; return sizeof(struct header) + below(state, 1024); }
    if (choice < 900) { *class = 1; return 1024 + below(state, 64 * 1024); }
    if (choice < 985) { *class = 2; return 64 * 1024 + below(state, 448 * 1024); }
    if (choice < 998) { *class = 3; return 512 * 1024 + below(state, 3 * 1024 * 1024); }
    *class = 4;
    return 4 * 1024 * 1024 + below(state, 4 * 1024 * 1024);
}

static struct header *allocate_block(uint64_t *state) {
    size_t class;
    size_t size = pick_size(state, &class);
    struct header *block;
    if (below(state, 32) == 0) {
        void *aligned = NULL;
        size_t alignment = (size_t)64 << below(state, 7);
        CHECK(posix_memalign(&aligned, alignment, size) == 0);
        CHECK(((uintptr_t)aligned & (alignment - 1)) == 0);
        block = aligned;
        atomic_fetch_add(&aligned_allocations, 1);
    } else if (below(state, 8) == 0) {
        block = calloc(1, size);
        CHECK(block != NULL);
        for (size_t offset = 0; offset < size; offset += 4096) CHECK(((unsigned char *)block)[offset] == 0);
    } else {
        block = malloc(size);
        CHECK(block != NULL);
    }
    block->size = size;
    block->tag = next(state) | 1;
    visit_pattern(block, 0);
    atomic_fetch_add(&class_counts[class], 1);
    atomic_fetch_add(&allocations, 1);
    return block;
}

static void free_block(struct header *block, int remote) {
    if (block == NULL) return;
    visit_pattern(block, 1);
    free(block);
    atomic_fetch_add(&frees, 1);
    if (remote) atomic_fetch_add(&remote_frees, 1);
}

static struct header *reallocate_block(struct header *block, uint64_t *state) {
    size_t class;
    size_t size = pick_size(state, &class);
    visit_pattern(block, 1);
    size_t kept = block->size < size ? block->size : size;
    uint64_t tag = block->tag;
    struct header *moved = realloc(block, size);
    CHECK(moved != NULL);
    for (size_t offset = sizeof *moved; offset < kept && offset < 64; offset++) {
        CHECK(((unsigned char *)moved)[offset] == pattern(tag, offset));
    }
    moved->size = size;
    moved->tag = next(state) | 1;
    visit_pattern(moved, 0);
    atomic_fetch_add(&class_counts[class], 1);
    atomic_fetch_add(&reallocations, 1);
    return moved;
}

__attribute__((constructor)) static void allocate_before_main(void) {
    uint64_t state = 0x5eedc0de;
    constructor_block = allocate_block(&state);
}

struct worker {
    pthread_t thread;
    uint64_t state;
    size_t operations;
    enum exit_mode mode;
    sem_t cancel_ready;
    sem_t never_posted;
};

static void cleanup_handler(void *argument) {
    struct header *block = argument;
    uint64_t state = block->tag;
    free_block(allocate_block(&state), 0);
    free_block(block, 0);
    atomic_fetch_add(&cleanup_runs, 1);
}

static void tsd_destructor(void *argument) {
    struct header *block = argument;
    uint64_t state = block->tag;
    free_block(block, 0);
    /* A second destructor iteration: set again once, then release it. */
    if (state & 2) {
        struct header *again = allocate_block(&state);
        again->tag &= ~(uint64_t)2;
        visit_pattern(again, 0);
        CHECK(pthread_setspecific(tsd_key, again) == 0);
    }
    atomic_fetch_add(&tsd_runs, 1);
}

static void exchange_with_table(struct header **local, uint64_t *state) {
    struct header *previous = atomic_exchange(&slots[below(state, SLOTS)], *local);
    atomic_fetch_add(&transfers, 1);
    *local = previous;
}

static void worker_exit(struct worker *self) {
    if (self->mode == EXIT_PTHREAD_EXIT) pthread_exit(NULL);
    if (self->mode == EXIT_CANCEL) {
        CHECK(sem_post(&self->cancel_ready) == 0);
        for (;;) sem_wait(&self->never_posted);
    }
}

static void *worker_main(void *argument) {
    struct worker *self = argument;
    struct header *local[LOCAL] = { 0 };
    struct header *cleanup_block = allocate_block(&self->state);
    CHECK(pthread_setspecific(tsd_key, allocate_block(&self->state)) == 0);
    pthread_cleanup_push(cleanup_handler, cleanup_block);

    for (size_t index = 0; index < BATCH; index++) {
        if (below(&self->state, 4) != 0) continue;
        void *block = atomic_exchange(&batch[index], NULL);
        if (block != NULL) { free(block); atomic_fetch_add(&frees, 1); atomic_fetch_add(&remote_frees, 1); }
    }
    for (size_t operation = 0; operation < self->operations; operation++) {
        struct header **entry = &local[below(&self->state, LOCAL)];
        uint64_t choice = below(&self->state, 100);
        if (*entry == NULL) {
            *entry = allocate_block(&self->state);
        } else if (choice < 40) {
            free_block(*entry, 0);
            *entry = NULL;
        } else if (choice < 50) {
            *entry = reallocate_block(*entry, &self->state);
        } else if (choice < 80) {
            exchange_with_table(entry, &self->state);
        } else {
            /* Take a block from the table and free it: a remote free when
             * another owner, live or exited, allocated it. */
            free_block(atomic_exchange(&slots[below(&self->state, SLOTS)], NULL), 1);
        }
    }
    /* Leave about half the live blocks for others to free after this exit. */
    for (size_t index = 0; index < LOCAL; index++) {
        if (local[index] == NULL) continue;
        int exchanged = below(&self->state, 2) == 0;
        if (exchanged) exchange_with_table(&local[index], &self->state);
        free_block(local[index], exchanged);
        local[index] = NULL;
    }
    atomic_fetch_sub(&workers_running, 1);
    atomic_fetch_add(&exits[self->mode], 1);
    worker_exit(self);
    pthread_cleanup_pop(1);
    return NULL;
}

static void publish_batch(uint64_t *state) {
    for (size_t index = 0; index < BATCH; index++) {
        void *block = malloc(BATCH_SIZE);
        CHECK(block != NULL);
        memset(block, (int)below(state, 256), BATCH_SIZE);
        atomic_fetch_add(&allocations, 1);
        atomic_fetch_add(&class_counts[0], 1);
        void *previous = atomic_exchange(&batch[index], block);
        if (previous != NULL) { free(previous); atomic_fetch_add(&frees, 1); }
    }
}

static void drain(void) {
    for (size_t index = 0; index < SLOTS; index++) free_block(atomic_exchange(&slots[index], NULL), 1);
    for (size_t index = 0; index < BATCH; index++) {
        void *block = atomic_exchange(&batch[index], NULL);
        if (block != NULL) { free(block); atomic_fetch_add(&frees, 1); }
    }
}

static long resident_kib(void) {
    FILE *status = fopen("/proc/self/status", "r");
    char line[256];
    long value = -1;
    if (status == NULL) return -1;
    while (fgets(line, sizeof line, status) != NULL) {
        if (strncmp(line, "VmRSS:", 6) == 0) { value = strtol(line + 6, NULL, 10); break; }
    }
    fclose(status);
    return value;
}

static void checkpoint(unsigned round) {
    struct rusage usage;
    CHECK(getrusage(RUSAGE_SELF, &usage) == 0);
    printf("checkpoint round=%u allocations=%zu frees=%zu rss_kib=%ld max_rss_kib=%ld", round,
           atomic_load(&allocations), atomic_load(&frees), resident_kib(), usage.ru_maxrss);
#ifdef CRABC_NATIVE_ALLOCATOR_AUDIT
    struct process_audit process;
    struct owner_audit owner;
    CHECK(__crabc_x86_owned_allocator_process_test_audit(&process) == 0);
    CHECK(__crabc_x86_owned_allocator_worker_owner_test_audit(&owner) == 0);
    printf(" page_map_entries=%zu page_map_submaps=%zu arenas=%zu live_threads=%zu"
           " metadata_live=%zu metadata_high_water=%zu later_theaps=%zu abandoned_pages=%zu"
           " attached_workers=%zu reclaimed_descriptors=%zu",
           process.page_map_registered_entries, process.page_map_published_submaps,
           process.arena_registry_count, process.live_thread_count,
           process.metadata_live_capabilities, process.metadata_high_water_capabilities,
           process.shared_later_theaps, process.main_heap_abandoned_pages,
           owner.attached_worker_owners, owner.reclaimed_worker_descriptors);
#endif
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv) {
    CHECK(argc == 6);
    soak_seed = strtoull(argv[1], NULL, 0);
    unsigned rounds = (unsigned)strtoul(argv[2], NULL, 10);
    unsigned workers = (unsigned)strtoul(argv[3], NULL, 10);
    unsigned interval = (unsigned)strtoul(argv[4], NULL, 10);
    unsigned watchdog = (unsigned)strtoul(argv[5], NULL, 10);
    CHECK(rounds > 0 && workers > 0 && workers <= MAX_WORKERS && interval > 0 && watchdog > 0);
    alarm(watchdog);
    CHECK(pthread_key_create(&tsd_key, tsd_destructor) == 0);
    printf("soak seed=0x%016llx rounds=%u workers=%u checkpoint_interval=%u\n",
           (unsigned long long)soak_seed, rounds, workers, interval);

    uint64_t main_state = soak_seed;
    atomic_store(&slots[0], constructor_block);
    struct worker pool[MAX_WORKERS];
    for (unsigned round = 1; round <= rounds; round++) {
        publish_batch(&main_state);
        atomic_store(&workers_running, workers);
        for (unsigned index = 0; index < workers; index++) {
            struct worker *worker = &pool[index];
            worker->state = soak_seed ^ ((uint64_t)round << 32) ^ ((uint64_t)index * 0x2545f4914f6cdd1dull);
            worker->operations = 256 + below(&worker->state, 4096);
            worker->mode = (enum exit_mode)below(&worker->state, EXIT_MODES);
            CHECK(sem_init(&worker->cancel_ready, 0, 0) == 0);
            CHECK(sem_init(&worker->never_posted, 0, 0) == 0);
            CHECK(pthread_create(&worker->thread, NULL, worker_main, worker) == 0);
        }
        /* The initial thread keeps allocating, transferring, and freeing
         * while the owners run, then releases whatever they leave. */
        struct header *mine = NULL;
        while (atomic_load(&workers_running) != 0) {
            if (mine == NULL) mine = allocate_block(&main_state);
            else if (below(&main_state, 2) == 0) exchange_with_table(&mine, &main_state);
            else { free_block(mine, 0); mine = NULL; }
        }
        free_block(mine, 0);
        for (unsigned index = 0; index < workers; index++) {
            struct worker *worker = &pool[index];
            if (worker->mode == EXIT_CANCEL) {
                while (sem_wait(&worker->cancel_ready) != 0) CHECK(errno == EINTR);
                CHECK(pthread_cancel(worker->thread) == 0);
            }
            void *result = NULL;
            CHECK(pthread_join(worker->thread, &result) == 0);
            CHECK(worker->mode == EXIT_CANCEL ? result == PTHREAD_CANCELED : result == NULL);
            CHECK(sem_destroy(&worker->cancel_ready) == 0);
            CHECK(sem_destroy(&worker->never_posted) == 0);
        }
        /* Free about half the table now; the rest survives into later rounds. */
        for (size_t index = 0; index < SLOTS; index++) {
            if (below(&main_state, 2) == 0) free_block(atomic_exchange(&slots[index], NULL), 1);
        }
        if (round % interval == 0 || round == rounds) {
            drain();
            checkpoint(round);
        }
    }
    CHECK(atomic_load(&allocations) == atomic_load(&frees));
    size_t exited = atomic_load(&exits[EXIT_RETURN]) + atomic_load(&exits[EXIT_PTHREAD_EXIT])
        + atomic_load(&exits[EXIT_CANCEL]);
    printf("summary allocations=%zu frees=%zu remote_frees=%zu transfers=%zu reallocations=%zu"
           " aligned=%zu cleanup_runs=%zu tsd_runs=%zu exits_return=%zu exits_pthread_exit=%zu"
           " exits_cancel=%zu",
           atomic_load(&allocations), atomic_load(&frees), atomic_load(&remote_frees),
           atomic_load(&transfers), atomic_load(&reallocations), atomic_load(&aligned_allocations),
           atomic_load(&cleanup_runs), atomic_load(&tsd_runs), atomic_load(&exits[EXIT_RETURN]),
           atomic_load(&exits[EXIT_PTHREAD_EXIT]), atomic_load(&exits[EXIT_CANCEL]));
    for (size_t class = 0; class < CLASSES; class++) {
        printf(" class_%s=%zu", class_names[class], atomic_load(&class_counts[class]));
    }
    printf("\n");
    CHECK(exited == (size_t)rounds * workers);
    CHECK(atomic_load(&cleanup_runs) == exited);
    CHECK(atomic_load(&tsd_runs) >= exited);
    return 0;
}

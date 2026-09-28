/* A joined remote-free workload with quiescent medium-page observations.
 *
 * One owner touches sixteen full medium pages, then parks while an independent
 * worker frees all but one block per page. The coordinator scans after that
 * worker joins, after the owner frees the survivors, and after owner exit.
 * A one-byte pipe handshake keeps the process still for each external mapping
 * snapshot. No allocator operation occurs between the printed audit and ack.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum { EPOCHS = 4, PAGES_PER_EPOCH = 16, BLOCKS_PER_PAGE = 42,
       BLOCKS = PAGES_PER_EPOCH * BLOCKS_PER_PAGE, REQUEST = 10248 };

struct process_audit {
    size_t page_map_registered_entries, page_map_published_submaps, arena_registry_count,
        live_thread_count, metadata_live_capabilities, metadata_high_water_capabilities,
        shared_later_theaps, main_heap_abandoned_pages;
};

struct page_class_audit {
    size_t registered_slices;
    size_t small_empty_slices, small_used_slices;
    size_t medium_empty_slices, medium_used_slices;
    size_t large_empty_slices, large_used_slices;
    size_t singleton_empty_slices, singleton_used_slices;
    size_t unknown_kind_slices;
    size_t abandoned_slices, detached_slices, attached_slices;
    size_t nonprimary_slices;
    size_t medium_abandoned_slices, medium_detached_slices, medium_attached_slices;
    size_t medium_remote_pending_slices, medium_reusable_slices, medium_retired_slices;
};

extern int __crabc_x86_owned_allocator_process_test_audit(struct process_audit *output);
extern int __crabc_x86_owned_allocator_page_class_test_audit(struct page_class_audit *output);

static void *blocks[BLOCKS];
static sem_t owner_ready;
static sem_t owner_resume;
static sem_t owner_cleared;
static sem_t owner_exit;

static void fail(const char *reason) {
    (void)write(STDERR_FILENO, reason, strlen(reason));
    (void)write(STDERR_FILENO, "\n", 1);
    _exit(91);
}

static void wait_sem(sem_t *semaphore) {
    while (sem_wait(semaphore) != 0) {
        if (errno != EINTR) fail("semaphore wait failed");
    }
}

static void read_proc(const char *path, char *data, size_t capacity) {
    int descriptor = open(path, O_RDONLY);
    if (descriptor < 0) fail("cannot open process status");
    ssize_t length = read(descriptor, data, capacity - 1);
    (void)close(descriptor);
    if (length <= 0 || length >= (ssize_t)(capacity - 1)) fail("incomplete process status");
    data[length] = '\0';
}

static long proc_value(char *data, const char *key) {
    size_t key_length = strlen(key);
    char *line = data;
    while (*line != '\0') {
        if (strncmp(line, key, key_length) == 0 && line[key_length] == ':') {
            return strtol(line + key_length + 1, NULL, 10);
        }
        char *end = strchr(line, '\n');
        if (end == NULL) break;
        line = end + 1;
    }
    fail("missing process status field");
    return -1;
}

static void write_all(const char *data, size_t size) {
    while (size != 0) {
        ssize_t written = write(STDOUT_FILENO, data, size);
        if (written <= 0) fail("snapshot output failed");
        data += written;
        size -= (size_t)written;
    }
}

static void snapshot(unsigned epoch, const char *phase) {
    struct process_audit process;
    struct page_class_audit classes;
    if (__crabc_x86_owned_allocator_process_test_audit(&process) != 0)
        fail("process PageMap audit failed");
    if (__crabc_x86_owned_allocator_page_class_test_audit(&classes) != 0)
        fail("class PageMap audit failed");
    if (process.page_map_registered_entries != classes.registered_slices)
        fail("PageMap class count mismatch");
    size_t kind_total = classes.small_empty_slices + classes.small_used_slices
        + classes.medium_empty_slices + classes.medium_used_slices
        + classes.large_empty_slices + classes.large_used_slices
        + classes.singleton_empty_slices + classes.singleton_used_slices
        + classes.unknown_kind_slices;
    if (kind_total != classes.registered_slices) fail("PageMap class partition failed");

    char status[4096], rollup[4096];
    read_proc("/proc/self/status", status, sizeof status);
    read_proc("/proc/self/smaps_rollup", rollup, sizeof rollup);
    long rss = proc_value(status, "VmRSS");
    long hwm = proc_value(status, "VmHWM");
    long rollup_rss = proc_value(rollup, "Rss");
    long anonymous = proc_value(rollup, "Anonymous");
    long huge = proc_value(rollup, "AnonHugePages");
    long referenced = proc_value(rollup, "Referenced");
    char line[1024];
    int length = snprintf(line, sizeof line,
        "snapshot epoch=%u phase=%s rss_kib=%ld hwm_kib=%ld rollup_rss_kib=%ld"
        " anonymous_kib=%ld anon_huge_kib=%ld referenced_kib=%ld"
        " page_map_entries=%zu page_map_submaps=%zu"
        " small_empty=%zu small_used=%zu medium_empty=%zu medium_used=%zu"
        " large_empty=%zu large_used=%zu singleton_empty=%zu singleton_used=%zu"
        " medium_abandoned=%zu medium_detached=%zu medium_attached=%zu"
        " medium_remote_pending=%zu medium_reusable=%zu medium_retired=%zu\n",
        epoch, phase, rss, hwm, rollup_rss, anonymous, huge, referenced,
        process.page_map_registered_entries, process.page_map_published_submaps,
        classes.small_empty_slices, classes.small_used_slices,
        classes.medium_empty_slices, classes.medium_used_slices,
        classes.large_empty_slices, classes.large_used_slices,
        classes.singleton_empty_slices, classes.singleton_used_slices,
        classes.medium_abandoned_slices, classes.medium_detached_slices,
        classes.medium_attached_slices, classes.medium_remote_pending_slices,
        classes.medium_reusable_slices, classes.medium_retired_slices);
    if (length <= 0 || length >= (int)sizeof line) fail("snapshot line overflow");
    write_all(line, (size_t)length);
    char acknowledgement;
    if (read(STDIN_FILENO, &acknowledgement, 1) != 1 || acknowledgement != 'x') {
        fail("missing mapping snapshot acknowledgement");
    }
}

static void *owner_main(void *unused) {
    (void)unused;
    for (size_t index = 0; index < BLOCKS; index++) {
        blocks[index] = malloc(REQUEST);
        if (blocks[index] == NULL) fail("medium allocation failed");
        memset(blocks[index], (int)(index & 255), REQUEST);
    }
    if (sem_post(&owner_ready) != 0) fail("owner ready failed");
    wait_sem(&owner_resume);
    for (size_t index = BLOCKS_PER_PAGE - 1; index < BLOCKS; index += BLOCKS_PER_PAGE) {
        free(blocks[index]);
        blocks[index] = NULL;
    }
    if (sem_post(&owner_cleared) != 0) fail("owner cleared failed");
    wait_sem(&owner_exit);
    return NULL;
}

static void *remote_main(void *unused) {
    (void)unused;
    for (size_t index = 0; index < BLOCKS; index++) {
        unsigned char *block = blocks[index];
        if (block[0] != (unsigned char)(index & 255) ||
            block[REQUEST - 1] != (unsigned char)(index & 255)) {
            fail("medium block changed before remote free");
        }
        if (index % BLOCKS_PER_PAGE != BLOCKS_PER_PAGE - 1) {
            free(block);
            blocks[index] = NULL;
        }
    }
    return NULL;
}

int main(void) {
    if (sem_init(&owner_ready, 0, 0) != 0 || sem_init(&owner_resume, 0, 0) != 0 ||
        sem_init(&owner_cleared, 0, 0) != 0 || sem_init(&owner_exit, 0, 0) != 0) {
        fail("semaphore initialization failed");
    }
    void *warm = malloc(8);
    if (warm == NULL) fail("allocator warmup failed");
    *(volatile unsigned char *)warm = 7;
    free(warm);
    snapshot(0, "baseline");
    for (unsigned epoch = 1; epoch <= EPOCHS; epoch++) {
        pthread_t owner, remote;
        if (pthread_create(&owner, NULL, owner_main, NULL) != 0) fail("owner start failed");
        wait_sem(&owner_ready);
        snapshot(epoch, "allocated");
        if (pthread_create(&remote, NULL, remote_main, NULL) != 0) fail("remote start failed");
        if (pthread_join(remote, NULL) != 0) fail("remote join failed");
        snapshot(epoch, "remote_joined");
        if (sem_post(&owner_resume) != 0) fail("owner resume failed");
        wait_sem(&owner_cleared);
        snapshot(epoch, "owner_cleared");
        if (sem_post(&owner_exit) != 0) fail("owner exit failed");
        if (pthread_join(owner, NULL) != 0) fail("owner join failed");
        snapshot(epoch, "owner_joined");
        struct timespec delay = { .tv_sec = 0, .tv_nsec = 20000000 };
        if (nanosleep(&delay, NULL) != 0) fail("settle wait failed");
        snapshot(epoch, "settled_20ms");
    }
    if (sem_destroy(&owner_ready) != 0 || sem_destroy(&owner_resume) != 0 ||
        sem_destroy(&owner_cleared) != 0 || sem_destroy(&owner_exit) != 0) {
        fail("semaphore destruction failed");
    }
    static const char done[] = "done epochs=4 blocks_per_epoch=672 request=10248\n";
    write_all(done, sizeof done - 1);
    return 0;
}

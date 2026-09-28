/* Observe the first medium allocation and the first new-page transition.
 * The same client is linked against pinned C and the owned native allocator.
 * A scalar process audit precedes each class scan while no other allocator
 * operation is active; the write to stdout occurs after both reads.
 */
#define _POSIX_C_SOURCE 200809L

#include <malloc.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum { REQUEST = 65536, BLOCKS = 10 };
enum { ALIGNMENT_SAMPLES = 16 };
static const size_t alignment_sizes[] = {1, 8, 9, 15, 16, 17, 24, 32, 10248, 65536};

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

static void fail(const char *reason) {
    (void)write(STDERR_FILENO, reason, strlen(reason));
    (void)write(STDERR_FILENO, "\n", 1);
    _exit(91);
}

static void emit(const char *line, size_t length) {
    while (length != 0) {
        ssize_t written = write(STDOUT_FILENO, line, length);
        if (written <= 0) fail("trace write failed");
        line += written;
        length -= (size_t)written;
    }
}

static void trace(void) {
    void *blocks[BLOCKS];
    for (size_t index = 0; index < BLOCKS; index++) {
        blocks[index] = malloc(REQUEST);
        if (blocks[index] == NULL) fail("medium allocation failed");
        *(volatile unsigned char *)blocks[index] = (unsigned char)index;
        size_t usable = malloc_usable_size(blocks[index]);
        struct process_audit process;
        struct page_class_audit classes;
        if (__crabc_x86_owned_allocator_process_test_audit(&process) != 0 ||
            __crabc_x86_owned_allocator_page_class_test_audit(&classes) != 0 ||
            process.page_map_registered_entries != classes.registered_slices) {
            fail("PageMap audit failed");
        }
        char line[256];
        int length = snprintf(line, sizeof line,
            "trace index=%zu request=%u usable=%zu entries=%zu medium_used=%zu"
            " medium_abandoned=%zu\n",
            index, REQUEST, usable, process.page_map_registered_entries,
            classes.medium_used_slices, classes.medium_abandoned_slices);
        if (length <= 0 || length >= (int)sizeof line) fail("trace line overflow");
        emit(line, (size_t)length);
    }
    for (size_t index = 0; index < BLOCKS; index++) free(blocks[index]);
}

static void *worker(void *unused) {
    (void)unused;
    trace();
    return NULL;
}

static void trace_alignment(void) {
    for (size_t size_index = 0;
         size_index < sizeof alignment_sizes / sizeof alignment_sizes[0]; size_index++) {
        size_t size = alignment_sizes[size_index];
        void *blocks[ALIGNMENT_SAMPLES];
        size_t aligned16 = 0, minimum = SIZE_MAX, maximum = 0;
        for (size_t index = 0; index < ALIGNMENT_SAMPLES; index++) {
            blocks[index] = malloc(size);
            if (blocks[index] == NULL) fail("alignment allocation failed");
            *(volatile unsigned char *)blocks[index] = (unsigned char)index;
            aligned16 += ((uintptr_t)blocks[index] & 15) == 0;
            size_t usable = malloc_usable_size(blocks[index]);
            if (usable < minimum) minimum = usable;
            if (usable > maximum) maximum = usable;
        }
        char line[160];
        int length = snprintf(line, sizeof line,
            "alignment size=%zu aligned16=%zu usable_min=%zu usable_max=%zu\n",
            size, aligned16, minimum, maximum);
        if (length <= 0 || length >= (int)sizeof line) fail("alignment line overflow");
        emit(line, (size_t)length);
        for (size_t index = 0; index < ALIGNMENT_SAMPLES; index++) free(blocks[index]);
    }
    static const char done[] = "done sizes=10 samples_per_size=16\n";
    emit(done, sizeof done - 1);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "alignment") == 0) {
        trace_alignment();
        return 0;
    } else if (argc == 1) {
        trace();
    } else if (argc == 2 && strcmp(argv[1], "worker") == 0) {
        pthread_t owner;
        if (pthread_create(&owner, NULL, worker, NULL) != 0 ||
            pthread_join(owner, NULL) != 0) fail("worker lifecycle failed");
    } else {
        fail("unknown trace mode");
    }
    static const char done[] = "done blocks=10 request=65536\n";
    emit(done, sizeof done - 1);
    return 0;
}

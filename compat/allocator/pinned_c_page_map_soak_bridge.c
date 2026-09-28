/* Read the pinned allocator's registered slice image after all soak workers
 * have joined. The unchanged workload calls this bridge only at checkpoints.
 * Other native allocator audit fields have no C equivalent here. */
#include <stddef.h>
#include <stdint.h>

#include "mimalloc/internal.h"

struct process_audit {
    size_t page_map_registered_entries, page_map_published_submaps, arena_registry_count,
        live_thread_count, metadata_live_capabilities, metadata_high_water_capabilities,
        shared_later_theaps, main_heap_abandoned_pages;
};

struct owner_audit {
    size_t owner_installed, page_engine_active, attached_worker_owners, reclaimed_worker_descriptors;
};

int __crabc_x86_owned_allocator_process_test_audit(struct process_audit *output) {
    if (output == NULL) return -1;
    const mi_page_map_t *map = _mi_page_map();
    if (map == NULL || map->reserved_size < sizeof(mi_page_map_t)) return -1;
    const size_t bound = 1 + (map->reserved_size - sizeof(mi_page_map_t)) / sizeof(mi_submap_t);
    const size_t committed = mi_atomic_load_acquire(&map->committed_count);
    if (committed > bound) return -1;

    size_t registered = 0;
    size_t published = 0;
    for (size_t i = 0; i < committed; i++) {
        mi_submap_t submap = _mi_page_map_at(map, i);
        if (submap == NULL) continue;
        published++;
        for (size_t j = 0; j < MI_PAGE_MAP_SUB_COUNT; j++) {
            if (submap[j] != NULL) registered++;
        }
    }
    *output = (struct process_audit) {
        registered, published, SIZE_MAX, SIZE_MAX, SIZE_MAX, SIZE_MAX, SIZE_MAX, SIZE_MAX
    };
    return 0;
}

int __crabc_x86_owned_allocator_worker_owner_test_audit(struct owner_audit *output) {
    if (output == NULL) return -1;
    *output = (struct owner_audit) { SIZE_MAX, SIZE_MAX, SIZE_MAX, SIZE_MAX };
    return 0;
}

/* The class snapshot belongs to the native allocator diagnostic. Refuse it
 * explicitly if a caller accidentally enables that separate observation. */
int __crabc_x86_owned_allocator_page_class_test_audit(void *output) {
    (void)output;
    return -1;
}

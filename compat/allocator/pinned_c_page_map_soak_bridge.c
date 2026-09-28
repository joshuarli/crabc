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

/* Every bucket counts registered slices, so one multi-slice page contributes
 * once per mapped slot. These fields match the joined native page image. */
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

static void classify_registered_slice(struct page_class_audit *audit, const mi_page_t *page) {
    const size_t block_size = page->block_size;
    const bool used = page->used != 0;
    const bool medium = block_size > MI_SMALL_MAX_OBJ_SIZE && block_size <= MI_MEDIUM_MAX_OBJ_SIZE;
    if (block_size == 0) audit->unknown_kind_slices++;
    else if (block_size <= MI_SMALL_MAX_OBJ_SIZE) {
        if (used) audit->small_used_slices++;
        else audit->small_empty_slices++;
    }
    else if (medium) {
        if (used) audit->medium_used_slices++;
        else audit->medium_empty_slices++;
    }
    else if (block_size <= MI_LARGE_MAX_OBJ_SIZE) {
        if (used) audit->large_used_slices++;
        else audit->large_empty_slices++;
    }
    else {
        if (used) audit->singleton_used_slices++;
        else audit->singleton_empty_slices++;
    }

    const mi_threadid_t owner = mi_page_thread_id(page);
    if (owner == MI_THREADID_ABANDONED || owner == MI_THREADID_ABANDONED_MAPPED) {
        audit->abandoned_slices++;
        if (medium) audit->medium_abandoned_slices++;
    }
    else if (owner == MI_THREADID_DETACHED) {
        audit->detached_slices++;
        if (medium) audit->medium_detached_slices++;
    }
    else {
        audit->attached_slices++;
        if (medium) audit->medium_attached_slices++;
    }
    if (medium) {
        if (mi_tf_block(mi_atomic_load_acquire(&page->xthread_free)) != NULL) {
            audit->medium_remote_pending_slices++;
        }
        if (page->free != NULL || page->local_free != NULL) audit->medium_reusable_slices++;
        if (page->retire_expire != 0) audit->medium_retired_slices++;
    }
#if MI_PAGE_META_IS_ALIGNED
    if (mi_atomic_load_acquire(&page->self) != page) audit->nonprimary_slices++;
#endif
}

/* The caller has joined every worker and excludes allocation while this
 * scan reads source-plain page fields and the two atomic ownership heads. */
static int scan_page_map(size_t *registered_out, size_t *published_out,
                         struct page_class_audit *classes) {
    const mi_page_map_t *map = _mi_page_map();
    if (map == NULL || map->reserved_size < sizeof(mi_page_map_t)) return -1;
    const size_t bound = 1 + (map->reserved_size - sizeof(mi_page_map_t)) / sizeof(mi_submap_t);
    const size_t committed = mi_atomic_load_acquire(&map->committed_count);
    if (committed > bound) return -1;

    if (classes != NULL) *classes = (struct page_class_audit) { 0 };
    size_t registered = 0;
    size_t published = 0;
    for (size_t i = 0; i < committed; i++) {
        mi_submap_t submap = _mi_page_map_at(map, i);
        if (submap == NULL) continue;
        published++;
        for (size_t j = 0; j < MI_PAGE_MAP_SUB_COUNT; j++) {
            mi_page_t *page = submap[j];
            if (page == NULL) continue;
            registered++;
            if (classes != NULL) classify_registered_slice(classes, page);
        }
    }
    if (classes != NULL) classes->registered_slices = registered;
    *registered_out = registered;
    *published_out = published;
    return 0;
}

int __crabc_x86_owned_allocator_process_test_audit(struct process_audit *output) {
    if (output == NULL) return -1;
    size_t registered, published;
    if (scan_page_map(&registered, &published, NULL) != 0) return -1;
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

int __crabc_x86_owned_allocator_page_class_test_audit(struct page_class_audit *output) {
    if (output == NULL) return -1;
    size_t registered, published;
    return scan_page_map(&registered, &published, output);
}

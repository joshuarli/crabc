/*
 * SPDX-License-Identifier: MIT
 *
 * Test-only C evidence ABI for crabc-mimalloc's hidden ticket-zero runtime
 * page owner. This header is never installed and its deliberately prefixed
 * functions are not a libc allocation interface or a backend switch.
 */
#ifndef CRABC_MIMALLOC_RUNTIME_TICKET_ZERO_TEST_H
#define CRABC_MIMALLOC_RUNTIME_TICKET_ZERO_TEST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * `page_size` must be the original thread's nonzero Linux `AT_PAGESZ` value.
 * The process may initialize exactly once. There is no shutdown: this source-
 * shaped owner intentionally retains its page state until process exit.
 */
int crabc_ticket_zero_test_init(size_t page_size);

/*
 * A read-only scalar lifecycle snapshot for the bounded pthread soak. It
 * carries no allocation pointer, page identity, map root, route, allocator,
 * or release capability. The original initializing thread may request it only
 * after every worker in the current schedule has joined. Success preserves
 * errno and returns zero; a nonquiescent or inactive runtime returns -1.
 */
struct crabc_ticket_zero_test_lifecycle_audit {
    size_t process_active;
    size_t page_owner_ready;
    size_t page_map_registered_entry_count;
    size_t page_map_published_submap_count;
    size_t page_map_lazy_submap_allocation_count;
    size_t arena_registry_count;
    size_t live_thread_count;
    size_t metadata_live_capability_count;
    size_t metadata_high_water_capability_count;
    size_t shared_later_theap_count;
    size_t main_heap_abandoned_page_count;
    size_t main_heap_os_abandoned_pages_empty;
};

int crabc_ticket_zero_test_lifecycle_audit(struct crabc_ticket_zero_test_lifecycle_audit *audit);

/*
 * Every call must be serialized on the original initializing thread. A
 * non-null allocation is private to this adapter and must reach its matching
 * free/realloc exactly once; foreign, stale, cross-thread, and aliased use is
 * outside this test ABI. `free(NULL)` is a no-op.
 */
void *crabc_ticket_zero_test_malloc(size_t size);
void *crabc_ticket_zero_test_zalloc(size_t size);
void *crabc_ticket_zero_test_realloc(void *p, size_t size);
void crabc_ticket_zero_test_free(void *p);

/*
 * After the original thread has freed every adapter allocation, one fresh
 * pthread may call this to attach, allocate and free one scoped later-main
 * page-engine block, and complete its normal teardown. It accepts no pointer
 * and never routes malloc/free. On success it returns 0 and preserves errno;
 * on failure it returns -1 with errno set. It is not valid on the original
 * thread, a reused worker, or while ticket-zero allocations are live.
 */
int crabc_ticket_zero_test_worker_roundtrip(size_t size);

/*
 * After the original thread has freed every adapter allocation, one fresh
 * pthread may call this to retain one page engine through a pointer-private
 * mixed local workload. That workload keeps multiple allocations live across
 * small, medium, large, singleton, and multi-page singleton requests, checks
 * their contents, locally reuses freed small and medium blocks, frees every
 * block, and completes normal teardown. It accepts and returns no pointer.
 * On success it returns 0 and preserves errno; on failure it returns -1 with
 * errno set. It is not valid on the original thread, a reused worker, or while
 * ticket-zero allocations are live.
 */
int crabc_ticket_zero_test_worker_mixed_roundtrip(void);

/*
 * After the original thread has freed every adapter allocation, one fresh
 * pthread may call this to become owner A of a full small-page workload. The
 * adapter creates and joins two private publisher pthreads B/C; neither
 * receives an allocation pointer and each publishes only an opaque logical
 * remote-free token. A then collects both publications, reuses both exact
 * blocks while still live, frees every remaining block, and completes normal
 * teardown. The C caller accepts and returns no pointer. On success it returns
 * 0 and preserves errno; on failure it returns -1 with errno set. It is not
 * valid on the original thread, a reused worker, or while ticket-zero
 * allocations are live.
 */
int crabc_ticket_zero_test_worker_remote_free_roundtrip(void);

#ifdef __cplusplus
}
#endif

#endif

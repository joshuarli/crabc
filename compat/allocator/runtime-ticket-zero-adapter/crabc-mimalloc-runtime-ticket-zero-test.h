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

/*
 * After the original thread has freed every adapter allocation, one fresh
 * pthread may become mixed-page owner A. The adapter fills two distinct full
 * medium pages, a distinct one-client large page, one live arena singleton,
 * and one live OS-aligned singleton. Joined B/C receive opaque pre-exit
 * remote-free capabilities for the first medium and the large page. Source
 * collection runs through A's ordinary post-destructor runtime finish: it
 * resumes A's private TLS page owner, maps the first medium, releases the
 * now-empty large page, and
 * leaves the unchanged second medium source-unmapped. A second joined fresh B
 * receives only an opaque post-exit route, retaining the arena singleton's
 * PageMap-only terminal tail and the OS singleton's private-list/clipped-map
 * tail. On B's first direct free of the unchanged full medium, B claims the
 * source low owner bit and gives joined C only one scoped producer for a
 * distinct private client from that same page. C atomically publishes it and
 * returns before B's existing collector consumes both clients. B then releases
 * its remaining private clients and completes its own no-page runtime
 * attachment. The runtime releases A's worker admission only when that
 * completed B lifecycle returns the terminal proof. The C caller neither
 * receives a client pointer nor invokes a generic worker finalizer.
 * On success this returns 0 and preserves errno; on failure it returns -1
 * with errno set.
 */
int crabc_ticket_zero_test_worker_owner_exit_roundtrip(void);

/*
 * After the original thread has freed every adapter allocation, one fresh
 * pthread may become owner A of an initially nonfull mapped-regular page with
 * one returned local free block. Successive calls alternate the existing
 * sole-medium aggregate result and direct-small source drain; both enter the
 * same ordinary runtime finish and give B only an opaque reclamation route.
 * B attaches normally, adopts and uses A's exact page, frees all private
 * clients, and completes its page lifecycle before the route permits A's
 * admission claim to release. The C caller receives no client address, route,
 * PageMap, or generic finalizer authority. On success this returns 0 and
 * preserves errno; on failure it returns -1 with errno set.
 */
int crabc_ticket_zero_test_worker_owner_exit_reclaim_roundtrip(void);

#ifdef __cplusplus
}
#endif

#endif

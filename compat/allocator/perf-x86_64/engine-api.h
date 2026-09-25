/*
 * SPDX-License-Identifier: MIT
 *
 * Opaque, backend-neutral engine boundary for the native x86-64 allocator
 * performance matrix (`compat/allocator/perf_engine_x86_64.py`).
 *
 * One C workload source (`engine-fixture.c`) calls only these functions.  Each
 * lane links exactly one separately compiled backend:
 *
 *   - `engine-c-backend.c` forwards to the pinned mimalloc v3.5.0 C source;
 *   - `engine-rust-backend.rs` forwards to crabc-mimalloc's persistent
 *     per-thread source owners through its hidden `__crabc_runtime` friend
 *     boundary (the same entry points crabc-libc's native shadow selects).
 *
 * Neither backend is visible to the fixture's optimizer: the workload cannot
 * inline, hoist, or specialize allocator code, so both lanes pay one ordinary
 * external call per operation.  This header is neither a public mimalloc
 * header nor a crabc libc ABI and is never installed.
 */
#ifndef CRABC_ALLOCATOR_PERF_ENGINE_X86_64_API_H
#define CRABC_ALLOCATOR_PERF_ENGINE_X86_64_API_H

#include <stddef.h>

/* Called exactly once on the initial thread before any other entry. */
int crabc_allocator_engine_process_init(void);

/*
 * Called by every non-initial thread before its first allocator operation,
 * and after its last one respectively.  A thread that has called
 * `thread_done` performs no further allocator operation.
 */
int crabc_allocator_engine_thread_init(void);
int crabc_allocator_engine_thread_done(void);

/*
 * The C allocation contract of the selected libc boundary: malloc/calloc/
 * realloc results satisfy the platform's 16-byte fundamental alignment where
 * the backend's own C ABI does.  `free(NULL)` is a no-op.  A backend failure
 * that cannot be reported through a null result terminates the process.
 */
void *crabc_allocator_engine_malloc(size_t size);
void crabc_allocator_engine_free(void *block);
void *crabc_allocator_engine_calloc(size_t count, size_t size);
void *crabc_allocator_engine_realloc(void *block, size_t size);
void *crabc_allocator_engine_aligned(size_t alignment, size_t size);
size_t crabc_allocator_engine_usable_size(const void *block);

/*
 * First-class heaps and child subprocesses, measured only by the
 * `heap_destroy` and `subproc_destroy` workloads.  These entries are
 * optional: the fixture declares them weak, and a backend that does not
 * define them makes those two workloads fail as unavailable rather than
 * breaking every other row.
 *
 *   heap_new / heap_malloc / heap_destroy are `mi_heap_new`,
 *   `mi_heap_malloc` and `mi_heap_destroy` (which frees every live block).
 *   subproc_new creates a child subprocess; subproc_add_current_thread is
 *   called by a fresh thread *instead of* thread_init, before any
 *   allocation, and makes that thread a member (`mi_subproc_add_current_thread`);
 *   the thread still calls thread_done.  subproc_destroy, called after every
 *   member thread has finished, releases the subprocess with its remaining
 *   heaps, pages and arenas (`mi_subproc_destroy`).
 */
typedef struct crabc_allocator_engine_heap crabc_allocator_engine_heap;
typedef struct crabc_allocator_engine_subproc crabc_allocator_engine_subproc;

crabc_allocator_engine_heap *crabc_allocator_engine_heap_new(void);
void *crabc_allocator_engine_heap_malloc(crabc_allocator_engine_heap *heap, size_t size);
void crabc_allocator_engine_heap_destroy(crabc_allocator_engine_heap *heap);
crabc_allocator_engine_subproc *crabc_allocator_engine_subproc_new(void);
int crabc_allocator_engine_subproc_add_current_thread(crabc_allocator_engine_subproc *subproc);
void crabc_allocator_engine_subproc_destroy(crabc_allocator_engine_subproc *subproc);

#endif

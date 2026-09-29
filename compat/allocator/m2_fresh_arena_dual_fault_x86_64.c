/* A fresh arena metadata fault can escape its map while a later claim succeeds. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

static mi_subproc_t owner;
static mi_heap_t heap;
static bool fail_metadata;
static bool fail_cleanup;
static unsigned protect_calls;
static void* protected_address;
static size_t protected_length;
static int protected_flags;
static unsigned selected_unmaps;
static void* escaped_address;
static size_t escaped_length;
static unsigned warning_fragments;
static unsigned warning_bodies;
static unsigned warning_order;
static int64_t warning_reserved[5];
static int64_t warning_committed[5];
static int64_t warning_commit_calls[5];

int __real_mprotect(void*, size_t, int);
int __real_munmap(void*, size_t);
int __wrap_mprotect(void* address, size_t length, int protection) {
  if (fail_metadata && protection == (PROT_READ | PROT_WRITE)) {
    fail_metadata = false;
    protect_calls++;
    protected_address = address;
    protected_length = length;
    protected_flags = protection;
    errno = ENOMEM;
    return -1;
  }
  return __real_mprotect(address, length, protection);
}

int __wrap_munmap(void* address, size_t length) {
  if (fail_cleanup && protected_address != NULL) {
    fail_cleanup = false;
    selected_unmaps++;
    escaped_address = address;
    escaped_length = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(address, length);
}

static void capture_warning(const char* message, void* unused) {
  MI_UNUSED(unused);
  if (message == NULL || message[0] == '\0') return;
  if (strncmp(message, "mimalloc: warning: thread 0x", 27) == 0) {
    warning_fragments++;
    return;
  }
  if (warning_bodies < 5) {
    const unsigned index = warning_bodies++;
    warning_reserved[index] = owner.stats.reserved.current;
    warning_committed[index] = owner.stats.committed.current;
    warning_commit_calls[index] = owner.stats.commit_calls.total;
    unsigned category = 0;
    if (strstr(message, "cannot commit OS memory") != NULL) category = 1;
    else if (strstr(message, "unable to commit meta-data for OS memory") != NULL) category = 2;
    else if (strstr(message, "unable to free OS memory") != NULL) category = 3;
    else if (strstr(message, "unable to allocate aligned OS memory directly") != NULL) category = 4;
    warning_order = warning_order * 10 + category;
  }
}

static bool live(void* address) {
  unsigned char residency = 0;
  return mincore(address, (size_t)sysconf(_SC_PAGESIZE), &residency) == 0;
}

#define EMIT(name, value) printf(name "=%lld\n", (long long)(value))

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  memset(&owner, 0, sizeof(owner));
  memset(&heap, 0, sizeof(heap));
  mi_lock_init(&owner.arena_reserve_lock);
  mi_atomic_store_relaxed(&owner.heap_count, 1);
  heap.subproc = &owner;
  mi_os_mem_config.has_overcommit = true;
  mi_os_mem_config.has_transparent_huge_pages = false;
  mi_option_set(mi_option_arena_reserve, 32 * 1024);
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(capture_warning, NULL);
  const size_t registry_before = mi_arenas_get_count(&owner);
  const int64_t reserved_before = owner.stats.reserved.current;
  const int64_t committed_before = owner.stats.committed.current;
  const int64_t mmap_before = owner.stats.mmap_calls.total;
  const int64_t commit_before = owner.stats.commit_calls.total;
  const int64_t arena_before = owner.stats.arena_count.total;

  fail_metadata = true;
  fail_cleanup = true;
  mi_memid_t failed_id = _mi_memid_none();
  void* const failed_start = mi_arenas_try_alloc(&heap, 1, MI_ARENA_SLICE_ALIGN,
      true, true, NULL, 0, -1, &failed_id);
  const bool refused = failed_start == NULL && !fail_metadata && !fail_cleanup;
  const bool no_memory_id = failed_id.memkind == MI_MEM_NONE;
  const size_t failed_registry = mi_arenas_get_count(&owner);
  const bool escaped_live = escaped_address != NULL && live(escaped_address);
  const int64_t reserved_after_failure = owner.stats.reserved.current;
  const int64_t committed_after_failure = owner.stats.committed.current;
  const int64_t mmap_after_failure = owner.stats.mmap_calls.total;
  const int64_t commit_after_failure = owner.stats.commit_calls.total;
  const int64_t arena_after_failure = owner.stats.arena_count.total;

  mi_memid_t recovery_id = _mi_memid_none();
  void* const recovery_start = mi_arenas_try_alloc(&heap, 1, MI_ARENA_SLICE_ALIGN,
      true, true, NULL, 0, -1, &recovery_id);
  mi_arena_t* const recovery_arena = recovery_start == NULL ? NULL
      : recovery_id.mem.arena.arena;
  const bool recovery_memory = recovery_start != NULL
      && recovery_id.memkind == MI_MEM_ARENA
      && recovery_arena != NULL
      && recovery_arena->memid.memkind == MI_MEM_OS
      && recovery_arena->memid.mem.os.base == recovery_arena->start
      && recovery_arena->memid.mem.os.size >= MI_ARENA_MIN_SIZE
      && !recovery_arena->memid.initially_committed;
  const size_t recovery_registry = mi_arenas_get_count(&owner);
  const size_t recovery_slice = recovery_memory ? recovery_id.mem.arena.slice_index : 0;
  const bool recovery_bitmap_claimed = recovery_memory
      && mi_bbitmap_is_clearN(recovery_arena->slices_free, recovery_slice, 1)
      && mi_bitmap_is_setN(recovery_arena->slices_committed, recovery_slice, 1);
  const bool prior_live_during_recovery = live(escaped_address);
  const int64_t recovery_reserved_delta = owner.stats.reserved.current - reserved_before;
  const int64_t recovery_committed_delta = owner.stats.committed.current - committed_before;
  const int64_t recovery_mmap_delta = owner.stats.mmap_calls.total - mmap_before;
  const int64_t recovery_commit_delta = owner.stats.commit_calls.total - commit_before;
  const int64_t recovery_arena_delta = owner.stats.arena_count.total - arena_before;
  const unsigned warnings_before_release = warning_bodies;
  if (recovery_start != NULL) {
    _mi_arenas_free(&owner, recovery_start, MI_ARENA_SLICE_SIZE, recovery_id);
  }
  const bool claim_released = recovery_memory
      && mi_bbitmap_is_setN(recovery_arena->slices_free, recovery_slice, 1)
      && mi_arenas_get_count(&owner) == recovery_registry;
  const bool recovery_mapping_live = recovery_memory && live(recovery_arena->start);
  const bool prior_live_after_release = live(escaped_address);
  const bool raw_cleanup = escaped_address != NULL
      && __real_munmap(escaped_address, escaped_length) == 0;
  const bool raw_gone = escaped_address != NULL && !live(escaped_address);
  const bool raw_no_stats = owner.stats.reserved.current == reserved_before + recovery_reserved_delta
      && owner.stats.committed.current == committed_before + recovery_committed_delta;

  EMIT("refused", refused);
  EMIT("no_memory_id", no_memory_id);
  EMIT("registry_before", registry_before);
  EMIT("failed_registry", failed_registry);
  EMIT("metadata_calls", protect_calls);
  EMIT("metadata_size", protected_length);
  EMIT("metadata_exact", protected_address == escaped_address
      && protected_flags == (PROT_READ | PROT_WRITE));
  EMIT("cleanup_calls", selected_unmaps);
  EMIT("escaped_size", escaped_length);
  EMIT("escaped_aligned", escaped_address != NULL
      && ((uintptr_t)escaped_address % MI_ARENA_ALIGNMENT) == 0);
  EMIT("escaped_live", escaped_live);
  EMIT("warning_fragments", warning_fragments);
  EMIT("warning_bodies", warning_bodies);
  EMIT("warning_order", warning_order);
  const unsigned fallback = warning_order == 4123;
  EMIT("fallback_warning_before_stats", !fallback
      || (warning_reserved[0] == reserved_before + (int64_t)escaped_length
          && warning_committed[0] == committed_before
          && warning_commit_calls[0] == commit_before));
  EMIT("warning_commit_before_stats", warning_bodies >= 1 + fallback
      && warning_reserved[fallback] == reserved_before + (int64_t)escaped_length
      && warning_committed[fallback] == committed_before
      && warning_commit_calls[fallback] == commit_before + 1);
  EMIT("warning_meta_before_stats", warning_bodies >= 2 + fallback
      && warning_reserved[1 + fallback] == reserved_before + (int64_t)escaped_length
      && warning_committed[1 + fallback] == committed_before
      && warning_commit_calls[1 + fallback] == commit_before + 1);
  EMIT("warning_free_before_stats", warning_bodies >= 3 + fallback
      && warning_reserved[2 + fallback] == reserved_before + (int64_t)escaped_length
      && warning_committed[2 + fallback] == committed_before
      && warning_commit_calls[2 + fallback] == commit_before + 1);
  EMIT("reserved_after_failure", reserved_after_failure - reserved_before);
  EMIT("committed_after_failure", committed_after_failure - committed_before);
  EMIT("mmap_after_failure", mmap_after_failure - mmap_before);
  EMIT("commit_after_failure", commit_after_failure - commit_before);
  EMIT("arena_after_failure", arena_after_failure - arena_before);
  EMIT("recovery_memory", recovery_memory);
  EMIT("recovery_slice_index", recovery_memory ? recovery_slice : -1);
  EMIT("recovery_slice_count", recovery_memory ? recovery_id.mem.arena.slice_count : -1);
  EMIT("recovery_initially_committed", recovery_memory && recovery_id.initially_committed);
  EMIT("recovery_initially_zero", recovery_memory && recovery_id.initially_zero);
  EMIT("recovery_is_pinned", recovery_memory && recovery_id.is_pinned);
  EMIT("recovery_arena_info_slices", recovery_memory ? recovery_arena->info_slices : -1);
  EMIT("recovery_arena_size", recovery_memory ? recovery_arena->memid.mem.os.size : 0);
  EMIT("recovery_registry", recovery_registry);
  EMIT("recovery_bitmap_claimed", recovery_bitmap_claimed);
  EMIT("prior_live_during_recovery", prior_live_during_recovery);
  EMIT("recovery_reserved_delta", recovery_reserved_delta);
  EMIT("recovery_committed_delta", recovery_committed_delta);
  EMIT("recovery_mmap_delta", recovery_mmap_delta);
  EMIT("recovery_commit_delta", recovery_commit_delta);
  EMIT("recovery_arena_delta", recovery_arena_delta);
  EMIT("claim_released", claim_released);
  EMIT("recovery_mapping_live", recovery_mapping_live);
  EMIT("prior_live_after_release", prior_live_after_release);
  EMIT("release_warnings", warning_bodies - warnings_before_release);
  EMIT("raw_cleanup", raw_cleanup);
  EMIT("raw_gone", raw_gone);
  EMIT("raw_no_stats", raw_no_stats);
  return 0;
}

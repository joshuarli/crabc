/* Native x86-64 M2 VM-primitives oracle.
 *
 * This intentionally includes the fixed v3.5.0 `src/os.c`, `src/arena.c`,
 * `src/init.c`, and `src/page.c` into the probe so their private configuration,
 * OS-allocation, first arena-reserve, preloading-state, and direct
 * page-extension bodies are observed directly. The Python producer omits those
 * four ordinary source objects from the link
 * list. It records address-free fixed-profile facts for the regular lifecycle
 * and one bounded, child-only source-option/first-arena policy record. It
 * does not qualify ambient retries, huge-page success/placement, diagnostics,
 * or general arena use.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <unistd.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

/* Linux 5.10 supplies this exact non-replacing fixed-map flag. The aligned
 * overmap oracle uses it only to make one otherwise kernel-chosen test
 * geometry deterministic; do not substitute MAP_FIXED or a portability
 * fallback for this source-bound native witness. */
#ifndef MAP_FIXED_NOREPLACE
#error "native x86 M2 aligned-overmap oracle requires Linux MAP_FIXED_NOREPLACE"
#endif

/* Resolved through `-I <pinned-source>/src`; keep each private source body
 * singular by omitting `src/os.c`, `src/arena.c`, `src/init.c`, and
 * `src/page.c` from the ordinary C source list. */

/* `src/os.c:141,151-152` contains exactly the two fetch-add and one
 * strong-CAS operations in `_mi_os_get_aligned_hint`. Interpose only those
 * macro uses while directly including that one source body. Each wrapper
 * delegates to the same C11 AcqRel/Acquire operation; it neither models nor
 * replaces the source cursor. Capture is disabled except around a selected
 * direct call below, and no `init.c` or other source atomics are affected. */
typedef struct aligned_hint_atomic_record_s {
  bool active;
  _Atomic(uintptr_t)* cursor;
  uintptr_t fetch_old[2];
  uintptr_t fetch_add[2];
  size_t fetch_count;
  uintptr_t cas_expected_before;
  uintptr_t cas_expected_after;
  uintptr_t cas_desired;
  size_t cas_count;
  bool cas_succeeded;
  bool cursor_consistent;
} aligned_hint_atomic_record_t;

static aligned_hint_atomic_record_t aligned_hint_atomic_record = {0};
static pthread_mutex_t aligned_hint_competitor_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t aligned_hint_competitor_ready = PTHREAD_COND_INITIALIZER;
static pthread_cond_t aligned_hint_competitor_done = PTHREAD_COND_INITIALIZER;
static bool aligned_hint_competitor_enabled = false;
static bool aligned_hint_competitor_waiting = false;
static bool aligned_hint_competitor_finished = false;
static uintptr_t aligned_hint_competitor_add = 0;
static uintptr_t aligned_hint_competitor_old = 0;

static uintptr_t m2_aligned_hint_fetch_add(
    _Atomic(uintptr_t)* cursor, uintptr_t amount);
static bool m2_aligned_hint_compare_exchange(
    _Atomic(uintptr_t)* cursor, uintptr_t* expected, uintptr_t desired);

#undef mi_atomic_add_acq_rel
#undef mi_atomic_cas_strong_acq_rel
#define mi_atomic_add_acq_rel(p, x) m2_aligned_hint_fetch_add((p), (x))
#define mi_atomic_cas_strong_acq_rel(p, expected, desired) \
  m2_aligned_hint_compare_exchange((p), (expected), (desired))
#include "os.c"
#undef mi_atomic_add_acq_rel
#undef mi_atomic_cas_strong_acq_rel
/* Restore the pinned atomic spellings before directly including the other
 * private source units. The wrappers above are scoped to `os.c` alone. */
#define mi_atomic_cas_strong_acq_rel(p, exp, des) \
  mi_atomic_cas_strong((p), (exp), (des), mi_memory_order(acq_rel), mi_memory_order(acquire))
#define mi_atomic_add_acq_rel(p, x) \
  mi_atomic(fetch_add_explicit)((p), (x), mi_memory_order(acq_rel))
#include "arena.c"
#include "init.c"
#include "page.c"

static uintptr_t m2_aligned_hint_fetch_add(
    _Atomic(uintptr_t)* cursor, uintptr_t amount) {
  const uintptr_t observed = atomic_fetch_add_explicit(
      cursor, amount, memory_order_acq_rel);
  if (!aligned_hint_atomic_record.active) return observed;

  if (aligned_hint_atomic_record.cursor == NULL) {
    aligned_hint_atomic_record.cursor = cursor;
  } else if (aligned_hint_atomic_record.cursor != cursor) {
    aligned_hint_atomic_record.cursor_consistent = false;
  }
  if (aligned_hint_atomic_record.fetch_count < 2) {
    const size_t index = aligned_hint_atomic_record.fetch_count;
    aligned_hint_atomic_record.fetch_old[index] = observed;
    aligned_hint_atomic_record.fetch_add[index] = amount;
  }
  aligned_hint_atomic_record.fetch_count++;

  if (aligned_hint_competitor_enabled && aligned_hint_atomic_record.fetch_count == 1) {
    pthread_mutex_lock(&aligned_hint_competitor_lock);
    aligned_hint_competitor_waiting = true;
    pthread_cond_signal(&aligned_hint_competitor_ready);
    while (!aligned_hint_competitor_finished) {
      pthread_cond_wait(&aligned_hint_competitor_done, &aligned_hint_competitor_lock);
    }
    pthread_mutex_unlock(&aligned_hint_competitor_lock);
  }
  return observed;
}

static bool m2_aligned_hint_compare_exchange(
    _Atomic(uintptr_t)* cursor, uintptr_t* expected, uintptr_t desired) {
  const uintptr_t expected_before = *expected;
  const bool swapped = atomic_compare_exchange_strong_explicit(
      cursor, expected, desired, memory_order_acq_rel, memory_order_acquire);
  if (!aligned_hint_atomic_record.active) return swapped;

  if (aligned_hint_atomic_record.cursor == NULL) {
    aligned_hint_atomic_record.cursor = cursor;
  } else if (aligned_hint_atomic_record.cursor != cursor) {
    aligned_hint_atomic_record.cursor_consistent = false;
  }
  aligned_hint_atomic_record.cas_expected_before = expected_before;
  aligned_hint_atomic_record.cas_expected_after = *expected;
  aligned_hint_atomic_record.cas_desired = desired;
  aligned_hint_atomic_record.cas_succeeded = swapped;
  aligned_hint_atomic_record.cas_count++;
  return swapped;
}

/* The producer links with `--wrap=munmap`.  This controlled one-shot seam
 * reaches the unchanged pinned `_mi_prim_free` call inside `src/prim/unix/prim.c`;
 * it does not replace a source function or make the fault path a host model.
 * Keep it disabled through startup and every success record, then enable it
 * only around the source `_mi_os_free` call selected below. */
static bool fail_next_munmap = false;
static size_t wrapped_munmap_calls = 0;
static int last_real_munmap_result = -1;
/* The normal fixed-range transition record faults only the pinned Unix
 * imports.  It observes the source `_mi_os_*` wrappers rather than replacing
 * a policy function, so failed commit/decommit/protect calls retain their
 * source result and their existing mapping owner can make the explicit retry. */
static bool fail_next_mprotect = false;
static bool fail_next_madvise_dontneed = false;
static bool fail_next_madvise_free_einval = false;
static bool capture_transition_mprotect = false;
static size_t captured_transition_mprotect_calls = 0;
static int captured_transition_protections[4];
/* The selected `mi_page_extend_free` source body owns this separate record.
 * It captures the raw direct `_mi_os_commit` primitive and never substitutes
 * the page-extension algorithm or reuses a callback count from page setup. */
static bool capture_page_extension_mprotect = false;
static size_t captured_page_extension_mprotect_calls = 0;
static void* captured_page_extension_mprotect_addresses[2];
static size_t captured_page_extension_mprotect_lengths[2];
static int captured_page_extension_mprotect_protections[2];
static bool capture_transition_madvise = false;
static size_t captured_transition_madvise_calls = 0;
static int captured_transition_advices[4];
static void* captured_transition_madvise_addresses[4];
static size_t captured_transition_madvise_lengths[4];
/* The ordinary lifecycle above also frees mappings through this wrapper.
 * Capture only the selected failed full-MemoryId release and its retry, so
 * the address-free trace can prove both source calls used the retained base
 * and full length rather than merely observing two `munmap` attempts. */
static bool capture_release_munmap = false;
static size_t captured_release_munmap_calls = 0;
static void* captured_release_munmap_addresses[2];
static size_t captured_release_munmap_lengths[2];

/* The policy child owns this one selected source `mi_arena_reserve` call. Its
 * `mmap` wrapper forces both source-generated MAP_HUGETLB attempts to fail,
 * allowing the unchanged Unix source to retry a null hint and then choose a
 * regular hinted map. Its `madvise` wrapper makes the selected THP advisory
 * fail. The regular map starts a separate `unix_mmap_prim_aligned` call, so
 * its non-null hint is distinct from the failed large map's high hint. The
 * returned numeric delta is not stable: the source aligns a randomized,
 * atomically advanced cursor before returning each hint. The record compares
 * those source relations, never virtual addresses or a raw trace count. */
static bool capture_policy_mapping = false;
static size_t captured_policy_large_calls = 0;
static void* captured_policy_large_hints[2];
static size_t captured_policy_regular_calls = 0;
static void* captured_policy_regular_hint = NULL;
static size_t captured_policy_thp_calls = 0;

/* This is deliberately separate from the first-arena policy record above.
 * It calls the pinned `_mi_prim_alloc` receiver with the largest page-multiple
 * length, after `_mi_os_get_aligned_hint`'s unsigned request arithmetic wraps.
 * The wrapper retains the two raw Unix attempts: the source-derived hint must
 * fail before the source's null-address fallback. There is no successful map
 * to release on this diagnostic path, so `addr == NULL` is the ownership
 * result rather than an unowned failed pointer. */
static bool capture_aligned_hint_direct_caller = false;
static size_t captured_aligned_hint_direct_calls = 0;
static void* captured_aligned_hint_direct_addresses[2];
static size_t captured_aligned_hint_direct_lengths[2];

typedef struct policy_child_record_s {
  bool source_options_applied;
  size_t first_arena_size;
  bool first_arena_initially_committed;
  bool large_high_hint_failed;
  bool large_null_hint_retry_failed;
  bool regular_hinted_map_after_large_fallback;
  bool thp_advice_failure_ignored;
} policy_child_record_t;

/* The pinned `mi_os_prim_alloc_aligned` body is included above. This tiny
 * fixture state controls only its imported mmap/munmap results while a COW
 * child executes one selected call. It does not model an allocator function:
 * the source still decides whether it has a direct candidate, an overmap, and
 * whether to continue after a void partial free. */
typedef enum aligned_overmap_phase_e {
  ALIGNED_OVERMAP_OFF = 0,
  ALIGNED_OVERMAP_DIRECT,
  ALIGNED_OVERMAP_OVER,
} aligned_overmap_phase_t;

typedef struct aligned_overmap_probe_s {
  bool active;
  bool fail_direct_map;
  size_t fail_cleanup_ordinal;
  aligned_overmap_phase_t phase;
  void* direct_target;
  void* over_target;
  size_t direct_mmap_calls;
  size_t over_mmap_calls;
  size_t cleanup_munmap_calls;
  void* cleanup_addresses[3];
  size_t cleanup_lengths[3];
} aligned_overmap_probe_t;

static aligned_overmap_probe_t aligned_overmap_probe = {0};

int __real_munmap(void* address, size_t length);
void* __real_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset);
int __real_madvise(void* address, size_t length, int advice);
int __real_mprotect(void* address, size_t length, int protection);

int __wrap_munmap(void* address, size_t length) {
  wrapped_munmap_calls++;
  if (aligned_overmap_probe.active) {
    const size_t index = aligned_overmap_probe.cleanup_munmap_calls;
    if (index < sizeof(aligned_overmap_probe.cleanup_addresses)
                    / sizeof(aligned_overmap_probe.cleanup_addresses[0])) {
      aligned_overmap_probe.cleanup_addresses[index] = address;
      aligned_overmap_probe.cleanup_lengths[index] = length;
    }
    aligned_overmap_probe.cleanup_munmap_calls++;
    if (aligned_overmap_probe.fail_cleanup_ordinal != 0
        && aligned_overmap_probe.cleanup_munmap_calls
            == aligned_overmap_probe.fail_cleanup_ordinal) {
      errno = ENOMEM;
      return -1;
    }
    last_real_munmap_result = __real_munmap(address, length);
    return last_real_munmap_result;
  }
  if (capture_release_munmap && captured_release_munmap_calls < 2) {
    const size_t index = captured_release_munmap_calls;
    captured_release_munmap_addresses[index] = address;
    captured_release_munmap_lengths[index] = length;
    captured_release_munmap_calls++;
  }
  if (fail_next_munmap) {
    fail_next_munmap = false;
    errno = ENOMEM;
    return -1;
  }
  last_real_munmap_result = __real_munmap(address, length);
  return last_real_munmap_result;
}

void* __wrap_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset) {
  if (aligned_overmap_probe.active) {
    if (aligned_overmap_probe.phase == ALIGNED_OVERMAP_DIRECT) {
      aligned_overmap_probe.direct_mmap_calls++;
      if (aligned_overmap_probe.fail_direct_map) {
        /* `unix_mmap_prim_aligned` may try a source high hint and then null.
         * Fail every direct raw attempt; moving to the overmap phase only
         * after the null retry prevents an accidental direct fallback map. */
        if (address == NULL) aligned_overmap_probe.phase = ALIGNED_OVERMAP_OVER;
        errno = ENOMEM;
        return MAP_FAILED;
      }
      aligned_overmap_probe.phase = ALIGNED_OVERMAP_OVER;
      return __real_mmap(
          aligned_overmap_probe.direct_target, length, protection,
          flags | MAP_FIXED_NOREPLACE, descriptor, offset);
    }
    if (aligned_overmap_probe.phase == ALIGNED_OVERMAP_OVER) {
      aligned_overmap_probe.over_mmap_calls++;
      return __real_mmap(
          aligned_overmap_probe.over_target, length, protection,
          flags | MAP_FIXED_NOREPLACE, descriptor, offset);
    }
    errno = EINVAL;
    return MAP_FAILED;
  }
  if (capture_aligned_hint_direct_caller) {
    if (captured_aligned_hint_direct_calls < 2) {
      const size_t index = captured_aligned_hint_direct_calls;
      captured_aligned_hint_direct_addresses[index] = address;
      captured_aligned_hint_direct_lengths[index] = length;
    }
    captured_aligned_hint_direct_calls++;
    /* Force the source hinted branch to reach its literal null retry. The
     * second raw map remains a real Linux rejection of the impossible length. */
    if (captured_aligned_hint_direct_calls == 1 && address != NULL) {
      errno = ENOMEM;
      return MAP_FAILED;
    }
  }
  if (capture_policy_mapping) {
    if ((flags & MAP_HUGETLB) != 0) {
      if (captured_policy_large_calls < 2) {
        captured_policy_large_hints[captured_policy_large_calls] = address;
      }
      captured_policy_large_calls++;
      errno = ENOMEM;
      return MAP_FAILED;
    }
    if (captured_policy_regular_calls == 0) {
      captured_policy_regular_hint = address;
    }
    captured_policy_regular_calls++;
  }
  return __real_mmap(address, length, protection, flags, descriptor, offset);
}

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (capture_transition_mprotect && captured_transition_mprotect_calls < 4) {
    captured_transition_protections[captured_transition_mprotect_calls] = protection;
    captured_transition_mprotect_calls++;
  }
  if (capture_page_extension_mprotect
      && captured_page_extension_mprotect_calls < 2) {
    const size_t index = captured_page_extension_mprotect_calls;
    captured_page_extension_mprotect_addresses[index] = address;
    captured_page_extension_mprotect_lengths[index] = length;
    captured_page_extension_mprotect_protections[index] = protection;
    captured_page_extension_mprotect_calls++;
  }
  if (fail_next_mprotect) {
    fail_next_mprotect = false;
    errno = ENOMEM;
    return -1;
  }
  return __real_mprotect(address, length, protection);
}

int __wrap_madvise(void* address, size_t length, int advice) {
  if (capture_policy_mapping && advice == MADV_HUGEPAGE) {
    captured_policy_thp_calls++;
    errno = ENOMEM;
    return -1;
  }
  if (capture_transition_madvise && captured_transition_madvise_calls < 4) {
    const size_t index = captured_transition_madvise_calls;
    captured_transition_advices[index] = advice;
    captured_transition_madvise_addresses[index] = address;
    captured_transition_madvise_lengths[index] = length;
    captured_transition_madvise_calls++;
  }
  if (advice == MADV_FREE && fail_next_madvise_free_einval) {
    fail_next_madvise_free_einval = false;
    errno = EINVAL;
    return -1;
  }
  if (advice == MADV_DONTNEED && fail_next_madvise_dontneed) {
    fail_next_madvise_dontneed = false;
    errno = ENOMEM;
    return -1;
  }
  return __real_madvise(address, length, advice);
}

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

static int64_t current_reserved(const mi_subproc_t* subproc) {
  return mi_atomic_loadi64_relaxed((_Atomic(int64_t)*)(&subproc->stats.reserved.current));
}

static int64_t current_committed(const mi_subproc_t* subproc) {
  return mi_atomic_loadi64_relaxed((_Atomic(int64_t)*)(&subproc->stats.committed.current));
}

static int64_t total_reserved(const mi_subproc_t* subproc) {
  return mi_atomic_loadi64_relaxed((_Atomic(int64_t)*)(&subproc->stats.reserved.total));
}

static int64_t total_committed(const mi_subproc_t* subproc) {
  return mi_atomic_loadi64_relaxed((_Atomic(int64_t)*)(&subproc->stats.committed.total));
}

static int64_t current_mmap_calls(const mi_subproc_t* subproc) {
  return mi_atomic_loadi64_relaxed((_Atomic(int64_t)*)(&subproc->stats.mmap_calls.total));
}

static int64_t current_reset(const mi_subproc_t* subproc) {
  return subproc->stats.reset.total;
}

static int64_t current_purged(const mi_subproc_t* subproc) {
  return subproc->stats.purged.total;
}

static int64_t current_reset_calls(const mi_subproc_t* subproc) {
  return subproc->stats.reset_calls.total;
}

static int64_t current_purge_calls(const mi_subproc_t* subproc) {
  return subproc->stats.purge_calls.total;
}

/* This direct source receiver deliberately uses `mi_manage_memory` rather
 * than an adapter. It exercises the same external callback through source
 * arena initialization, `mi_arena_try_alloc_at`, and `mi_arena_purge`; raw
 * addresses stay inside the oracle and only exact ownership relations leave
 * as trace booleans. The external caller retains the mmap range, matching
 * source MI_MEM_EXTERNAL's no-unmap authority. */
typedef struct external_callback_record_s {
  size_t commit_calls;
  size_t purge_calls;
  void* last_start;
  size_t last_size;
  bool commit_zero_nonnull;
  bool purge_zero_null;
  bool commit_zero;
  bool needs_recommit;
} external_callback_record_t;

typedef struct external_callback_result_s {
  bool managed_external_owner;
  bool commit_zero_propagated;
  bool purge_raw_span_null_zero_and_statistics;
  bool purge_true_clears_commit;
  bool recommit_reinvokes_callback;
  bool purge_false_preserves_commit;
  bool purge_mixed_clears_commit;
  bool negative_delay_skips_callback_and_statistics;
  bool no_normal_advice;
  bool one_published_owner_per_registry;
  bool page_extension_direct_commit_fault_bypasses_callback;
  bool page_extension_failure_preserves_unpublished_state;
  bool page_extension_retry_commits_without_callback;
} external_callback_result_t;

static bool capture_external_page_extension(
    mi_subproc_t* _subproc, external_callback_record_t* record,
    external_callback_result_t* result);

static bool external_arena_callback(
    bool commit, void* start, size_t size, bool* is_zero, void* argument) {
  external_callback_record_t* const record = (external_callback_record_t*)argument;
  if (record == NULL) return false;
  record->last_start = start;
  record->last_size = size;
  if (commit) {
    record->commit_calls++;
    record->commit_zero_nonnull = (is_zero != NULL);
    if (is_zero != NULL) *is_zero = record->commit_zero;
    return true;
  }
  record->purge_calls++;
  record->purge_zero_null = (is_zero == NULL);
  return record->needs_recommit;
}

static external_callback_result_t capture_external_callback_arena(
    mi_subproc_t* subproc) {
  external_callback_result_t result = {0};
  const size_t size = MI_ARENA_MIN_SIZE;
  const size_t alignment = MI_ARENA_ALIGNMENT;
  const size_t raw_size = size + alignment;
  void* const raw = mmap(NULL, raw_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) return result;
  void* const base = (void*)(((uintptr_t)raw + alignment - 1) & ~(alignment - 1));
  const long prior_delay = mi_option_get(mi_option_purge_delay);
  const long prior_purge_decommits = mi_option_get(mi_option_purge_decommits);
  const bool prior_preloading = os_preloading;
  external_callback_record_t record = {0};
  mi_arena_id_t arena_id = _mi_arena_id_none();

  /* Preloading and purge_decommits would choose normal policy only without a
   * callback. `_mi_os_purge_ex` must instead call us before either branch. */
  mi_option_set(mi_option_purge_delay, 0);
  mi_option_set(mi_option_purge_decommits, 1);
  os_preloading = true;
  const bool managed = mi_manage_memory(
      base, size, false /* committed */, false /* pinned */, false /* zero */,
      -1, false, external_arena_callback, &record, &arena_id);
  mi_arena_t* const arena = _mi_arena_from_id(arena_id);
  result.managed_external_owner = managed && arena != NULL
      && arena->memid.memkind == MI_MEM_EXTERNAL
      && arena->memid.mem.os.base == base
      && arena->memid.mem.os.size == size;
  if (!result.managed_external_owner) goto restore;

  record.commit_calls = 0;
  record.purge_calls = 0;
  record.commit_zero_nonnull = false;
  record.commit_zero = true;
  mi_memid_t first_id = _mi_memid_none();
  void* const first = mi_arena_try_alloc_at(arena, 2, true, 0, &first_id);
  const size_t first_index = first_id.mem.arena.slice_index;
  result.commit_zero_propagated = first != NULL
      && first_id.initially_zero
      && record.commit_calls == 1
      && record.commit_zero_nonnull
      && record.last_start == first
      && record.last_size == 2 * MI_ARENA_SLICE_SIZE;
  if (!result.commit_zero_propagated) goto restore;

  record.purge_calls = 0;
  record.needs_recommit = true;
  captured_transition_madvise_calls = 0;
  capture_transition_madvise = true;
  const int64_t purge_calls_before = current_purge_calls(subproc);
  const int64_t purged_before = current_purged(subproc);
  const bool needs_recommit = mi_arena_purge(arena, first_index, 2);
  const int64_t purge_calls_after = current_purge_calls(subproc);
  const int64_t purged_after = current_purged(subproc);
  capture_transition_madvise = false;
  result.purge_raw_span_null_zero_and_statistics = needs_recommit
      && record.purge_calls == 1
      && record.purge_zero_null
      && record.last_start == first
      && record.last_size == 2 * MI_ARENA_SLICE_SIZE
      && purge_calls_after == purge_calls_before + 1
      && purged_after == purged_before + (int64_t)(2 * MI_ARENA_SLICE_SIZE);
  result.purge_true_clears_commit = mi_bitmap_is_clearN(arena->slices_committed, first_index, 2);
  result.no_normal_advice = (captured_transition_madvise_calls == 0);
  if (!result.purge_raw_span_null_zero_and_statistics
      || !result.purge_true_clears_commit || !result.no_normal_advice) goto restore;

  /* The source free bitmap is normally restored by `_mi_arenas_free` after
   * `mi_arena_purge`; model that already-owned release edge here so the next
   * direct source allocator call reaches the same now-clear commit bitmap. */
  mi_bbitmap_setN(arena->slices_free, first_index, 2);
  record.commit_calls = 0;
  mi_memid_t recommit_id = _mi_memid_none();
  void* const recommit = mi_arena_try_alloc_at(arena, 2, true, 0, &recommit_id);
  result.recommit_reinvokes_callback = recommit == first
      && record.commit_calls == 1
      && record.last_start == recommit
      && record.last_size == 2 * MI_ARENA_SLICE_SIZE;
  if (!result.recommit_reinvokes_callback) goto restore;

  record.purge_calls = 0;
  record.needs_recommit = false;
  const bool false_recommit = mi_arena_purge(
      arena, recommit_id.mem.arena.slice_index, 2);
  result.purge_false_preserves_commit = !false_recommit
      && record.purge_calls == 1
      && mi_bitmap_is_setN(arena->slices_committed, recommit_id.mem.arena.slice_index, 2);
  if (!result.purge_false_preserves_commit) goto restore;

  mi_bbitmap_setN(arena->slices_free, recommit_id.mem.arena.slice_index, 2);
  /* The previous callback-false source result intentionally retained both
   * commit bits. Form the independent mixed precondition explicitly before
   * the direct partial callback commit below. */
  mi_bitmap_clearN(arena->slices_committed, recommit_id.mem.arena.slice_index, 2);
  mi_memid_t mixed_id = _mi_memid_none();
  void* const mixed = mi_arena_try_alloc_at(arena, 2, false, 0, &mixed_id);
  if (mixed == NULL) goto restore;
  /* Make exactly one bit committed before the source purge's set/count
   * observation. This is its own bitmap transition, not an invented policy. */
  if (!mi_arena_commit(subproc, arena, mixed, MI_ARENA_SLICE_SIZE, NULL, 0)) goto restore;
  mi_bitmap_setN(arena->slices_committed, mixed_id.mem.arena.slice_index, 1, NULL);
  record.purge_calls = 0;
  record.needs_recommit = false;
  const bool mixed_recommit = mi_arena_purge(
      arena, mixed_id.mem.arena.slice_index, 2);
  result.purge_mixed_clears_commit = !mixed_recommit
      && record.purge_calls == 1
      && mi_bitmap_is_clearN(arena->slices_committed, mixed_id.mem.arena.slice_index, 2);
  if (!result.purge_mixed_clears_commit) goto restore;

  record.purge_calls = 0;
  mi_option_set(mi_option_purge_delay, -1);
  const int64_t negative_calls_before = current_purge_calls(subproc);
  const int64_t negative_purged_before = current_purged(subproc);
  const bool negative_recommit = mi_arena_purge(
      arena, mixed_id.mem.arena.slice_index, 2);
  result.negative_delay_skips_callback_and_statistics = !negative_recommit
      && record.purge_calls == 0
      && current_purge_calls(subproc) == negative_calls_before
      && current_purged(subproc) == negative_purged_before;
  result.one_published_owner_per_registry = (mi_arenas_get_count(subproc) >= 1);
  if (!capture_external_page_extension(subproc, &record, &result)) goto restore;

restore:
  capture_transition_madvise = false;
  mi_option_set(mi_option_purge_delay, prior_delay);
  mi_option_set(mi_option_purge_decommits, prior_purge_decommits);
  os_preloading = prior_preloading;
  return result;
}


/* This source-page receiver uses a public exclusive external heap to obtain
 * a live on-demand page, exhausts only that page's current free list, then
 * invokes the unchanged static `mi_page_extend_free` body included above.
 * A public allocation may validly select a fresh page after extension failure,
 * so the fault phase records the source function itself. The success phase
 * returns to an ordinary allocation from that same refilled page. */
static bool capture_external_page_extension(
    mi_subproc_t* _subproc, external_callback_record_t* record,
    external_callback_result_t* result) {
  const size_t size = MI_ARENA_MIN_SIZE;
  const size_t alignment = MI_ARENA_ALIGNMENT;
  const size_t raw_size = size + alignment;
  void* const raw = mmap(NULL, raw_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (raw == MAP_FAILED) return false;
  void* const base = (void*)(((uintptr_t)raw + alignment - 1) & ~(alignment - 1));
  const long prior_on_demand = mi_option_get(mi_option_page_commit_on_demand);
  mi_arena_id_t arena_id = _mi_arena_id_none();
  mi_option_set(mi_option_page_commit_on_demand, 1);
  const bool managed = mi_manage_memory(
      base, size, false /* committed */, false /* pinned */, false /* zero */,
      -1, false, external_arena_callback, record, &arena_id);
  mi_heap_t* const heap = managed ? mi_heap_new_in_arena(arena_id) : NULL;
  const size_t request = MI_SMALL_MAX_OBJ_SIZE + 1;
  void* const first = (heap == NULL ? NULL : mi_heap_malloc(heap, request));
  mi_page_t* const page = (first == NULL ? NULL : _mi_ptr_page(first));
  if (page == NULL || page->memid.memkind != MI_MEM_ARENA
      || page->memid.mem.arena.arena != _mi_arena_from_id(arena_id)
      || mi_page_slice_committed(page) == 0 || page->capacity >= page->reserved) {
    mi_option_set(mi_option_page_commit_on_demand, prior_on_demand);
    return false;
  }

  /* Initial page metadata and prefix commitment legitimately used the callback.
   * Only the following source extension record is required to bypass it. */
  record->commit_calls = 0;
  mi_theap_t* const page_theap = mi_page_theap(page);
  bool reached_direct_commit = false;
  bool complete = false;
  for (size_t attempt = 0; attempt < 32 && !complete; attempt++) {
    while (page->free != NULL) {
      void* const block = mi_heap_malloc(heap, request);
      if (block == NULL || _mi_ptr_page(block) != page) {
        mi_option_set(mi_option_page_commit_on_demand, prior_on_demand);
        return false;
      }
    }
    if (page->capacity >= page->reserved) break;
    const uint16_t capacity_before = page->capacity;
    const uint16_t prefix_before = page->slice_pcommitted;
    const void* const direct_address = mi_page_slice_start(page)
        + mi_page_slice_committed(page);
    captured_page_extension_mprotect_calls = 0;
    capture_page_extension_mprotect = true;
    fail_next_mprotect = true;
    const bool extended = mi_page_extend_free(page_theap, page);
    capture_page_extension_mprotect = false;
    if (captured_page_extension_mprotect_calls == 0) {
      if (!extended || !fail_next_mprotect) {
        mi_option_set(mi_option_page_commit_on_demand, prior_on_demand);
        return false;
      }
      fail_next_mprotect = false;
      continue;
    }
    reached_direct_commit = true;
    const bool fault_consumed = !fail_next_mprotect;
    const bool failure_unchanged = !extended && page->free == NULL
        && page->capacity == capacity_before && page->slice_pcommitted == prefix_before;
    const bool direct_primitive = captured_page_extension_mprotect_calls == 1
        && captured_page_extension_mprotect_addresses[0] == direct_address
        && captured_page_extension_mprotect_lengths[0] != 0
        && captured_page_extension_mprotect_protections[0] == (PROT_READ | PROT_WRITE);
    const size_t direct_length = captured_page_extension_mprotect_lengths[0];
    result->page_extension_direct_commit_fault_bypasses_callback = fault_consumed
        && direct_primitive && record->commit_calls == 0;
    result->page_extension_failure_preserves_unpublished_state = failure_unchanged;
    if (!result->page_extension_direct_commit_fault_bypasses_callback
        || !result->page_extension_failure_preserves_unpublished_state) {
      mi_option_set(mi_option_page_commit_on_demand, prior_on_demand);
      return false;
    }

    captured_page_extension_mprotect_calls = 0;
    capture_page_extension_mprotect = true;
    const bool retried = mi_page_extend_free(page_theap, page);
    capture_page_extension_mprotect = false;
    void* const ordinary = retried && page->free != NULL
        ? mi_heap_malloc(heap, request) : NULL;
    const bool ordinary_after_retry = ordinary != NULL && _mi_ptr_page(ordinary) == page;
    result->page_extension_retry_commits_without_callback = ordinary_after_retry
        && page->capacity > capacity_before && page->slice_pcommitted > prefix_before
        && captured_page_extension_mprotect_calls == 1
        && captured_page_extension_mprotect_addresses[0] == direct_address
        && captured_page_extension_mprotect_lengths[0] == direct_length
        && captured_page_extension_mprotect_protections[0] == (PROT_READ | PROT_WRITE)
        && record->commit_calls == 0;
    complete = result->page_extension_retry_commits_without_callback;
  }
  capture_page_extension_mprotect = false;
  fail_next_mprotect = false;
  mi_option_set(mi_option_page_commit_on_demand, prior_on_demand);
  return reached_direct_commit && complete;
}

/* This is the full normal Linux no-callback `_mi_os_purge_ex` choice matrix:
 * the exact private `os_preloading` state, negative/zero/positive delay,
 * purge_decommits, allow_reset, and source conservative range normalization.
 * Every raw advice is observed through the unchanged Unix import wrapper; the
 * source counter changes are checked before the full mapping owner is freed. */
static bool capture_normal_no_callback_purge_matrix(
    mi_subproc_t* subproc, void* base, size_t page) {
  typedef struct purge_range_s {
    size_t offset;
    size_t size;
    bool contains_page;
    size_t advice_offset;
    size_t advice_length;
  } purge_range_t;
  const long delays[] = { -1, 0, 1 };
  const bool purge_decommits[] = { false, true };
  const bool preloading_states[] = { false, true };
  const bool reset_permissions[] = { false, true };
  const purge_range_t ranges[] = {
    { 0, 0, false, 0, 0 },
    { 1, page - 1, false, 0, 0 },
    { 0, page, true, 0, page },
    /* Conservative source normalization of this nonempty span retains only
     * its middle page: start=base+page, length=page. */
    { 1, 3 * page - 2, true, page, page },
  };
  const long prior_delay = mi_option_get(mi_option_purge_delay);
  const long prior_purge_decommits = mi_option_get(mi_option_purge_decommits);
  const bool prior_preloading = os_preloading;
  bool complete = true;

  for (size_t delay_index = 0; delay_index < sizeof(delays) / sizeof(delays[0]); delay_index++) {
    for (size_t decommit_index = 0;
         decommit_index < sizeof(purge_decommits) / sizeof(purge_decommits[0]);
         decommit_index++) {
      for (size_t preloading_index = 0;
           preloading_index < sizeof(preloading_states) / sizeof(preloading_states[0]);
           preloading_index++) {
        for (size_t reset_index = 0;
             reset_index < sizeof(reset_permissions) / sizeof(reset_permissions[0]);
             reset_index++) {
          for (size_t range_index = 0; range_index < sizeof(ranges) / sizeof(ranges[0]); range_index++) {
            const long delay = delays[delay_index];
            const bool purge_decommit = purge_decommits[decommit_index];
            const bool preloading = preloading_states[preloading_index];
            const bool allow_reset = reset_permissions[reset_index];
            const purge_range_t range = ranges[range_index];
            const bool negative_delay = delay < 0;
            const bool decommit_branch = !negative_delay && purge_decommit && !preloading;
            const bool reset_branch = !negative_delay && !decommit_branch
                && allow_reset && range.contains_page;
            const bool advice_expected = !negative_delay && range.contains_page
                && (decommit_branch || allow_reset);
            const bool expected_recommit = decommit_branch && !range.contains_page;
            const int64_t purge_calls_before = current_purge_calls(subproc);
            const int64_t purged_before = current_purged(subproc);
            const int64_t reset_calls_before = current_reset_calls(subproc);
            const int64_t reset_before = current_reset(subproc);
            const int64_t committed_before = current_committed(subproc);

            mi_option_set(mi_option_purge_delay, delay);
            mi_option_set(mi_option_purge_decommits, purge_decommit ? 1 : 0);
            os_preloading = preloading;
            captured_transition_madvise_calls = 0;
            capture_transition_madvise = true;
            const bool needs_recommit = _mi_os_purge_ex(
                subproc, (uint8_t*)base + range.offset, range.size, allow_reset,
                range.size, NULL, NULL);
            capture_transition_madvise = false;

            const bool counters_match =
                current_purge_calls(subproc) == purge_calls_before + (negative_delay ? 0 : 1)
                && current_purged(subproc) == purged_before
                    + (negative_delay ? 0 : (int64_t)range.size)
                && current_reset_calls(subproc) == reset_calls_before + (reset_branch ? 1 : 0)
                && current_reset(subproc) == reset_before + (reset_branch ? (int64_t)page : 0)
                && current_committed(subproc) == committed_before;
            const bool advice_matches = captured_transition_madvise_calls
                    == (advice_expected ? 1 : 0)
                && (!advice_expected || (captured_transition_advices[0] == MADV_DONTNEED
                    && captured_transition_madvise_addresses[0]
                        == (uint8_t*)base + range.advice_offset
                    && captured_transition_madvise_lengths[0] == range.advice_length));
            if (needs_recommit != expected_recommit || !counters_match || !advice_matches) {
              complete = false;
            }
          }
        }
      }
    }
  }

  mi_option_set(mi_option_purge_delay, prior_delay);
  mi_option_set(mi_option_purge_decommits, prior_purge_decommits);
  os_preloading = prior_preloading;
  return complete;
}

static bool write_all(int descriptor, const void* buffer, size_t length) {
  const uint8_t* bytes = buffer;
  size_t written = 0;
  while (written < length) {
    const ssize_t result = write(descriptor, bytes + written, length - written);
    if (result < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (result == 0) return false;
    written += (size_t)result;
  }
  return true;
}

static size_t read_all(int descriptor, void* buffer, size_t length) {
  uint8_t* bytes = buffer;
  size_t read_count = 0;
  while (read_count < length) {
    const ssize_t result = read(descriptor, bytes + read_count, length - read_count);
    if (result < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (result == 0) break;
    read_count += (size_t)result;
  }
  return read_count;
}

/* These direct source receivers form one finite normal-release aligned-hint
 * matrix. They deliberately execute in short COW children before the parent
 * starts its own initialized cursor record: the child-only cold/default and
 * deterministic threshold schedules cannot contaminate the parent's first
 * live source fetch. No child overwrites a cold Theap; only post-init rows
 * stage the already initialized source output buffer. */
static void aligned_hint_capture_begin(void) {
  aligned_hint_atomic_record = (aligned_hint_atomic_record_t){
      .active = true,
      .cursor_consistent = true,
  };
}

static void* aligned_hint_capture_call(size_t alignment, size_t size) {
  aligned_hint_capture_begin();
  void* const hint = _mi_os_get_aligned_hint(alignment, size);
  aligned_hint_atomic_record.active = false;
  return hint;
}

static size_t aligned_hint_request_size(size_t alignment, size_t size) {
  size_t request = size + _mi_os_page_size();
  request += alignment - 1;
  return _mi_align_up(request, _mi_os_large_page_size());
}

static bool aligned_hint_record_is_one_initial_randomized_start(
    void* hint, size_t request, bool require_zero_first_fetch) {
  return hint != NULL
      && (uintptr_t)hint >= MI_HINT_BASE
      && (uintptr_t)hint < MI_HINT_BASE + MI_HINT_AREA
      && aligned_hint_atomic_record.cursor_consistent
      && aligned_hint_atomic_record.fetch_count == 2
      && (!require_zero_first_fetch || aligned_hint_atomic_record.fetch_old[0] == 0)
      && aligned_hint_atomic_record.fetch_add[0] == request
      && aligned_hint_atomic_record.cas_count == 1
      && aligned_hint_atomic_record.cas_succeeded
      && aligned_hint_atomic_record.cas_expected_before
          == aligned_hint_atomic_record.fetch_old[0] + request
      && aligned_hint_atomic_record.fetch_old[1] >= MI_HINT_BASE
      && aligned_hint_atomic_record.fetch_old[1] < MI_HINT_BASE + MI_HINT_AREA;
}

static bool stage_initialized_aligned_hint_random(mi_theap_t* theap,
                                                  uint32_t first, uint32_t second) {
  if (!mi_theap_is_initialized(theap) || first == 0 || second == 0) return false;
  for (size_t index = 0; index < sizeof(theap->random.output) / sizeof(theap->random.output[0]); index++) {
    theap->random.output[index] = 0;
  }
  /* `_mi_random_next` reads two source-order words per public uintptr_t. */
  theap->random.output[0] = 0;
  theap->random.output[1] = first;
  theap->random.output[2] = 0;
  theap->random.output[3] = second;
  theap->random.output_available = 16;
  return true;
}

static bool reap_exact_child(const char* label, pid_t child) {
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  const bool complete = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  if (!complete) {
    fprintf(stderr, "%s failed: waited=%ld expected=%ld errno=%d exited=%d status=%d signaled=%d signal=%d\n",
            label, (long)waited, (long)child, waited < 0 ? errno : 0,
            waited == child && WIFEXITED(status),
            waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1,
            waited == child && WIFSIGNALED(status),
            waited == child && WIFSIGNALED(status) ? WTERMSIG(status) : 0);
  }
  return complete;
}

static bool capture_aligned_hint_child(const char* label, int (*child_body)(void)) {
  const pid_t child = fork();
  if (child < 0) {
    fprintf(stderr, "%s fork failed: errno=%d\n", label, errno);
    return false;
  }
  if (child == 0) _exit(child_body());
  return reap_exact_child(label, child);
}

static int run_aligned_hint_cold_child(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  mi_theap_t* const theap = _mi_theap_default();
  if (_mi_process_is_initialized || mi_theap_is_initialized(theap)) return 1;

  void* const first = aligned_hint_capture_call(alignment, page);
  const aligned_hint_atomic_record_t first_record = aligned_hint_atomic_record;
  if (first != NULL || mi_theap_is_initialized(theap)
      || first_record.fetch_count != 1 || first_record.fetch_old[0] != 0
      || first_record.cas_count != 0 || !first_record.cursor_consistent) return 2;

  void* const second = aligned_hint_capture_call(alignment, page);
  const aligned_hint_atomic_record_t second_record = aligned_hint_atomic_record;
  return (second != NULL && !mi_theap_is_initialized(theap)
          && second_record.fetch_count == 1 && second_record.cas_count == 0
          && second_record.cursor_consistent
          && second_record.fetch_old[0]
              == first_record.fetch_old[0] + first_record.fetch_add[0]) ? 0 : 3;
}

static bool capture_aligned_hint_cold_child(void) {
  const pid_t child = fork();
  if (child < 0) return false;
  if (child == 0) _exit(run_aligned_hint_cold_child());
  return reap_exact_child("aligned-hint cold child", child);
}

static int run_aligned_hint_eligibility_child(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  mi_theap_t* const theap = _mi_theap_default();
  if (!mi_theap_is_initialized(theap)) return 1;

  aligned_hint_capture_call(mi_os_mem_config.alloc_granularity, page);
  if (aligned_hint_atomic_record.fetch_count != 0) return 2;
  aligned_hint_capture_call(16 * MI_GiB + page, page);
  if (aligned_hint_atomic_record.fetch_count != 0) return 3;
  /* This selected child temporarily supplies the source's low-VA observation
   * and restores it before any eligible call. It is fixture state only; the
   * normal parent retains its actual initialized process configuration. */
  const size_t original_vbits = mi_os_mem_config.virtual_address_bits;
  mi_os_mem_config.virtual_address_bits = 45;
  aligned_hint_capture_call(alignment, page);
  mi_os_mem_config.virtual_address_bits = original_vbits;
  if (aligned_hint_atomic_record.fetch_count != 0) return 4;

  if (!stage_initialized_aligned_hint_random(theap, 1, 2)) return 5;
  const size_t request = aligned_hint_request_size(16 * MI_GiB, page);
  void* const exact_max = aligned_hint_capture_call(16 * MI_GiB, page);
  return aligned_hint_record_is_one_initial_randomized_start(exact_max, request, true)
      && theap->random.output_available == 14 ? 0 : 6;
}

static bool capture_aligned_hint_eligibility_child(void) {
  const pid_t child = fork();
  if (child < 0) return false;
  if (child == 0) _exit(run_aligned_hint_eligibility_child());
  return reap_exact_child("aligned-hint eligibility child", child);
}

static int run_aligned_hint_threshold_child(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  const size_t request = aligned_hint_request_size(alignment, page);
  mi_theap_t* const theap = _mi_theap_default();
  if (!stage_initialized_aligned_hint_random(theap, 1, 2)) return 1;

  void* const initial = aligned_hint_capture_call(alignment, page);
  if (!aligned_hint_record_is_one_initial_randomized_start(initial, request, true)
      || initial != (void*)MI_HINT_BASE || theap->random.output_available != 14) return 2;
  const uintptr_t cursor_after_initial = atomic_load_explicit(
      aligned_hint_atomic_record.cursor, memory_order_acquire);
  if (cursor_after_initial >= MI_HINT_MAX) return 3;
  const size_t to_max = MI_HINT_MAX - cursor_after_initial;
  if (to_max <= page + alignment - 1) return 4;
  const size_t exact_max_size = to_max - page - (alignment - 1);
  if (aligned_hint_request_size(alignment, exact_max_size) != to_max) return 5;

  if (aligned_hint_capture_call(alignment, exact_max_size) == NULL
      || aligned_hint_atomic_record.fetch_count != 1
      || atomic_load_explicit(aligned_hint_atomic_record.cursor, memory_order_acquire) != MI_HINT_MAX) return 6;
  void* const equality = aligned_hint_capture_call(alignment, page);
  if (equality != (void*)MI_HINT_MAX || aligned_hint_atomic_record.fetch_count != 1
      || aligned_hint_atomic_record.fetch_old[0] != MI_HINT_MAX
      || aligned_hint_atomic_record.cas_count != 0
      || atomic_load_explicit(aligned_hint_atomic_record.cursor, memory_order_acquire)
          != MI_HINT_MAX + request) return 7;
  void* const wrapped = aligned_hint_capture_call(alignment, page);
  const bool wrapped_valid = wrapped == (void*)MI_HINT_BASE
      && aligned_hint_record_is_one_initial_randomized_start(wrapped, request, false)
      && theap->random.output_available == 12;
  if (!wrapped_valid) {
    fprintf(stderr,
            "aligned-hint threshold wrap failed: hint=%p fetches=%zu old0=%#zx old1=%#zx "
            "cas=%zu cas_ok=%d expected_before=%#zx expected_after=%#zx cursor=%#zx output=%d\n",
            wrapped, aligned_hint_atomic_record.fetch_count,
            (size_t)aligned_hint_atomic_record.fetch_old[0],
            (size_t)aligned_hint_atomic_record.fetch_old[1],
            aligned_hint_atomic_record.cas_count, aligned_hint_atomic_record.cas_succeeded,
            (size_t)aligned_hint_atomic_record.cas_expected_before,
            (size_t)aligned_hint_atomic_record.cas_expected_after,
            (size_t)atomic_load_explicit(aligned_hint_atomic_record.cursor, memory_order_acquire),
            theap->random.output_available);
  }
  return wrapped_valid ? 0 : 8;
}

static bool capture_aligned_hint_threshold_child(void) {
  const pid_t child = fork();
  if (child < 0) return false;
  if (child == 0) _exit(run_aligned_hint_threshold_child());
  return reap_exact_child("aligned-hint threshold child", child);
}

static void* run_aligned_hint_competitor(void* unused) {
  (void)unused;
  pthread_mutex_lock(&aligned_hint_competitor_lock);
  while (!aligned_hint_competitor_waiting) {
    pthread_cond_wait(&aligned_hint_competitor_ready, &aligned_hint_competitor_lock);
  }
  _Atomic(uintptr_t)* const cursor = aligned_hint_atomic_record.cursor;
  pthread_mutex_unlock(&aligned_hint_competitor_lock);
  aligned_hint_competitor_old = atomic_fetch_add_explicit(
      cursor, aligned_hint_competitor_add, memory_order_acq_rel);
  pthread_mutex_lock(&aligned_hint_competitor_lock);
  aligned_hint_competitor_finished = true;
  pthread_cond_signal(&aligned_hint_competitor_done);
  pthread_mutex_unlock(&aligned_hint_competitor_lock);
  return NULL;
}

static int run_aligned_hint_cas_child(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  const size_t request = aligned_hint_request_size(alignment, page);
  mi_theap_t* const theap = _mi_theap_default();
  if (!stage_initialized_aligned_hint_random(theap, 1, 2)) return 1;

  pthread_mutex_lock(&aligned_hint_competitor_lock);
  aligned_hint_competitor_enabled = true;
  aligned_hint_competitor_waiting = false;
  aligned_hint_competitor_finished = false;
  aligned_hint_competitor_add = request;
  aligned_hint_competitor_old = 0;
  pthread_mutex_unlock(&aligned_hint_competitor_lock);
  pthread_t competitor;
  if (pthread_create(&competitor, NULL, run_aligned_hint_competitor, NULL) != 0) return 2;
  void* const hint = aligned_hint_capture_call(alignment, page);
  if (pthread_join(competitor, NULL) != 0) return 3;
  aligned_hint_competitor_enabled = false;

  return hint == (void*)(2 * request)
      && aligned_hint_atomic_record.cursor_consistent
      && aligned_hint_atomic_record.fetch_count == 2
      && aligned_hint_atomic_record.fetch_old[0] == 0
      && aligned_hint_atomic_record.fetch_old[1] == 2 * request
      && aligned_hint_atomic_record.cas_count == 1
      && !aligned_hint_atomic_record.cas_succeeded
      && aligned_hint_atomic_record.cas_expected_before == request
      && aligned_hint_atomic_record.cas_expected_after == 2 * request
      && aligned_hint_competitor_old == request
      && atomic_load_explicit(aligned_hint_atomic_record.cursor, memory_order_acquire)
          == 3 * request
      && theap->random.output_available == 14 ? 0 : 4;
}

static bool capture_aligned_hint_cas_child(void) {
  const pid_t child = fork();
  if (child < 0) return false;
  if (child == 0) _exit(run_aligned_hint_cas_child());
  return reap_exact_child("aligned-hint CAS child", child);
}

static bool capture_aligned_hint_initialized_parent(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  mi_theap_t* const theap = _mi_theap_default();
  if (!mi_theap_is_initialized(theap)) return false;
  const size_t request = aligned_hint_request_size(alignment, page);
  void* const hint = aligned_hint_capture_call(alignment, page);
  return aligned_hint_record_is_one_initial_randomized_start(hint, request, true);
}

static bool regular_hint_is_fresh_after_large_fallback(void) {
  return captured_policy_large_calls == 2 && captured_policy_regular_calls == 1
      && captured_policy_large_hints[0] != NULL
      && captured_policy_regular_hint != NULL
      && captured_policy_regular_hint != captured_policy_large_hints[0];
}

static int run_policy_child(int record_descriptor) {
  policy_child_record_t record = {0};
  if (setenv("mimalloc_arena_reserve", "128M", 1) != 0
      || setenv("mimalloc_arena_eager_commit", "2", 1) != 0
      || setenv("mimalloc_allow_large_os_pages", "1", 1) != 0
      || setenv("mimalloc_allow_thp", "1", 1) != 0) {
    return 1;
  }

  /* This is the unchanged source process initializer, including its raw
   * environment option read. It runs only after fork, before the parent
   * selects its separate allow_thp=0 fixed lifecycle. */
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) return 2;

  record.source_options_applied =
      mi_option_get(mi_option_arena_reserve) == 128 * 1024
      && mi_option_get(mi_option_arena_eager_commit) == 2
      && mi_option_is_enabled(mi_option_allow_large_os_pages)
      && mi_option_is_enabled(mi_option_allow_thp);

  mi_arena_id_t arena_id = _mi_arena_id_none();
  capture_policy_mapping = true;
  const bool reserved = mi_arena_reserve(
      subproc, MI_ARENA_SLICE_SIZE, true /* source normal-release caller */, &arena_id);
  capture_policy_mapping = false;
  mi_arena_t* const arena = _mi_arena_from_id(arena_id);
  size_t area_size = 0;
  void* const area = mi_arena_area(arena_id, &area_size);
  record.first_arena_size = area_size;
  record.first_arena_initially_committed =
      reserved && arena != NULL && area != NULL && arena->memid.initially_committed;
  record.large_high_hint_failed =
      captured_policy_large_calls == 2 && captured_policy_large_hints[0] != NULL;
  record.large_null_hint_retry_failed =
      captured_policy_large_calls == 2 && captured_policy_large_hints[1] == NULL;
  record.regular_hinted_map_after_large_fallback =
      reserved && regular_hint_is_fresh_after_large_fallback();
  /* Successful reservation after the wrapper's ENOMEM is the source proof
   * that `unix_mmap` ignores its best-effort MADV_HUGEPAGE result. */
  record.thp_advice_failure_ignored = reserved && captured_policy_thp_calls == 1;

  if (!write_all(record_descriptor, &record, sizeof(record))) return 3;
  return (record.source_options_applied && record.first_arena_size == 128 * 1024 * 1024
          && record.first_arena_initially_committed && record.large_high_hint_failed
          && record.large_null_hint_retry_failed
          && record.regular_hinted_map_after_large_fallback
          && record.thp_advice_failure_ignored) ? 0 : 4;
}

static bool capture_policy_child(policy_child_record_t* record) {
  int descriptors[2];
  if (pipe(descriptors) != 0) return false;
  const pid_t child = fork();
  if (child < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    return false;
  }
  if (child == 0) {
    close(descriptors[0]);
    const int result = run_policy_child(descriptors[1]);
    close(descriptors[1]);
    _exit(result);
  }
  close(descriptors[1]);
  const size_t record_bytes = read_all(descriptors[0], record, sizeof(*record));
  close(descriptors[0]);
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);

  const int wait_error = waited < 0 ? errno : 0;
  const bool child_exited = waited == child && WIFEXITED(status);
  const int child_exit_status = child_exited ? WEXITSTATUS(status) : -1;
  const bool child_signaled = waited == child && WIFSIGNALED(status);
  const int child_signal = child_signaled ? WTERMSIG(status) : 0;
  const bool captured = record_bytes == sizeof(*record) && child_exited
      && child_exit_status == 0;
  if (!captured) {
    fprintf(stderr,
            "policy child capture failed: record_bytes=%zu expected_bytes=%zu "
            "waited=%ld expected_pid=%ld wait_errno=%d exited=%d exit_status=%d "
            "signaled=%d signal=%d options=%d arena_size=%zu committed=%d "
            "large_high=%d large_null=%d regular_hint=%d thp=%d\n",
            record_bytes, sizeof(*record), (long)waited, (long)child, wait_error,
            child_exited, child_exit_status, child_signaled, child_signal,
            record->source_options_applied, record->first_arena_size,
            record->first_arena_initially_committed, record->large_high_hint_failed,
            record->large_null_hint_retry_failed,
            record->regular_hinted_map_after_large_fallback,
            record->thp_advice_failure_ignored);
  }
  return captured;
}

/* This is a deliberately finite direct-included C oracle for
 * `src/os.c:344-430`. It uses fixed, non-replacing native mappings solely to
 * select the source branch geometry. Every allocation, partial free, source
 * warning disposition, MemoryId, and statistic transition remains in the
 * pinned C body. In particular, failed cleanup rows prove the source's actual
 * best-effort behavior before the Rust retained-owner boundary is compared in
 * a separate trace namespace. */
typedef enum aligned_overmap_case_e {
  ALIGNED_OVERMAP_DIRECT_ALIGNED,
  ALIGNED_OVERMAP_DIRECT_MAP_FAILURE_FALLBACK,
  ALIGNED_OVERMAP_PREFIX_ZERO_SUFFIX_ONLY,
  ALIGNED_OVERMAP_COMPLETE_CLEANUP,
  ALIGNED_OVERMAP_DIRECT_CLEANUP_FAILURE,
  ALIGNED_OVERMAP_PREFIX_CLEANUP_FAILURE,
  ALIGNED_OVERMAP_SUFFIX_CLEANUP_FAILURE,
} aligned_overmap_case_t;

typedef struct aligned_overmap_targets_s {
  void* direct_aligned;
  void* direct_unaligned;
  void* over_aligned;
  void* over_unaligned;
} aligned_overmap_targets_t;

typedef struct aligned_overmap_statistics_s {
  int64_t reserved_total;
  int64_t reserved_current;
  int64_t committed_total;
  int64_t committed_current;
  int64_t mmap_calls;
} aligned_overmap_statistics_t;

typedef struct aligned_overmap_matrix_record_s {
  bool normal_direct_aligned;
  bool direct_map_failure_fallback;
  bool prefix_zero_suffix_only;
  bool complete_direct_prefix_suffix_cleanup;
  bool direct_cleanup_failure_reserved_source_continues_escaped_live_stats;
  bool direct_cleanup_failure_committed_source_continues_escaped_live_stats;
  bool prefix_cleanup_failure_reserved_source_continues_escaped_live_stats;
  bool prefix_cleanup_failure_committed_source_continues_escaped_live_stats;
  bool suffix_cleanup_failure_reserved_source_continues_escaped_live_stats;
  bool suffix_cleanup_failure_committed_source_continues_escaped_live_stats;
} aligned_overmap_matrix_record_t;

static aligned_overmap_statistics_t aligned_overmap_statistics(
    const mi_subproc_t* subproc) {
  return (aligned_overmap_statistics_t){
      .reserved_total = total_reserved(subproc),
      .reserved_current = current_reserved(subproc),
      .committed_total = total_committed(subproc),
      .committed_current = current_committed(subproc),
      .mmap_calls = current_mmap_calls(subproc),
  };
}

static bool aligned_overmap_allocation_statistics_match(
    aligned_overmap_statistics_t before, const mi_subproc_t* subproc,
    size_t length, bool commit, int64_t maps) {
  const aligned_overmap_statistics_t after = aligned_overmap_statistics(subproc);
  const int64_t committed = commit ? (int64_t)length : 0;
  return after.mmap_calls == before.mmap_calls + maps
      && after.reserved_total == before.reserved_total + (int64_t)length
      && after.reserved_current == before.reserved_current + (int64_t)length
      && after.committed_total == before.committed_total + committed
      && after.committed_current == before.committed_current + committed;
}

static bool aligned_overmap_release_statistics_match(
    aligned_overmap_statistics_t before, const mi_subproc_t* subproc,
    size_t length, bool commit, int64_t maps) {
  const aligned_overmap_statistics_t after = aligned_overmap_statistics(subproc);
  const int64_t committed = commit ? (int64_t)length : 0;
  /* `mi_stat_decrease` restores current bytes but does not decrement total;
   * a source cleanup failure has already applied each partial adjustment.
   * This validates the observable source bookkeeping even when one physical
   * range remains live outside the returned MemoryId. */
  return after.mmap_calls == before.mmap_calls + maps
      && after.reserved_total == before.reserved_total + (int64_t)length
      && after.reserved_current == before.reserved_current
      && after.committed_total == before.committed_total + committed
      && after.committed_current == before.committed_current;
}

static bool aligned_overmap_prepare_targets(
    size_t page, size_t alignment, size_t over_length,
    aligned_overmap_targets_t* targets) {
  if (page == 0 || alignment < page || (alignment & (alignment - 1)) != 0
      || alignment > SIZE_MAX / 6
      || over_length > SIZE_MAX - 6 * alignment - page) {
    return false;
  }
  const size_t span = 6 * alignment + page + over_length;
  void* const reservation = __real_mmap(
      NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED) return false;
  const uintptr_t start = (uintptr_t)reservation;
  const uintptr_t end = start + span;
  const uintptr_t aligned = (start + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const uintptr_t direct_unaligned = aligned + page;
  const uintptr_t over_aligned = aligned + 2 * alignment;
  const uintptr_t over_unaligned = aligned + 4 * alignment + page;
  const bool fits = aligned >= start && direct_unaligned >= aligned
      && over_aligned >= direct_unaligned && over_unaligned >= over_aligned
      && over_unaligned <= end && over_length <= end - over_unaligned;
  const int release = __real_munmap(reservation, span);
  if (!fits || release != 0) return false;
  targets->direct_aligned = (void*)aligned;
  targets->direct_unaligned = (void*)direct_unaligned;
  targets->over_aligned = (void*)over_aligned;
  targets->over_unaligned = (void*)over_unaligned;
  return true;
}

static void aligned_overmap_begin(
    bool fail_direct_map, size_t fail_cleanup_ordinal,
    void* direct_target, void* over_target) {
  aligned_overmap_probe = (aligned_overmap_probe_t){
      .active = true,
      .fail_direct_map = fail_direct_map,
      .fail_cleanup_ordinal = fail_cleanup_ordinal,
      .phase = ALIGNED_OVERMAP_DIRECT,
      .direct_target = direct_target,
      .over_target = over_target,
  };
}

static bool aligned_overmap_mapping_is_live(void* address, size_t page) {
  unsigned char residency = 0;
  return mincore(address, page, &residency) == 0;
}

static bool aligned_overmap_cleanup_matches(
    const aligned_overmap_probe_t* probe, size_t expected_count,
    void* const expected_addresses[3], const size_t expected_lengths[3]) {
  if (probe->cleanup_munmap_calls != expected_count) return false;
  for (size_t index = 0; index < expected_count; index++) {
    if (probe->cleanup_addresses[index] != expected_addresses[index]
        || probe->cleanup_lengths[index] != expected_lengths[index]) {
      return false;
    }
  }
  return true;
}

static bool run_aligned_overmap_case(
    mi_subproc_t* subproc, aligned_overmap_case_t selected, bool commit) {
  const size_t page = _mi_os_page_size();
  const size_t length = 2 * page;
  const size_t alignment = 8 * page;
  const size_t over_length = length + alignment;
  if (page == 0 || length / 2 != page || alignment / 8 != page) return false;

  aligned_overmap_targets_t targets = {0};
  if (!aligned_overmap_prepare_targets(page, alignment, over_length, &targets)) return false;
  const bool direct_failure = selected == ALIGNED_OVERMAP_DIRECT_MAP_FAILURE_FALLBACK
      || selected == ALIGNED_OVERMAP_PREFIX_ZERO_SUFFIX_ONLY;
  const bool direct_aligned = selected == ALIGNED_OVERMAP_DIRECT_ALIGNED;
  const bool prefix_zero = selected == ALIGNED_OVERMAP_PREFIX_ZERO_SUFFIX_ONLY;
  const size_t cleanup_failure = selected == ALIGNED_OVERMAP_DIRECT_CLEANUP_FAILURE ? 1
      : selected == ALIGNED_OVERMAP_PREFIX_CLEANUP_FAILURE ? 2
      : selected == ALIGNED_OVERMAP_SUFFIX_CLEANUP_FAILURE ? 3 : 0;
  void* const direct_target = direct_aligned ? targets.direct_aligned : targets.direct_unaligned;
  void* const over_target = prefix_zero ? targets.over_aligned : targets.over_unaligned;
  const uintptr_t over_base = (uintptr_t)over_target;
  const uintptr_t aligned_address = (over_base + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const size_t prefix = (size_t)(aligned_address - over_base);
  const size_t suffix = over_length - prefix - length;
  if (prefix >= over_length || suffix >= over_length || prefix + suffix + length != over_length) {
    return false;
  }

  void* expected_addresses[3] = {NULL, NULL, NULL};
  size_t expected_lengths[3] = {0, 0, 0};
  size_t expected_cleanup_count = 0;
  if (!direct_failure && !direct_aligned) {
    expected_addresses[expected_cleanup_count] = direct_target;
    expected_lengths[expected_cleanup_count++] = length;
  }
  if (!direct_aligned && prefix != 0) {
    expected_addresses[expected_cleanup_count] = over_target;
    expected_lengths[expected_cleanup_count++] = prefix;
  }
  if (!direct_aligned && suffix != 0) {
    expected_addresses[expected_cleanup_count] = (void*)(aligned_address + length);
    expected_lengths[expected_cleanup_count++] = suffix;
  }

  const aligned_overmap_statistics_t before = aligned_overmap_statistics(subproc);
  mi_memid_t memid = _mi_memid_none();
  aligned_overmap_begin(direct_failure, cleanup_failure, direct_target, over_target);
  void* const result = _mi_os_alloc_aligned(
      subproc, length, alignment, commit, false /* allow_large */, &memid);
  const aligned_overmap_probe_t probe = aligned_overmap_probe;
  aligned_overmap_probe.active = false;

  const int64_t expected_maps = direct_aligned ? 1 : 2;
  const void* const expected_result = direct_aligned ? direct_target : (void*)aligned_address;
  bool complete = result == expected_result
      && memid.mem.os.base == expected_result
      && memid.mem.os.size == length
      && memid.initially_committed == commit
      && probe.over_mmap_calls == (direct_aligned ? 0 : 1)
      && (direct_failure ? probe.direct_mmap_calls >= 1 : probe.direct_mmap_calls == 1)
      && aligned_overmap_cleanup_matches(
          &probe, expected_cleanup_count, expected_addresses, expected_lengths)
      && aligned_overmap_allocation_statistics_match(
          before, subproc, length, commit, expected_maps);
  if (result == NULL) return false;

  void* escaped_address = NULL;
  size_t escaped_length = 0;
  if (cleanup_failure == 1) {
    escaped_address = direct_target;
    escaped_length = length;
  } else if (cleanup_failure == 2) {
    escaped_address = over_target;
    escaped_length = prefix;
  } else if (cleanup_failure == 3) {
    escaped_address = (void*)(aligned_address + length);
    escaped_length = suffix;
  }
  if (escaped_address != NULL) {
    complete = complete && escaped_length != 0
        && aligned_overmap_mapping_is_live(escaped_address, page);
  }

  _mi_os_free_ex(subproc, result, length, commit, memid);
  complete = complete && aligned_overmap_release_statistics_match(
      before, subproc, length, commit, expected_maps);
  if (escaped_address != NULL) {
    /* This is the source-observable mismatch: `memid` frees only the returned
     * middle while a failed best-effort cleanup range remains mapped. The
     * raw cleanup below is fixture teardown, not a source retry. */
    complete = complete && aligned_overmap_mapping_is_live(escaped_address, page)
        && __real_munmap(escaped_address, escaped_length) == 0;
  }
  return complete;
}

static int run_aligned_overmap_matrix_child(int record_descriptor) {
  aligned_overmap_matrix_record_t record = {0};
  _mi_os_init();
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) return 1;
  record.normal_direct_aligned = run_aligned_overmap_case(
      subproc, ALIGNED_OVERMAP_DIRECT_ALIGNED, false);
  record.direct_map_failure_fallback = run_aligned_overmap_case(
      subproc, ALIGNED_OVERMAP_DIRECT_MAP_FAILURE_FALLBACK, false);
  record.prefix_zero_suffix_only = run_aligned_overmap_case(
      subproc, ALIGNED_OVERMAP_PREFIX_ZERO_SUFFIX_ONLY, false);
  record.complete_direct_prefix_suffix_cleanup = run_aligned_overmap_case(
      subproc, ALIGNED_OVERMAP_COMPLETE_CLEANUP, false);
  record.direct_cleanup_failure_reserved_source_continues_escaped_live_stats =
      run_aligned_overmap_case(subproc, ALIGNED_OVERMAP_DIRECT_CLEANUP_FAILURE, false);
  record.direct_cleanup_failure_committed_source_continues_escaped_live_stats =
      run_aligned_overmap_case(subproc, ALIGNED_OVERMAP_DIRECT_CLEANUP_FAILURE, true);
  record.prefix_cleanup_failure_reserved_source_continues_escaped_live_stats =
      run_aligned_overmap_case(subproc, ALIGNED_OVERMAP_PREFIX_CLEANUP_FAILURE, false);
  record.prefix_cleanup_failure_committed_source_continues_escaped_live_stats =
      run_aligned_overmap_case(subproc, ALIGNED_OVERMAP_PREFIX_CLEANUP_FAILURE, true);
  record.suffix_cleanup_failure_reserved_source_continues_escaped_live_stats =
      run_aligned_overmap_case(subproc, ALIGNED_OVERMAP_SUFFIX_CLEANUP_FAILURE, false);
  record.suffix_cleanup_failure_committed_source_continues_escaped_live_stats =
      run_aligned_overmap_case(subproc, ALIGNED_OVERMAP_SUFFIX_CLEANUP_FAILURE, true);
  if (!write_all(record_descriptor, &record, sizeof(record))) return 2;
  return record.normal_direct_aligned
      && record.direct_map_failure_fallback
      && record.prefix_zero_suffix_only
      && record.complete_direct_prefix_suffix_cleanup
      && record.direct_cleanup_failure_reserved_source_continues_escaped_live_stats
      && record.direct_cleanup_failure_committed_source_continues_escaped_live_stats
      && record.prefix_cleanup_failure_reserved_source_continues_escaped_live_stats
      && record.prefix_cleanup_failure_committed_source_continues_escaped_live_stats
      && record.suffix_cleanup_failure_reserved_source_continues_escaped_live_stats
      && record.suffix_cleanup_failure_committed_source_continues_escaped_live_stats ? 0 : 3;
}

static bool capture_aligned_overmap_matrix_child(
    aligned_overmap_matrix_record_t* record) {
  int descriptors[2];
  if (pipe(descriptors) != 0) return false;
  const pid_t child = fork();
  if (child < 0) {
    close(descriptors[0]);
    close(descriptors[1]);
    return false;
  }
  if (child == 0) {
    close(descriptors[0]);
    const int result = run_aligned_overmap_matrix_child(descriptors[1]);
    close(descriptors[1]);
    _exit(result);
  }
  close(descriptors[1]);
  const size_t record_bytes = read_all(descriptors[0], record, sizeof(*record));
  close(descriptors[0]);
  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  const bool captured = record_bytes == sizeof(*record)
      && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
  if (!captured) {
    fprintf(stderr,
            "aligned-overmap child failed: bytes=%zu expected=%zu waited=%ld expected_pid=%ld "
            "errno=%d exited=%d status=%d\n",
            record_bytes, sizeof(*record), (long)waited, (long)child,
            waited < 0 ? errno : 0, waited == child && WIFEXITED(status),
            waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  }
  return captured;
}

#if defined(CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE)

#define ALIGNED_HINT_SOURCE_PROFILE_BEGIN \
  "CRABC_MI_M2_ALIGNED_HINT_SOURCE_PROFILE_TRACE_BEGIN"
#define ALIGNED_HINT_SOURCE_PROFILE_END \
  "CRABC_MI_M2_ALIGNED_HINT_SOURCE_PROFILE_TRACE_END"

/* These are separate profile binaries rather than a fixture-owned option
 * setting. The source preprocessor has already selected MI_DEBUG/MI_SECURE
 * before this file enters `_mi_os_get_aligned_hint`; the fixture only observes
 * that exact selected body. `MI_PRIM_HAS_PROCESS_ATTACH=1` leaves startup
 * explicit, so profile children start from the same zero static cursor and
 * default-Theap preimage as the normal-release cold receiver. */
static void aligned_hint_profile_trace_begin(void) {
  puts(ALIGNED_HINT_SOURCE_PROFILE_BEGIN);
}

static void aligned_hint_profile_trace_end(void) {
  puts(ALIGNED_HINT_SOURCE_PROFILE_END);
}

static int run_aligned_hint_debug_profile(void) {
  _mi_os_init();
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  mi_theap_t* const theap = _mi_theap_default();
  if (_mi_process_is_initialized || mi_theap_is_initialized(theap)) return 1;

  const size_t request = aligned_hint_request_size(alignment, page);
  void* const hint = aligned_hint_capture_call(alignment, page);
  const bool no_default_random = hint == (void*)MI_HINT_BASE
      && !mi_theap_is_initialized(theap)
      && aligned_hint_atomic_record.cursor_consistent
      && aligned_hint_atomic_record.fetch_count == 2
      && aligned_hint_atomic_record.fetch_old[0] == 0
      && aligned_hint_atomic_record.fetch_add[0] == request
      && aligned_hint_atomic_record.cas_count == 1
      && aligned_hint_atomic_record.cas_succeeded
      && aligned_hint_atomic_record.fetch_old[1] == MI_HINT_BASE;
  if (!no_default_random) return 2;

  aligned_hint_profile_trace_begin();
  U("m2.vm.aligned_hint.profile.debug_without_default_random", no_default_random);
  aligned_hint_profile_trace_end();
  return 0;
}

static int run_aligned_hint_secure_cold_child(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  mi_theap_t* const theap = _mi_theap_default();
  if (_mi_process_is_initialized || mi_theap_is_initialized(theap)) return 1;
  void* const hint = aligned_hint_capture_call(alignment, page);
  return hint == NULL && !mi_theap_is_initialized(theap)
      && aligned_hint_atomic_record.cursor_consistent
      && aligned_hint_atomic_record.fetch_count == 1
      && aligned_hint_atomic_record.fetch_old[0] == 0
      && aligned_hint_atomic_record.cas_count == 0 ? 0 : 2;
}

static int run_aligned_hint_secure_oversized_child(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  const size_t exact_boundary = 32 * MI_GiB - alignment - page;
  mi_theap_t* const theap = _mi_theap_default();
  if (_mi_process_is_initialized || mi_theap_is_initialized(theap)
      || aligned_hint_request_size(alignment, exact_boundary) != 32 * MI_GiB) return 1;
  void* const hint = aligned_hint_capture_call(alignment, exact_boundary + page);
  return hint == NULL && !mi_theap_is_initialized(theap)
      && aligned_hint_atomic_record.fetch_count == 0
      && aligned_hint_atomic_record.cas_count == 0
      && aligned_hint_atomic_record.cursor == NULL ? 0 : 2;
}

static int run_aligned_hint_secure_boundary_child(void) {
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  const size_t exact_boundary = 32 * MI_GiB - alignment - page;
  mi_process_init();
  mi_theap_t* const theap = _mi_theap_default();
  if (!stage_initialized_aligned_hint_random(theap, 1, 2)) return 1;
  const size_t request = aligned_hint_request_size(alignment, exact_boundary);
  void* const hint = aligned_hint_capture_call(alignment, exact_boundary);
  return request == 32 * MI_GiB
      && aligned_hint_record_is_one_initial_randomized_start(hint, request, true)
      && theap->random.output_available == 14 ? 0 : 2;
}

static int run_aligned_hint_secure_profile(void) {
  _mi_os_init();
  const bool cold_requires_random = capture_aligned_hint_child(
      "secure aligned-hint cold default", run_aligned_hint_secure_cold_child);
  const bool oversized_skips_cursor_and_random = capture_aligned_hint_child(
      "secure aligned-hint oversized request", run_aligned_hint_secure_oversized_child);
  const bool exact_boundary_randomizes = capture_aligned_hint_child(
      "secure aligned-hint exact boundary", run_aligned_hint_secure_boundary_child);
  if (!cold_requires_random || !oversized_skips_cursor_and_random || !exact_boundary_randomizes) {
    return 1;
  }

  aligned_hint_profile_trace_begin();
  U("m2.vm.aligned_hint.profile.secure_requires_default_random", cold_requires_random);
  U("m2.vm.aligned_hint.profile.secure_oversized_skips_cursor_and_random",
      oversized_skips_cursor_and_random);
  U("m2.vm.aligned_hint.profile.secure_exact_boundary_randomizes",
      exact_boundary_randomizes);
  aligned_hint_profile_trace_end();
  return 0;
}

static int run_aligned_hint_wrapped_direct_caller_child(void) {
  _mi_os_init();
  mi_process_init();
  const size_t page = _mi_os_page_size();
  const size_t alignment = 2 * MI_MiB;
  const size_t length = SIZE_MAX & ~(page - 1);
  mi_theap_t* const theap = _mi_theap_default();
  if (!stage_initialized_aligned_hint_random(theap, 1, 2)
      || length + page != 0
      || aligned_hint_request_size(alignment, length) != alignment) return 1;

  captured_aligned_hint_direct_calls = 0;
  captured_aligned_hint_direct_addresses[0] = NULL;
  captured_aligned_hint_direct_addresses[1] = NULL;
  captured_aligned_hint_direct_lengths[0] = 0;
  captured_aligned_hint_direct_lengths[1] = 0;
  bool is_large = true;
  bool is_zero = false;
  void* result = (void*)1;
  aligned_hint_capture_begin();
  capture_aligned_hint_direct_caller = true;
  const int error = _mi_prim_alloc(NULL, length, alignment, false, false,
                                   &is_large, &is_zero, &result);
  capture_aligned_hint_direct_caller = false;
  aligned_hint_atomic_record.active = false;
  const bool failed_without_owner = error != 0 && result == NULL && !is_large && is_zero;
  const bool hint_then_null = captured_aligned_hint_direct_calls == 2
      && captured_aligned_hint_direct_addresses[0] == (void*)MI_HINT_BASE
      && captured_aligned_hint_direct_addresses[1] == NULL
      && captured_aligned_hint_direct_lengths[0] == length
      && captured_aligned_hint_direct_lengths[1] == length;
  const bool source_cursor = aligned_hint_record_is_one_initial_randomized_start(
      (void*)MI_HINT_BASE, alignment, true) && theap->random.output_available == 14;
  return failed_without_owner && hint_then_null && source_cursor ? 0 : 2;
}

static int run_aligned_hint_wrapped_direct_caller_profile(void) {
  const bool hinted_then_null_without_owner = capture_aligned_hint_child(
      "wrapped aligned-hint direct caller", run_aligned_hint_wrapped_direct_caller_child);
  if (!hinted_then_null_without_owner) return 1;
  aligned_hint_profile_trace_begin();
  U("m2.vm.aligned_hint.profile.wrapped_direct_caller_hint_then_null_without_owner",
      hinted_then_null_without_owner);
  aligned_hint_profile_trace_end();
  return 0;
}

int main(void) {
#if CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE == 1
  return run_aligned_hint_debug_profile();
#elif CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE == 2
  return run_aligned_hint_secure_profile();
#elif CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE == 3
  return run_aligned_hint_wrapped_direct_caller_profile();
#else
#error "CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE must select debug, secure, or release direct caller"
#endif
}

#else
int main(void) {
  /* This fork is the literal constructor-suppressed source preimage. The
   * child proves `_mi_os_get_aligned_hint` advances its zero static cursor
   * before refusing to use `_mi_theap_empty`; all mutations are COW, so the
   * parent remains cold for the separately selected policy child below. */
  aligned_overmap_matrix_record_t aligned_overmap_record = {0};
  if (!capture_aligned_overmap_matrix_child(&aligned_overmap_record)) return 40;
  const bool aligned_hint_cold_missing_default_advances =
      capture_aligned_hint_cold_child();
  if (!aligned_hint_cold_missing_default_advances) return 38;
  policy_child_record_t policy_record = {0};
  if (!capture_policy_child(&policy_record)) return 8;
  /* The direct external callback receiver requires the same complete source
   * process and main-theap owner as `mi_manage_memory`, rather than only the
   * low-level OS statistics image used by the fixed primitive records. */
  _mi_options_init();
  /* Select the source `allow_thp=0` option before the exact `_mi_os_init`
   * call. This executable is its own native evidence process, so its
   * process-local `PR_SET_THP_DISABLE` transition cannot alter the runner. */
  mi_option_set(mi_option_allow_thp, 0);
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) return 10;

  /* Each normal-release row inherits the parent’s initialized Theap and its
   * still-zero cursor. Their source cursor/rand mutations are COW; only the
   * final parent receiver consumes the actual live first randomized start. */
  const bool aligned_hint_eligibility_geometry =
      capture_aligned_hint_eligibility_child();
  const bool aligned_hint_strict_threshold_and_one_draw =
      capture_aligned_hint_threshold_child();
  const bool aligned_hint_ignored_cas_failure =
      capture_aligned_hint_cas_child();
  const bool aligned_hint_initialized_first_start =
      capture_aligned_hint_initialized_parent();
  if (!aligned_hint_eligibility_geometry
      || !aligned_hint_strict_threshold_and_one_draw
      || !aligned_hint_ignored_cas_failure
      || !aligned_hint_initialized_first_start) return 39;

  const size_t page = _mi_os_page_size();
  const size_t alignment = page * 16;
  const bool thp_process_disabled =
      (prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0) == 1);
  if (page == 0 || alignment / 16 != page) return 11;

  mi_memid_t reserved_id = _mi_memid_none();
  void* const reserved = _mi_os_alloc_aligned(
      subproc, page, page, false /* commit */, false /* allow_large */, &reserved_id);
  if (reserved == NULL || reserved_id.initially_committed || !reserved_id.initially_zero) {
    return 12;
  }
  /* `_mi_os_commit_ex` increments its call counter before it reaches the
   * Unix mprotect failure, but only adjusts committed bytes after success.
   * The source returns false and leaves this reserved MemoryId live for the
   * next caller-selected attempt. */
  const int64_t committed_before_failed_commit = current_committed(subproc);
  capture_transition_mprotect = true;
  fail_next_mprotect = true;
  bool failed_commit_is_zero = true;
  const bool commit_failure_returns_false =
      !_mi_os_commit(subproc, reserved, page, &failed_commit_is_zero);
  const int64_t committed_after_failed_commit = current_committed(subproc);
  const bool commit_failure_is_one_source_attempt =
      captured_transition_mprotect_calls == 1
      && captured_transition_protections[0] == (PROT_READ | PROT_WRITE)
      && !failed_commit_is_zero
      && committed_after_failed_commit == committed_before_failed_commit;
  bool commit_is_zero = true;
  if (!_mi_os_commit(subproc, reserved, page, &commit_is_zero)) return 13;
  const bool commit_retry_is_one_additional_source_attempt =
      captured_transition_mprotect_calls == 2
      && captured_transition_protections[1] == (PROT_READ | PROT_WRITE);
  capture_transition_mprotect = false;
  if (!commit_failure_returns_false || !commit_failure_is_one_source_attempt
      || !commit_retry_is_one_additional_source_attempt) return 14;

  /* The default Unix decommit leaves this release-profile mapping accessible.
   * A failed MADV_DONTNEED reports false without changing the MemoryId or
   * forcing a hidden mprotect retry; the next explicit source call succeeds. */
  capture_transition_madvise = true;
  fail_next_madvise_dontneed = true;
  const bool decommit_failure_returns_false = !_mi_os_decommit(subproc, reserved, page);
  const bool decommit_failure_is_one_source_attempt =
      captured_transition_madvise_calls == 1
      && captured_transition_advices[0] == MADV_DONTNEED;
  if (!_mi_os_decommit(subproc, reserved, page)) return 15;
  const bool decommit_retry_is_one_additional_source_attempt =
      captured_transition_madvise_calls == 2
      && captured_transition_advices[1] == MADV_DONTNEED;
  capture_transition_madvise = false;
  if (!decommit_failure_returns_false || !decommit_failure_is_one_source_attempt
      || !decommit_retry_is_one_additional_source_attempt) return 16;

  /* The source reset cache starts at MADV_FREE.  An EINVAL changes its
   * process-global advice to MADV_DONTNEED and retries that same primitive;
   * subsequent fixed purge branches therefore observe the changed source
   * state, never an invented general advice fallback. */
  captured_transition_madvise_calls = 0;
  capture_transition_madvise = true;
  fail_next_madvise_free_einval = true;
  const bool reset_free_einval_falls_back_to_dontneed =
      _mi_os_reset(subproc, reserved, page)
      && captured_transition_madvise_calls == 2
      && captured_transition_advices[0] == MADV_FREE
      && captured_transition_advices[1] == MADV_DONTNEED;
  capture_transition_madvise = false;
  if (!reset_free_einval_falls_back_to_dontneed) return 17;

  /* Exercise both no-callback `_mi_os_purge_ex` option arms after the
   * fallback. The normal Unix decommit writes `needs_recommit = false` even
   * after its madvise error; a reset error is advisory and is likewise
   * consumed by the source's fixed false outcome. */
  captured_transition_madvise_calls = 0;
  capture_transition_madvise = true;
  /* `src/init.c` owns this private source bit. Select the ordinary
   * post-startup receiver before recording the decommit option arm. */
  os_preloading = false;
  mi_option_set(mi_option_purge_decommits, 1);
  fail_next_madvise_dontneed = true;
  const bool purge_decommit_failure_no_recommit =
      !_mi_os_purge(subproc, reserved, page)
      && captured_transition_madvise_calls == 1
      && captured_transition_advices[0] == MADV_DONTNEED
      && !fail_next_madvise_dontneed;
  const bool purge_decommit_retry_no_recommit =
      !_mi_os_purge(subproc, reserved, page)
      && captured_transition_madvise_calls == 2
      && captured_transition_advices[1] == MADV_DONTNEED;
  mi_option_set(mi_option_purge_decommits, 0);
  fail_next_madvise_dontneed = true;
  const bool purge_reset_failure_is_consumed =
      !_mi_os_purge(subproc, reserved, page)
      && captured_transition_madvise_calls == 3
      && captured_transition_advices[2] == MADV_DONTNEED
      && !fail_next_madvise_dontneed;
  capture_transition_madvise = false;
  if (!purge_decommit_failure_no_recommit || !purge_decommit_retry_no_recommit
      || !purge_reset_failure_is_consumed) {
    fprintf(stderr,
            "purge_decommit_failure_no_recommit=%d "
            "purge_decommit_retry_no_recommit=%d "
            "purge_reset_failure_is_consumed=%d purge_decommits=%ld "
            "purge_delay=%ld pending_dontneed_fault=%d\n",
            purge_decommit_failure_no_recommit,
            purge_decommit_retry_no_recommit,
            purge_reset_failure_is_consumed,
            mi_option_get(mi_option_purge_decommits),
            mi_option_get(mi_option_purge_delay),
            fail_next_madvise_dontneed);
    return 18;
  }

  mi_memid_t purge_matrix_id = _mi_memid_none();
  void* const purge_matrix_mapping = _mi_os_alloc_aligned(
      subproc, page * 3, page, true /* commit */, false /* allow_large */, &purge_matrix_id);
  if (purge_matrix_mapping == NULL || purge_matrix_id.mem.os.base != purge_matrix_mapping
      || purge_matrix_id.mem.os.size != page * 3) return 31;
  const bool normal_no_callback_purge_matrix =
      capture_normal_no_callback_purge_matrix(subproc, purge_matrix_mapping, page);
  _mi_os_free(subproc, purge_matrix_mapping, page * 3, purge_matrix_id);
  if (!normal_no_callback_purge_matrix) return 31;

  _mi_os_reuse(subproc, reserved, page);
  captured_transition_mprotect_calls = 0;
  capture_transition_mprotect = true;
  fail_next_mprotect = true;
  const bool protect_failure_returns_false = !_mi_os_protect(reserved, page);
  const bool protect_failure_is_one_source_attempt =
      captured_transition_mprotect_calls == 1
      && captured_transition_protections[0] == PROT_NONE;
  if (!_mi_os_protect(reserved, page)) return 19;
  const bool protect_retry_is_one_additional_source_attempt =
      captured_transition_mprotect_calls == 2
      && captured_transition_protections[1] == PROT_NONE;
  fail_next_mprotect = true;
  const bool unprotect_failure_returns_false = !_mi_os_unprotect(reserved, page);
  const bool unprotect_failure_is_one_source_attempt =
      captured_transition_mprotect_calls == 3
      && captured_transition_protections[2] == (PROT_READ | PROT_WRITE);
  if (!_mi_os_unprotect(reserved, page)) return 20;
  const bool unprotect_retry_is_one_additional_source_attempt =
      captured_transition_mprotect_calls == 4
      && captured_transition_protections[3] == (PROT_READ | PROT_WRITE);
  capture_transition_mprotect = false;
  if (!protect_failure_returns_false || !protect_failure_is_one_source_attempt
      || !protect_retry_is_one_additional_source_attempt
      || !unprotect_failure_returns_false || !unprotect_failure_is_one_source_attempt
      || !unprotect_retry_is_one_additional_source_attempt) return 21;
  _mi_os_free(subproc, reserved, page, reserved_id);

  mi_memid_t normal_id = _mi_memid_none();
  void* const normal = _mi_os_alloc(subproc, page + 1, &normal_id);
  const size_t normal_size = _mi_os_good_alloc_size(page + 1);
  if (normal == NULL || normal_id.mem.os.base != normal || normal_id.mem.os.size != normal_size
      || !normal_id.initially_committed || !normal_id.initially_zero) return 22;
  _mi_os_free(subproc, normal, page + 1, normal_id);

  mi_memid_t aligned_id = _mi_memid_none();
  void* const aligned = _mi_os_alloc_aligned(
      subproc, page, alignment, true /* commit */, false /* allow_large */, &aligned_id);
  const size_t aligned_size = _mi_os_good_alloc_size(page);
  if (aligned == NULL || ((uintptr_t)aligned % alignment) != 0
      || aligned_id.mem.os.base != aligned || aligned_id.mem.os.size != aligned_size) return 23;
  _mi_os_free(subproc, aligned, page, aligned_id);

  const size_t offset = page;
  const size_t offset_request = page * 2;
  mi_memid_t offset_id = _mi_memid_none();
  void* const offset_client = _mi_os_alloc_aligned_at_offset(
      subproc, offset_request, alignment, offset, true /* commit */, false /* allow_large */,
      &offset_id);
  const size_t offset_size = _mi_os_good_alloc_size(offset_request + alignment - offset);
  if (offset_client == NULL || offset_id.mem.os.base == offset_client
      || ((uintptr_t)offset_client + offset) % alignment != 0
      || offset_id.mem.os.size != offset_size) return 24;
  _mi_os_free(subproc, offset_client, offset_request, offset_id);

  /* `src/os.c:521-525` calls its regular decommit primitive after a successful
   * process-owned offset allocation and intentionally ignores that primitive's
   * result. Observe both outcomes before full-ID release. This is not an
   * allocation rollback: in both records the client remains interior and the
   * source retains the complete base/length `mi_memid_t` owner. */
  const size_t offset_prefix = _mi_align_up(offset, alignment) - offset;
  const size_t offset_full_size = _mi_os_good_alloc_size(offset_request + offset_prefix);
  const int64_t offset_success_reserved_before = current_reserved(subproc);
  const int64_t offset_success_committed_before = current_committed(subproc);
  mi_memid_t offset_success_id = _mi_memid_none();
  captured_transition_madvise_calls = 0;
  capture_transition_madvise = true;
  void* const offset_success_client = _mi_os_alloc_aligned_at_offset(
      subproc, offset_request, alignment, offset, true /* commit */, false /* allow_large */,
      &offset_success_id);
  capture_transition_madvise = false;
  const int64_t offset_success_reserved_after_allocate = current_reserved(subproc);
  const int64_t offset_success_committed_after_allocate = current_committed(subproc);
  const bool offset_prefix_decommit_success_attempt_and_full_owner =
      offset_success_client != NULL
      && offset_success_id.mem.os.base != offset_success_client
      && offset_success_id.mem.os.size == offset_full_size
      && (size_t)((uint8_t*)offset_success_client - (uint8_t*)offset_success_id.mem.os.base)
          == offset_prefix
      && captured_transition_madvise_calls == 1
      && captured_transition_advices[0] == MADV_DONTNEED
      && offset_success_reserved_after_allocate
          == offset_success_reserved_before + (int64_t)offset_success_id.mem.os.size
      && offset_success_committed_after_allocate
          == offset_success_committed_before + (int64_t)offset_success_id.mem.os.size;
  if (!offset_prefix_decommit_success_attempt_and_full_owner) return 32;
  _mi_os_free(subproc, offset_success_client, offset_request, offset_success_id);
  if (current_reserved(subproc) != offset_success_reserved_before
      || current_committed(subproc) != offset_success_committed_before + (int64_t)offset_prefix) {
    return 33;
  }

  const int64_t offset_failure_reserved_before = current_reserved(subproc);
  const int64_t offset_failure_committed_before = current_committed(subproc);
  mi_memid_t offset_failure_id = _mi_memid_none();
  captured_transition_madvise_calls = 0;
  capture_transition_madvise = true;
  fail_next_madvise_dontneed = true;
  void* const offset_failure_client = _mi_os_alloc_aligned_at_offset(
      subproc, offset_request, alignment, offset, true /* commit */, false /* allow_large */,
      &offset_failure_id);
  capture_transition_madvise = false;
  const int64_t offset_failure_reserved_after_allocate = current_reserved(subproc);
  const int64_t offset_failure_committed_after_allocate = current_committed(subproc);
  const bool offset_prefix_decommit_failure_attempt_consumed_and_full_owner =
      offset_failure_client != NULL
      && offset_failure_id.mem.os.base != offset_failure_client
      && offset_failure_id.mem.os.size == offset_full_size
      && (size_t)((uint8_t*)offset_failure_client - (uint8_t*)offset_failure_id.mem.os.base)
          == offset_prefix
      && captured_transition_madvise_calls == 1
      && captured_transition_advices[0] == MADV_DONTNEED
      && !fail_next_madvise_dontneed
      && offset_failure_reserved_after_allocate
          == offset_failure_reserved_before + (int64_t)offset_failure_id.mem.os.size
      && offset_failure_committed_after_allocate
          == offset_failure_committed_before + (int64_t)offset_failure_id.mem.os.size;
  if (!offset_prefix_decommit_failure_attempt_consumed_and_full_owner) return 34;
  if (mprotect(offset_failure_id.mem.os.base, offset_failure_id.mem.os.size,
               PROT_READ | PROT_WRITE) != 0) return 35;
  _mi_os_free(subproc, offset_failure_client, offset_request, offset_failure_id);
  if (current_reserved(subproc) != offset_failure_reserved_before
      || current_committed(subproc) != offset_failure_committed_before + (int64_t)offset_prefix) {
    return 36;
  }

  /* `_mi_os_free_ex` must use the complete MemoryId base/size even though its
   * client pointer is interior.  The source primitive reports `munmap`
   * failure but still applies its named subprocess statistics transition.
   * The Rust owner keeps that full mapping live for an explicit retry, so
   * make the pinned-C result observable before releasing the same ID again. */
  mi_memid_t failed_release_id = _mi_memid_none();
  void* const failed_release_client = _mi_os_alloc_aligned_at_offset(
      subproc, offset_request, alignment, offset, true /* commit */, false /* allow_large */,
      &failed_release_id);
  if (failed_release_client == NULL || failed_release_id.mem.os.base == failed_release_client
      || failed_release_id.mem.os.size == 0) return 25;
  const size_t failed_release_prefix =
      (size_t)((uint8_t*)failed_release_client - (uint8_t*)failed_release_id.mem.os.base);
  if (failed_release_prefix >= failed_release_id.mem.os.size) return 26;
  const size_t failed_release_commit_size = failed_release_id.mem.os.size - failed_release_prefix;
  const int64_t reserved_before_failure = current_reserved(subproc);
  const int64_t committed_before_failure = current_committed(subproc);
  const size_t munmap_before_failure = wrapped_munmap_calls;
  capture_release_munmap = true;
  fail_next_munmap = true;
  _mi_os_free(subproc, failed_release_client, offset_request, failed_release_id);
  const int64_t reserved_after_failure = current_reserved(subproc);
  const int64_t committed_after_failure = current_committed(subproc);
  const size_t munmap_after_failure = wrapped_munmap_calls;
  if (munmap_after_failure != munmap_before_failure + 1
      || captured_release_munmap_calls != 1
      || captured_release_munmap_addresses[0] != failed_release_id.mem.os.base
      || captured_release_munmap_lengths[0] != failed_release_id.mem.os.size
      || reserved_after_failure != reserved_before_failure - (int64_t)failed_release_id.mem.os.size
      || committed_after_failure != committed_before_failure - (int64_t)failed_release_commit_size) {
    return 27;
  }
  /* A successful range-wide protection change proves the full base/length
   * mapping remains live after the injected primitive error. */
  if (mprotect(failed_release_id.mem.os.base, failed_release_id.mem.os.size,
               PROT_READ | PROT_WRITE) != 0) return 28;
  _mi_os_free(subproc, failed_release_client, offset_request, failed_release_id);
  const int64_t reserved_after_retry = current_reserved(subproc);
  const int64_t committed_after_retry = current_committed(subproc);
  const size_t munmap_after_retry = wrapped_munmap_calls;
  if (munmap_after_retry != munmap_after_failure + 1 || last_real_munmap_result != 0
      || captured_release_munmap_calls != 2
      || captured_release_munmap_addresses[1] != failed_release_id.mem.os.base
      || captured_release_munmap_lengths[1] != failed_release_id.mem.os.size
      || reserved_after_retry != reserved_after_failure - (int64_t)failed_release_id.mem.os.size
      || committed_after_retry != committed_after_failure - (int64_t)failed_release_commit_size) {
    return 29;
  }
  capture_release_munmap = false;

  const external_callback_result_t external_callback =
      capture_external_callback_arena(subproc);
  if (!external_callback.managed_external_owner
      || !external_callback.commit_zero_propagated
      || !external_callback.purge_raw_span_null_zero_and_statistics
      || !external_callback.purge_true_clears_commit
      || !external_callback.recommit_reinvokes_callback
      || !external_callback.purge_false_preserves_commit
      || !external_callback.purge_mixed_clears_commit
      || !external_callback.negative_delay_skips_callback_and_statistics
      || !external_callback.no_normal_advice
      || !external_callback.one_published_owner_per_registry
      || !external_callback.page_extension_direct_commit_fault_bypasses_callback
      || !external_callback.page_extension_failure_preserves_unpublished_state
      || !external_callback.page_extension_retry_commits_without_callback) {
    return 37;
  }

  const int numa_count = _mi_os_numa_node_count();
  const int numa_current = _mi_os_numa_node();
  if (numa_count < 1 || numa_current < 0 || numa_current >= numa_count) return 30;

  puts("CRABC_MI_M2_VM_TRACE_BEGIN");
  U("m2.vm.config.page_size", page);
  U("m2.vm.config.large_page_size", _mi_os_large_page_size());
  U("m2.vm.config.alloc_granularity", mi_os_mem_config.alloc_granularity);
  U("m2.vm.config.has_overcommit", mi_os_mem_config.has_overcommit);
  U("m2.vm.config.has_partial_free", mi_os_mem_config.has_partial_free);
  U("m2.vm.config.has_virtual_reserve", mi_os_mem_config.has_virtual_reserve);
  U("m2.vm.config.has_transparent_huge_pages", mi_os_mem_config.has_transparent_huge_pages);
  U("m2.vm.thp.process_disabled", thp_process_disabled);
  U("m2.vm.reserved.initially_zero", reserved_id.initially_zero);
  U("m2.vm.reserved.initially_committed", reserved_id.initially_committed);
  U("m2.vm.reserved.commit.failure_returns_false", commit_failure_returns_false);
  U("m2.vm.reserved.commit.failure.one_source_attempt_and_counters_unchanged",
      commit_failure_is_one_source_attempt);
  U("m2.vm.reserved.commit.retry.one_additional_source_attempt",
      commit_retry_is_one_additional_source_attempt);
  U("m2.vm.reserved.commit_not_known_zero", !commit_is_zero);
  U("m2.vm.reserved.decommit.failure_returns_false", decommit_failure_returns_false);
  U("m2.vm.reserved.decommit.failure.one_source_attempt",
      decommit_failure_is_one_source_attempt);
  U("m2.vm.reserved.decommit.retry.one_additional_source_attempt",
      decommit_retry_is_one_additional_source_attempt);
  U("m2.vm.reserved.decommit_no_recommit", 1);
  U("m2.vm.reserved.reset.madv_free_einval_falls_back_to_dontneed",
      reset_free_einval_falls_back_to_dontneed);
  U("m2.vm.reserved.reset_success", 1);
  U("m2.vm.reserved.purge.decommit_failure_no_recommit",
      purge_decommit_failure_no_recommit);
  U("m2.vm.reserved.purge.decommit_retry_no_recommit",
      purge_decommit_retry_no_recommit);
  U("m2.vm.reserved.purge.reset_failure_is_consumed",
      purge_reset_failure_is_consumed);
  U("m2.vm.reserved.purge.normal_no_callback_policy_range_matrix",
      normal_no_callback_purge_matrix);
  U("m2.vm.reserved.reuse_linux_noop", 1);
  U("m2.vm.reserved.protect.failure_returns_false_and_one_source_attempt",
      protect_failure_returns_false && protect_failure_is_one_source_attempt);
  U("m2.vm.reserved.protect.retry.one_additional_source_attempt",
      protect_retry_is_one_additional_source_attempt);
  U("m2.vm.reserved.protect_success", 1);
  U("m2.vm.reserved.unprotect.failure_returns_false_and_one_source_attempt",
      unprotect_failure_returns_false && unprotect_failure_is_one_source_attempt);
  U("m2.vm.reserved.unprotect.retry.one_additional_source_attempt",
      unprotect_retry_is_one_additional_source_attempt);
  U("m2.vm.reserved.unprotect_success", 1);
  U("m2.vm.reserved.release_success", 1);
  U("m2.vm.normal.client_is_base", normal_id.mem.os.base == normal);
  U("m2.vm.normal.good_size", normal_size);
  U("m2.vm.normal.memid_base_and_size", normal_id.mem.os.size == normal_size);
  U("m2.vm.normal.initially_committed", normal_id.initially_committed);
  U("m2.vm.normal.initially_zero", normal_id.initially_zero);
  U("m2.vm.normal.release_success", 1);
  U("m2.vm.aligned.alignment", alignment);
  U("m2.vm.aligned.client_is_aligned", ((uintptr_t)aligned % alignment) == 0);
  U("m2.vm.aligned.good_size", aligned_size);
  U("m2.vm.aligned.memid_base_and_size", aligned_id.mem.os.size == aligned_size);
  U("m2.vm.aligned.release_success", 1);
  U("m2.vm.offset.client_offset_nonzero", offset_client != offset_id.mem.os.base);
  U("m2.vm.offset.client_plus_offset_is_aligned", ((uintptr_t)offset_client + offset) % alignment == 0);
  U("m2.vm.offset.good_size", offset_size);
  U("m2.vm.offset.memid_base_and_size", offset_id.mem.os.size == offset_size);
  U("m2.vm.offset.release_full_mapping_success", 1);
  U("m2.vm.offset.prefix_decommit.success_attempt_and_full_owner",
      offset_prefix_decommit_success_attempt_and_full_owner);
  U("m2.vm.offset.prefix_decommit.failure_attempt_consumed_and_full_owner",
      offset_prefix_decommit_failure_attempt_consumed_and_full_owner);
  U("m2.vm.release.offset_owner_interior", failed_release_id.mem.os.base != failed_release_client);
  U("m2.vm.release.failure.one_primitive_attempt", munmap_after_failure == munmap_before_failure + 1);
  U("m2.vm.release.failure.full_memid_base_and_size",
      captured_release_munmap_addresses[0] == failed_release_id.mem.os.base
      && captured_release_munmap_lengths[0] == failed_release_id.mem.os.size);
  U("m2.vm.release.failure.mapping_live", 1);
  U("m2.vm.release.failure.source_counters_apply", reserved_after_failure == reserved_before_failure - (int64_t)failed_release_id.mem.os.size
      && committed_after_failure == committed_before_failure - (int64_t)failed_release_commit_size);
  U("m2.vm.release.retry.one_additional_primitive_attempt", munmap_after_retry == munmap_after_failure + 1);
  U("m2.vm.release.retry.full_memid_base_and_size",
      captured_release_munmap_addresses[1] == failed_release_id.mem.os.base
      && captured_release_munmap_lengths[1] == failed_release_id.mem.os.size);
  U("m2.vm.release.retry.source_counters_reapply", reserved_after_retry == reserved_after_failure - (int64_t)failed_release_id.mem.os.size
      && committed_after_retry == committed_after_failure - (int64_t)failed_release_commit_size);
  U("m2.vm.release.retry.real_munmap_success", last_real_munmap_result == 0);
  U("m2.vm.external.callback.managed_typed_owner", external_callback.managed_external_owner);
  U("m2.vm.external.callback.commit_zero_propagated", external_callback.commit_zero_propagated);
  U("m2.vm.external.callback.purge_raw_span_null_zero_and_statistics",
      external_callback.purge_raw_span_null_zero_and_statistics);
  U("m2.vm.external.callback.purge_true_clears_commit", external_callback.purge_true_clears_commit);
  U("m2.vm.external.callback.recommit_reinvokes_callback",
      external_callback.recommit_reinvokes_callback);
  U("m2.vm.external.callback.purge_false_preserves_commit",
      external_callback.purge_false_preserves_commit);
  U("m2.vm.external.callback.purge_mixed_clears_commit",
      external_callback.purge_mixed_clears_commit);
  U("m2.vm.external.callback.negative_delay_skips_callback_and_statistics",
      external_callback.negative_delay_skips_callback_and_statistics);
  U("m2.vm.external.callback.no_normal_advice", external_callback.no_normal_advice);
  U("m2.vm.external.callback.one_published_owner_per_registry",
      external_callback.one_published_owner_per_registry);
  U("m2.vm.external.page_extension.direct_commit_fault_bypasses_callback",
      external_callback.page_extension_direct_commit_fault_bypasses_callback);
  U("m2.vm.external.page_extension.failure_preserves_unpublished_state",
      external_callback.page_extension_failure_preserves_unpublished_state);
  U("m2.vm.external.page_extension.retry_commits_without_callback",
      external_callback.page_extension_retry_commits_without_callback);
  U("m2.vm.numa.count_at_least_one", numa_count >= 1);
  U("m2.vm.numa.current_lt_count", numa_current < numa_count);
  U("m2.vm.aligned_hint.cold_missing_default_advances_cursor",
      aligned_hint_cold_missing_default_advances);
  U("m2.vm.aligned_hint.eligibility_and_geometry",
      aligned_hint_eligibility_geometry);
  U("m2.vm.aligned_hint.initialized_first_randomized_start",
      aligned_hint_initialized_first_start);
  U("m2.vm.aligned_hint.strict_max_then_wrap_one_draw",
      aligned_hint_strict_threshold_and_one_draw);
  U("m2.vm.aligned_hint.ignored_cas_failure_second_fetch",
      aligned_hint_ignored_cas_failure);
  U("m2.vm.policy.source_options_applied", policy_record.source_options_applied);
  U("m2.vm.policy.first_arena_size", policy_record.first_arena_size);
  U("m2.vm.policy.first_arena_initially_committed",
      policy_record.first_arena_initially_committed);
  U("m2.vm.policy.large_high_hint_failed", policy_record.large_high_hint_failed);
  U("m2.vm.policy.large_null_hint_retry_failed",
      policy_record.large_null_hint_retry_failed);
  U("m2.vm.policy.regular_hinted_map_after_large_fallback",
      policy_record.regular_hinted_map_after_large_fallback);
  U("m2.vm.policy.thp_advice_failure_ignored", policy_record.thp_advice_failure_ignored);
  puts("CRABC_MI_M2_VM_TRACE_END");
  puts("CRABC_MI_M2_ALIGNED_OVERMAP_TRACE_BEGIN");
  U("m2.vm.aligned_overmap.c.normal_direct_aligned_source_owner_and_stats",
      aligned_overmap_record.normal_direct_aligned);
  U("m2.vm.aligned_overmap.c.direct_map_failure_fallback_source_owner_and_stats",
      aligned_overmap_record.direct_map_failure_fallback);
  U("m2.vm.aligned_overmap.c.prefix_zero_suffix_only_source_geometry_and_stats",
      aligned_overmap_record.prefix_zero_suffix_only);
  U("m2.vm.aligned_overmap.c.complete_direct_prefix_suffix_cleanup_source_owner_and_stats",
      aligned_overmap_record.complete_direct_prefix_suffix_cleanup);
  U("m2.vm.aligned_overmap.c.direct_cleanup_failure_reserved_source_continues_escaped_live_stats",
      aligned_overmap_record.direct_cleanup_failure_reserved_source_continues_escaped_live_stats);
  U("m2.vm.aligned_overmap.c.direct_cleanup_failure_committed_source_continues_escaped_live_stats",
      aligned_overmap_record.direct_cleanup_failure_committed_source_continues_escaped_live_stats);
  U("m2.vm.aligned_overmap.c.prefix_cleanup_failure_reserved_source_continues_escaped_live_stats",
      aligned_overmap_record.prefix_cleanup_failure_reserved_source_continues_escaped_live_stats);
  U("m2.vm.aligned_overmap.c.prefix_cleanup_failure_committed_source_continues_escaped_live_stats",
      aligned_overmap_record.prefix_cleanup_failure_committed_source_continues_escaped_live_stats);
  U("m2.vm.aligned_overmap.c.suffix_cleanup_failure_reserved_source_continues_escaped_live_stats",
      aligned_overmap_record.suffix_cleanup_failure_reserved_source_continues_escaped_live_stats);
  U("m2.vm.aligned_overmap.c.suffix_cleanup_failure_committed_source_continues_escaped_live_stats",
      aligned_overmap_record.suffix_cleanup_failure_committed_source_continues_escaped_live_stats);
  puts("CRABC_MI_M2_ALIGNED_OVERMAP_TRACE_END");
  return 0;
}
#endif  /* CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE */

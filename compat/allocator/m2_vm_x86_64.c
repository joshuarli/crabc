/* Native x86-64 M2 VM-primitives oracle.
 *
 * This intentionally includes the fixed v3.5.0 `src/os.c`, `src/arena.c`,
 * `src/init.c`, `src/page.c`, and `src/prim/prim.c` into the probe so their
 * private configuration, OS-allocation, first arena-reserve, preloading-state,
 * direct page-extension, and Unix primitive-dispatch bodies are observed
 * directly. The Python producer omits those five ordinary source objects from
 * the link
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
#include <string.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pthread.h>
#include <time.h>
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
 * singular by omitting `src/os.c`, `src/arena.c`, `src/init.c`, `src/page.c`,
 * and `src/prim/prim.c` from the ordinary C source list. */

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

/* src/prim/unix/prim.c:401-410 has one selected retry-suppression strong
 * CAS. Include the ordinary prim.c dispatcher here as well, and omit its
 * standalone object from this fixture's source list, so this wrapper sees the
 * literal pinned source operation. It delegates every call to the same C11
 * AcqRel/Acquire CAS; only the child-selected first operation waits for one
 * real competing decrement. */
typedef struct large_page_retry_atomic_record_s {
  bool active;
  bool counter_consistent;
  _Atomic(size_t)* counter;
  size_t cas_count;
  size_t cas_expected_before;
  size_t cas_expected_after;
  size_t cas_desired;
  bool cas_succeeded;
} large_page_retry_atomic_record_t;

static large_page_retry_atomic_record_t large_page_retry_atomic_record = {
    .counter_consistent = true,
};
static pthread_mutex_t large_page_retry_competitor_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t large_page_retry_competitor_ready = PTHREAD_COND_INITIALIZER;
static pthread_cond_t large_page_retry_competitor_done = PTHREAD_COND_INITIALIZER;
static bool large_page_retry_competitor_enabled = false;
static bool large_page_retry_competitor_waiting = false;
static bool large_page_retry_competitor_finished = false;
static _Atomic(size_t)* large_page_retry_competitor_counter = NULL;
static size_t large_page_retry_competitor_expected = 0;
static size_t large_page_retry_competitor_desired = 0;
static bool large_page_retry_competitor_succeeded = false;

/* These waits belong only to this forked C witness. A deadline makes a broken
 * source/CAS schedule fail its child rather than leave the outer evidence
 * process waiting indefinitely; the child is still reaped by its exact parent.
 */
#define LARGE_PAGE_RETRY_WAIT_SECONDS 5
static bool large_page_retry_wait_for_locked(
    pthread_cond_t* condition, bool* complete) {
  struct timespec deadline;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) return false;
  deadline.tv_sec += LARGE_PAGE_RETRY_WAIT_SECONDS;
  while (!*complete) {
    const int result = pthread_cond_timedwait(
        condition, &large_page_retry_competitor_lock, &deadline);
    if (result == EINTR) continue;
    if (result != 0) return false;
  }
  return true;
}

static bool m2_large_page_retry_compare_exchange(
    _Atomic(size_t)* counter, size_t* expected, size_t desired);

#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)
/* The generated direct-include profile keeps every upstream raw syscall
 * intact except the one typed `mi_prim_mbind` body. It calls this exact
 * six-argument stub, so source initialization never enters a generic syscall
 * shim while the selected placement branch remains observable. */
#ifndef CRABC_M2_FAULT_SEAM_PRIM_PROFILE
#error "fault seam profile requires its fixed mi_prim_mbind direct-include overlay"
#endif
static long m2_fault_inventory_mbind_syscall(
    void* start, unsigned long length, unsigned long mode,
    const unsigned long* mask, unsigned long maxnode, unsigned flags);
#endif
#undef mi_atomic_cas_strong_acq_rel
#define mi_atomic_cas_strong_acq_rel(p, expected, desired) \
  m2_large_page_retry_compare_exchange((p), (expected), (desired))
#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)
#include CRABC_M2_FAULT_SEAM_PRIM_PROFILE
#else
#include "prim/prim.c"
#endif
#undef mi_atomic_cas_strong_acq_rel
#define mi_atomic_cas_strong_acq_rel(p, exp, des) \
  mi_atomic_cas_strong((p), (exp), (des), mi_memory_order(acq_rel), mi_memory_order(acquire))

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

static bool m2_large_page_retry_compare_exchange(
    _Atomic(size_t)* counter, size_t* expected, size_t desired) {
  const size_t expected_before = *expected;
  if (large_page_retry_atomic_record.active) {
    if (large_page_retry_atomic_record.counter == NULL) {
      large_page_retry_atomic_record.counter = counter;
    } else if (large_page_retry_atomic_record.counter != counter) {
      large_page_retry_atomic_record.counter_consistent = false;
    }
    if (large_page_retry_competitor_enabled
        && large_page_retry_atomic_record.cas_count == 0) {
      pthread_mutex_lock(&large_page_retry_competitor_lock);
      large_page_retry_competitor_counter = counter;
      large_page_retry_competitor_expected = expected_before;
      large_page_retry_competitor_desired = desired;
      large_page_retry_competitor_waiting = true;
      pthread_cond_signal(&large_page_retry_competitor_ready);
      if (!large_page_retry_wait_for_locked(
              &large_page_retry_competitor_done,
              &large_page_retry_competitor_finished)) {
        large_page_retry_atomic_record.counter_consistent = false;
      }
      pthread_mutex_unlock(&large_page_retry_competitor_lock);
    }
  }

  const bool swapped = atomic_compare_exchange_strong_explicit(
      counter, expected, desired, memory_order_acq_rel, memory_order_acquire);
  if (large_page_retry_atomic_record.active) {
    large_page_retry_atomic_record.cas_expected_before = expected_before;
    large_page_retry_atomic_record.cas_expected_after = *expected;
    large_page_retry_atomic_record.cas_desired = desired;
    large_page_retry_atomic_record.cas_succeeded = swapped;
    large_page_retry_atomic_record.cas_count++;
  }
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
/* The reset oracle needs distinct imported-error edges rather than a generic
 * one-shot fault: the unchanged source must retry EAGAIN using its snapshot,
 * switch its global advice only after FREE/EINVAL, and make exactly one
 * DONTNEED fallback attempt. This script only controls the wrapped import;
 * `_mi_prim_reset`, `_mi_os_reset`, and `_mi_os_purge` remain pinned bodies. */
#define RESET_MADVISE_SCRIPT_CAPACITY 3
typedef struct reset_madvise_step_s {
  int advice;
  int error;
} reset_madvise_step_t;

typedef struct reset_madvise_script_s {
  bool active;
  bool valid;
  size_t count;
  size_t next;
  reset_madvise_step_t steps[RESET_MADVISE_SCRIPT_CAPACITY];
} reset_madvise_script_t;

static reset_madvise_script_t reset_madvise_script = {0};

static bool reset_madvise_script_begin(
    const reset_madvise_step_t* steps, size_t count) {
  if (steps == NULL || count == 0 || count > RESET_MADVISE_SCRIPT_CAPACITY) {
    return false;
  }
  reset_madvise_script.active = false;
  reset_madvise_script.valid = true;
  reset_madvise_script.count = count;
  reset_madvise_script.next = 0;
  for (size_t index = 0; index < count; index++) {
    reset_madvise_script.steps[index] = steps[index];
  }
  reset_madvise_script.active = true;
  return true;
}

static bool reset_madvise_script_finish(void) {
  const bool complete = reset_madvise_script.active
      && reset_madvise_script.valid
      && reset_madvise_script.next == reset_madvise_script.count;
  reset_madvise_script.active = false;
  return complete;
}

/* Every scripted reset edge operates on the same source-owned full page.
 * Check the captured import arguments as one bounded witness so advice-only
 * assertions cannot accept a wrongly normalized range from the C oracle. */
static bool captured_transition_madvise_exact_range(
    void* address, size_t length, size_t count) {
  if (count > sizeof(captured_transition_madvise_addresses)
          / sizeof(captured_transition_madvise_addresses[0])
      || captured_transition_madvise_calls != count) {
    return false;
  }
  for (size_t index = 0; index < count; index++) {
    if (captured_transition_madvise_addresses[index] != address
        || captured_transition_madvise_lengths[index] != length) {
      return false;
    }
  }
  return true;
}
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

/* This is a separate direct source-primitive witness for the normal-release
 * large-page retry state. The pinned unix_mmap body owns the retry counter and
 * chooses every raw map; this fixture only forces its MAP_HUGETLB imports to
 * fail, records the returned regular map, and checks the exact later
 * _mi_prim_free range. No large-page success is requested or represented. */
#define LARGE_PAGE_RETRY_SUPPRESSION_COUNT 8
typedef struct large_page_retry_probe_s {
  bool active;
  bool range_consistent;
  size_t expected_length;
  size_t huge_calls;
  size_t regular_calls;
  size_t call_huge_calls;
  void* call_huge_hints[2];
  void* last_regular_address;
  size_t last_regular_length;
  void* expected_release_address;
  size_t expected_release_length;
  size_t release_calls;
  void* last_release_address;
  size_t last_release_length;
  bool release_exact;
  int last_release_result;
} large_page_retry_probe_t;

static large_page_retry_probe_t large_page_retry_probe = {
    .range_consistent = true,
    .release_exact = true,
    .last_release_result = -1,
};

/* This distinct child-owned probe faults only the three raw mmap imports of
 * two `_mi_os_alloc_huge_os_pages` calls. It records the literal source
 * arguments, leaving the fixed upstream large-only/one-GiB state machine and
 * upper failure ownership in the directly included C bodies. */
typedef struct large_only_failure_probe_s {
  bool active;
  size_t mmap_calls;
  void* hints[3];
  size_t lengths[3];
  int protections[3];
  int flags[3];
  int errors[3];
  size_t madvise_calls;
} large_only_failure_probe_t;

static large_only_failure_probe_t large_only_failure_probe;

/* This is a separate, fixed source-branch profile for `src/os.c:771-841`.
 * It replaces only a selected raw MAP_HUGETLB result with an anonymous normal
 * mapping at the source's exact claimed address.  That lets the included C
 * body observe its partial-prefix, timeout, noncontiguous-adjustment, and
 * per-page-free branches without claiming that this host provisioned huge
 * pages.  The profile has five literal cases; it is not a programmable map
 * script and remains inactive for the ordinary VM receipt. */
typedef enum huge_branch_probe_case_e {
  HUGE_BRANCH_PROBE_OFF = 0,
  HUGE_BRANCH_PROBE_PARTIAL_PRIMITIVE_FAILURE,
  HUGE_BRANCH_PROBE_TIMEOUT_AFTER_PROGRESS,
  HUGE_BRANCH_PROBE_NONCONTIGUOUS_ADJUSTMENT,
  HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
  HUGE_BRANCH_PROBE_FREE_CONTINUES_AFTER_FAILURE,
} huge_branch_probe_case_t;

typedef struct huge_branch_probe_s {
  bool active;
  bool valid;
  huge_branch_probe_case_t selected;
  size_t mmap_calls;
  void* hints[3];
  size_t lengths[3];
  int protections[3];
  int flags[3];
  void* fallback_addresses[3];
  int fallback_flags[3];
  size_t munmap_calls;
  void* munmap_addresses[3];
  size_t munmap_lengths[3];
  size_t fail_munmap_ordinal;
  size_t clock_calls;
  size_t syscall_calls;
  size_t diagnostic_calls;
  size_t diagnostic_first_length;
  size_t diagnostic_second_length;
  bool diagnostic_prefix_first;
  bool diagnostic_body_second;
  char diagnostic_first[96];
  char diagnostic_second[192];
  void* mbind_start;
  unsigned long mbind_length;
  unsigned long mbind_mode;
  bool mbind_mask_nonnull;
  unsigned long mbind_mask_value;
  unsigned long mbind_maxnode;
  unsigned mbind_flags;
  long mbind_result;
  int mbind_errno;
} huge_branch_probe_t;

static huge_branch_probe_t huge_branch_probe;
static huge_branch_probe_case_t huge_branch_child_case;

#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)
static size_t huge_branch_registration_callback_calls;
static size_t huge_branch_registration_fragment_length;
static char huge_branch_registration_fragment[192];

static bool m2_fault_inventory_warning_prefix(const char* message) {
  char expected[96];
  _mi_snprintf(expected, sizeof(expected), "mimalloc: warning: thread 0x%tx: ",
               (uintptr_t)_mi_thread_id());
  return message != NULL && strcmp(message, expected) == 0;
}

static size_t m2_fault_inventory_copy_fragment(char* destination, size_t capacity,
                                               const char* message) {
  if (capacity == 0) return 0;
  if (message == NULL) {
    destination[0] = '\0';
    return 0;
  }
  const size_t length = strnlen(message, capacity - 1);
  memcpy(destination, message, length);
  destination[length] = '\0';
  return length;
}

static bool m2_fault_inventory_default_continuation(const char* message) {
  char expected[192];
  _mi_snprintf(expected, sizeof(expected),
      "mimalloc: warning: thread 0x%tx: "
      "failed to bind huge (1GiB) pages to numa node 62 (error: 1 (0x01))\n\n",
      (uintptr_t)_mi_thread_id());
  return message != NULL && strcmp(message, expected) == 0;
}

static void m2_fault_inventory_output(const char* message, void* argument) {
  (void)argument;
  if (!huge_branch_probe.active) {
    huge_branch_registration_callback_calls++;
    huge_branch_registration_fragment_length = m2_fault_inventory_copy_fragment(
        huge_branch_registration_fragment, sizeof(huge_branch_registration_fragment), message);
    return;
  }
  const size_t index = huge_branch_probe.diagnostic_calls++;
  if (index == 0) {
    huge_branch_probe.diagnostic_first_length = m2_fault_inventory_copy_fragment(
        huge_branch_probe.diagnostic_first, sizeof(huge_branch_probe.diagnostic_first), message);
    huge_branch_probe.diagnostic_prefix_first = m2_fault_inventory_warning_prefix(message);
  }
  else if (index == 1) {
    huge_branch_probe.diagnostic_second_length = m2_fault_inventory_copy_fragment(
        huge_branch_probe.diagnostic_second, sizeof(huge_branch_probe.diagnostic_second), message);
    huge_branch_probe.diagnostic_body_second = message != NULL && strcmp(message,
        "failed to bind huge (1GiB) pages to numa node 62 (error: 1 (0x01))\n") == 0;
  }
}

static long m2_fault_inventory_mbind_syscall(
    void* start, unsigned long length, unsigned long mode,
    const unsigned long* mask, unsigned long maxnode, unsigned flags) {
  if (!huge_branch_probe.active
      || huge_branch_probe.selected != HUGE_BRANCH_PROBE_PLACEMENT_FAILURE) {
    huge_branch_probe.valid = false;
    errno = EINVAL;
    return -1;
  }
  huge_branch_probe.syscall_calls++;
  huge_branch_probe.mbind_start = start;
  huge_branch_probe.mbind_length = length;
  huge_branch_probe.mbind_mode = mode;
  huge_branch_probe.mbind_mask_nonnull = mask != NULL;
  huge_branch_probe.mbind_mask_value = mask == NULL ? 0 : *mask;
  huge_branch_probe.mbind_maxnode = maxnode;
  huge_branch_probe.mbind_flags = flags;
  huge_branch_probe.mbind_result = -1;
  huge_branch_probe.mbind_errno = EPERM;
  errno = EPERM;
  return -1;
}
#endif

/* This COW-child-only finite matrix receives only the two scalar forms used
 * by `_mi_prim_mem_init`: GET(0,0,0,0) and SET(1,0,0,0). It is deliberately
 * not a generic variadic forwarder or programmable script. The pinned source
 * also names one VMA annotation form, so the inactive wrapper forwards that
 * separately with its concrete int/pointer/size_t/pointer tuple; every other
 * prctl operation is rejected rather than being read through an unchecked
 * va_list shape. */
#define THP_DIRECT_POLICY_CAPTURE_CAPACITY 2

typedef enum thp_direct_policy_case_e {
  THP_DIRECT_POLICY_CASE_OFF = 0,
  THP_DIRECT_POLICY_CASE_ALLOW_ENABLED,
  THP_DIRECT_POLICY_CASE_QUERY_PERM,
  THP_DIRECT_POLICY_CASE_QUERY_INVAL,
  THP_DIRECT_POLICY_CASE_QUERY_NONZERO_ONE,
  THP_DIRECT_POLICY_CASE_QUERY_NONZERO_THREE,
  THP_DIRECT_POLICY_CASE_SET_SUCCESS,
  THP_DIRECT_POLICY_CASE_SET_PERM,
  THP_DIRECT_POLICY_CASE_SET_INVAL,
} thp_direct_policy_case_t;

typedef struct thp_direct_policy_probe_s {
  bool active;
  bool valid;
  thp_direct_policy_case_t selected_case;
  size_t calls;
  int options[THP_DIRECT_POLICY_CAPTURE_CAPACITY];
  int arguments[THP_DIRECT_POLICY_CAPTURE_CAPACITY][4];
} thp_direct_policy_probe_t;

static thp_direct_policy_probe_t thp_direct_policy_probe;

static size_t thp_direct_policy_expected_calls(thp_direct_policy_case_t selected_case) {
  switch (selected_case) {
    case THP_DIRECT_POLICY_CASE_ALLOW_ENABLED:
      return 0;
    case THP_DIRECT_POLICY_CASE_QUERY_PERM:
    case THP_DIRECT_POLICY_CASE_QUERY_INVAL:
    case THP_DIRECT_POLICY_CASE_QUERY_NONZERO_ONE:
    case THP_DIRECT_POLICY_CASE_QUERY_NONZERO_THREE:
      return 1;
    case THP_DIRECT_POLICY_CASE_SET_SUCCESS:
    case THP_DIRECT_POLICY_CASE_SET_PERM:
    case THP_DIRECT_POLICY_CASE_SET_INVAL:
      return 2;
    case THP_DIRECT_POLICY_CASE_OFF:
      return SIZE_MAX;
  }
  return SIZE_MAX;
}

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
int __real_prctl(int option, ...);
#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)
int __real_clock_gettime(clockid_t clock_id, struct timespec* time);
#endif

static int thp_direct_policy_error(int error) {
  errno = error;
  return -1;
}

int __wrap_prctl(int option, ...) {
  va_list arguments;
  va_start(arguments, option);

  if (option == PR_GET_THP_DISABLE || option == PR_SET_THP_DISABLE) {
    /* Both selected source calls pass literal `int` arguments. */
    const int argument0 = va_arg(arguments, int);
    const int argument1 = va_arg(arguments, int);
    const int argument2 = va_arg(arguments, int);
    const int argument3 = va_arg(arguments, int);
    va_end(arguments);

    if (!thp_direct_policy_probe.active) {
      return __real_prctl(option, argument0, argument1, argument2, argument3);
    }

    const size_t index = thp_direct_policy_probe.calls++;
    if (index < THP_DIRECT_POLICY_CAPTURE_CAPACITY) {
      thp_direct_policy_probe.options[index] = option;
      thp_direct_policy_probe.arguments[index][0] = argument0;
      thp_direct_policy_probe.arguments[index][1] = argument1;
      thp_direct_policy_probe.arguments[index][2] = argument2;
      thp_direct_policy_probe.arguments[index][3] = argument3;
    }

    const bool get_tuple = option == PR_GET_THP_DISABLE && argument0 == 0
        && argument1 == 0 && argument2 == 0 && argument3 == 0;
    const bool set_tuple = option == PR_SET_THP_DISABLE && argument0 == 1
        && argument1 == 0 && argument2 == 0 && argument3 == 0;
    if (index == 0 && get_tuple) {
      switch (thp_direct_policy_probe.selected_case) {
        case THP_DIRECT_POLICY_CASE_QUERY_PERM:
          return thp_direct_policy_error(EPERM);
        case THP_DIRECT_POLICY_CASE_QUERY_INVAL:
          return thp_direct_policy_error(EINVAL);
        case THP_DIRECT_POLICY_CASE_QUERY_NONZERO_ONE:
          return 1;
        case THP_DIRECT_POLICY_CASE_QUERY_NONZERO_THREE:
          return 3;
        case THP_DIRECT_POLICY_CASE_SET_SUCCESS:
        case THP_DIRECT_POLICY_CASE_SET_PERM:
        case THP_DIRECT_POLICY_CASE_SET_INVAL:
          return 0;
        case THP_DIRECT_POLICY_CASE_OFF:
        case THP_DIRECT_POLICY_CASE_ALLOW_ENABLED:
          break;
      }
    }
    if (index == 1 && set_tuple) {
      switch (thp_direct_policy_probe.selected_case) {
        case THP_DIRECT_POLICY_CASE_SET_SUCCESS:
          return 0;
        case THP_DIRECT_POLICY_CASE_SET_PERM:
          return thp_direct_policy_error(EPERM);
        case THP_DIRECT_POLICY_CASE_SET_INVAL:
          return thp_direct_policy_error(EINVAL);
        case THP_DIRECT_POLICY_CASE_OFF:
        case THP_DIRECT_POLICY_CASE_ALLOW_ENABLED:
        case THP_DIRECT_POLICY_CASE_QUERY_PERM:
        case THP_DIRECT_POLICY_CASE_QUERY_INVAL:
        case THP_DIRECT_POLICY_CASE_QUERY_NONZERO_ONE:
        case THP_DIRECT_POLICY_CASE_QUERY_NONZERO_THREE:
          break;
      }
    }
    thp_direct_policy_probe.valid = false;
    return thp_direct_policy_error(EINVAL);
  }

#if defined(PR_SET_VMA)
  if (option == PR_SET_VMA) {
    /* `unix_mmap` passes this exact source tuple when VMA naming is enabled. */
    const int suboption = va_arg(arguments, int);
    void* const address = va_arg(arguments, void*);
    const size_t length = va_arg(arguments, size_t);
    char* const name = va_arg(arguments, char*);
    va_end(arguments);
    if (thp_direct_policy_probe.active) {
      thp_direct_policy_probe.valid = false;
      return thp_direct_policy_error(EINVAL);
    }
    return __real_prctl(option, suboption, address, length, name);
  }
#endif

  va_end(arguments);
  if (thp_direct_policy_probe.active) {
    thp_direct_policy_probe.valid = false;
  }
  return thp_direct_policy_error(EINVAL);
}

/* The OS publication profile selects only unchanged mmap/mprotect/munmap
 * imports. The full pinned arena/page-map bodies still decide publication,
 * rollback, and void free. Captured failed ranges are fixture cleanup facts,
 * never a substitute C allocator owner. */
#if defined(CRABC_M2_OS_PUBLICATION_PROFILE)
static struct {
  unsigned selected;
  size_t commits;
  size_t map_faults;
  size_t releases;
  void* base;
  size_t length;
  bool active;
  bool retained;
} os_publication_probe;
#endif

int __wrap_munmap(void* address, size_t length) {
#if defined(CRABC_M2_OS_PUBLICATION_PROFILE)
  if (os_publication_probe.active && address == os_publication_probe.base) {
    os_publication_probe.releases++;
    os_publication_probe.length = length;
    if (os_publication_probe.selected >= 5) {
      os_publication_probe.retained = true;
      errno = ENOMEM;
      return -1;
    }
  }
#endif
  wrapped_munmap_calls++;
  if (huge_branch_probe.active) {
    const size_t index = huge_branch_probe.munmap_calls;
    if (index < sizeof(huge_branch_probe.munmap_addresses)
                    / sizeof(huge_branch_probe.munmap_addresses[0])) {
      huge_branch_probe.munmap_addresses[index] = address;
      huge_branch_probe.munmap_lengths[index] = length;
    }
    huge_branch_probe.munmap_calls++;
    if (huge_branch_probe.fail_munmap_ordinal != 0
        && huge_branch_probe.munmap_calls == huge_branch_probe.fail_munmap_ordinal) {
      errno = ENOMEM;
      return -1;
    }
    return __real_munmap(address, length);
  }
  if (large_page_retry_probe.active
      && large_page_retry_probe.expected_release_address != NULL) {
    large_page_retry_probe.release_calls++;
    large_page_retry_probe.last_release_address = address;
    large_page_retry_probe.last_release_length = length;
    if (address != large_page_retry_probe.expected_release_address
        || length != large_page_retry_probe.expected_release_length) {
      large_page_retry_probe.release_exact = false;
    }
    large_page_retry_probe.last_release_result = __real_munmap(address, length);
    return large_page_retry_probe.last_release_result;
  }
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
#if defined(CRABC_M2_OS_PUBLICATION_PROFILE)
  if (os_publication_probe.active && (os_publication_probe.selected == 1
      || ((os_publication_probe.selected == 4 || os_publication_probe.selected == 6)
          && os_publication_probe.commits >= 2 && protection == (PROT_READ | PROT_WRITE)))) {
    os_publication_probe.map_faults++;
    errno = ENOMEM;
    return MAP_FAILED;
  }
#endif
  if (large_only_failure_probe.active) {
    const size_t index = large_only_failure_probe.mmap_calls;
    if (index < sizeof(large_only_failure_probe.hints)
                    / sizeof(large_only_failure_probe.hints[0])) {
      large_only_failure_probe.hints[index] = address;
      large_only_failure_probe.lengths[index] = length;
      large_only_failure_probe.protections[index] = protection;
      large_only_failure_probe.flags[index] = flags;
      large_only_failure_probe.errors[index] = ENOMEM;
    }
    large_only_failure_probe.mmap_calls++;
    errno = ENOMEM;
    return MAP_FAILED;
  }
  if (huge_branch_probe.active) {
    const size_t index = huge_branch_probe.mmap_calls;
    if (index < sizeof(huge_branch_probe.hints) / sizeof(huge_branch_probe.hints[0])) {
      huge_branch_probe.hints[index] = address;
      huge_branch_probe.lengths[index] = length;
      huge_branch_probe.protections[index] = protection;
      huge_branch_probe.flags[index] = flags;
    }
    huge_branch_probe.mmap_calls++;
    if (length != MI_GiB || protection != (PROT_READ | PROT_WRITE)
        || (flags & MAP_HUGETLB) == 0 || address == NULL) {
      huge_branch_probe.valid = false;
      errno = EINVAL;
      return MAP_FAILED;
    }
    if (huge_branch_probe.selected == HUGE_BRANCH_PROBE_PARTIAL_PRIMITIVE_FAILURE
        && huge_branch_probe.mmap_calls >= 2) {
      errno = ENOMEM;
      return MAP_FAILED;
    }
    const int ordinary_flags = (flags & ~(MAP_HUGETLB
        | ((unsigned)MAP_HUGE_MASK << MAP_HUGE_SHIFT)))
        | MAP_FIXED_NOREPLACE;
    if (index < sizeof(huge_branch_probe.fallback_addresses)
                    / sizeof(huge_branch_probe.fallback_addresses[0])) {
      huge_branch_probe.fallback_addresses[index] = address;
      huge_branch_probe.fallback_flags[index] = ordinary_flags;
    }
    if (huge_branch_probe.selected == HUGE_BRANCH_PROBE_NONCONTIGUOUS_ADJUSTMENT) {
      if (index < sizeof(huge_branch_probe.fallback_addresses)
                      / sizeof(huge_branch_probe.fallback_addresses[0])) {
        huge_branch_probe.fallback_addresses[index] = NULL;
        huge_branch_probe.fallback_flags[index] = flags & ~(MAP_HUGETLB
            | ((unsigned)MAP_HUGE_MASK << MAP_HUGE_SHIFT));
      }
      return __real_mmap(
          NULL, length, protection, flags & ~(MAP_HUGETLB
              | ((unsigned)MAP_HUGE_MASK << MAP_HUGE_SHIFT)),
          descriptor, offset);
    }
    return __real_mmap(address, length, protection, ordinary_flags, descriptor, offset);
  }
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
  if (large_page_retry_probe.active) {
    if (length != large_page_retry_probe.expected_length) {
      large_page_retry_probe.range_consistent = false;
    }
    if ((flags & MAP_HUGETLB) != 0) {
      if (large_page_retry_probe.call_huge_calls
          < sizeof(large_page_retry_probe.call_huge_hints)
              / sizeof(large_page_retry_probe.call_huge_hints[0])) {
        large_page_retry_probe.call_huge_hints[
            large_page_retry_probe.call_huge_calls] = address;
      }
      large_page_retry_probe.call_huge_calls++;
      large_page_retry_probe.huge_calls++;
      errno = ENOMEM;
      return MAP_FAILED;
    }
    large_page_retry_probe.regular_calls++;
    void* const mapped = __real_mmap(
        address, length, protection, flags, descriptor, offset);
    if (mapped != MAP_FAILED) {
      large_page_retry_probe.last_regular_address = mapped;
      large_page_retry_probe.last_regular_length = length;
    }
    return mapped;
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
#if defined(CRABC_M2_OS_PUBLICATION_PROFILE)
  if (os_publication_probe.active) {
    os_publication_probe.commits++;
    if (os_publication_probe.commits == 1) os_publication_probe.base = address;
    const unsigned selected = os_publication_probe.selected;
    if (((selected == 2 || selected == 5) && os_publication_probe.commits == 1)
        || (selected == 3 && os_publication_probe.commits == 2)) {
      errno = ENOMEM;
      return -1;
    }
  }
#endif
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
  if (large_only_failure_probe.active) {
    large_only_failure_probe.madvise_calls++;
  }
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
  if (reset_madvise_script.active) {
    if (reset_madvise_script.next >= reset_madvise_script.count
        || reset_madvise_script.steps[reset_madvise_script.next].advice != advice) {
      reset_madvise_script.valid = false;
      errno = EINVAL;
      return -1;
    }
    const int error = reset_madvise_script.steps[reset_madvise_script.next].error;
    reset_madvise_script.next++;
    if (error != 0) {
      errno = error;
      return -1;
    }
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

#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)
/* `_mi_clock_start` first uses three `_mi_prim_clock_now` calls to calibrate
 * `mi_clock_diff` and select its start. Capture only the selected huge timeout
 * child and return that fixed 0,1,1,4 millisecond sequence; the fourth read
 * makes the source's first completed page exceed its one-millisecond limit.
 * Every other profile reaches the image's real clock_gettime unchanged. */
int __wrap_clock_gettime(clockid_t clock_id, struct timespec* time) {
  if (!huge_branch_probe.active) return __real_clock_gettime(clock_id, time);
  if (time == NULL) {
    errno = EINVAL;
    return -1;
  }
  const size_t call = huge_branch_probe.clock_calls++;
  time->tv_sec = 0;
  const mi_msecs_t milliseconds = (call == 0 ? 0 : (call == 1 || call == 2 ? 1 : 4));
  time->tv_nsec = (long)(milliseconds * 1000 * 1000);
  return 0;
}
#endif

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

/* `_mi_prim_reset` owns a function-static advice cache. Fork this one
 * fallback-error row before the parent accepts FREE/EINVAL, so the child
 * executes the actual pinned static state from FREE while the parent retains
 * FREE for its independent succeeding fallback row. No allocator function is
 * simulated: the child only scripts its imported `madvise` results. */
static bool capture_reset_fallback_eagain_child(
    mi_subproc_t* subproc, void* reserved, size_t page) {
  const pid_t child = fork();
  if (child < 0) {
    fprintf(stderr, "reset fallback EAGAIN child fork failed: errno=%d\n", errno);
    return false;
  }
  if (child == 0) {
    const reset_madvise_step_t steps[] = {
      { MADV_FREE, EAGAIN },
      { MADV_FREE, EINVAL },
      { MADV_DONTNEED, EAGAIN },
    };
    const int64_t reset_before = current_reset(subproc);
    const int64_t reset_calls_before = current_reset_calls(subproc);
    captured_transition_madvise_calls = 0;
    capture_transition_madvise = true;
    const bool began = reset_madvise_script_begin(steps, 3);
    const bool reset = began && _mi_os_reset(subproc, reserved, page);
    const bool script_complete = reset_madvise_script_finish();
    capture_transition_madvise = false;
    const bool expected = !reset
        && script_complete
        && captured_transition_madvise_calls == 3
        && captured_transition_madvise_exact_range(reserved, page, 3)
        && captured_transition_advices[0] == MADV_FREE
        && captured_transition_advices[1] == MADV_FREE
        && captured_transition_advices[2] == MADV_DONTNEED
        && current_reset_calls(subproc) == reset_calls_before + 1
        && current_reset(subproc) == reset_before + (int64_t)page
        && mprotect(reserved, page, PROT_READ | PROT_WRITE) == 0;
    _exit(expected ? 0 : 1);
  }
  return reap_exact_child("reset fallback EAGAIN child", child);
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

/* The process-wide THP setting is not touched by this fixture parent. Every
 * COW child calls the directly included void `_mi_prim_mem_init` with one
 * finite allow_thp case and a concrete PRCTL import result. C records only
 * exact count/tuple control flow, forced disabled configuration for allow=0,
 * and continuation after the void initializer. It does not manufacture a
 * typed error return or compare the allow-enabled ambient detection result. */
typedef struct thp_direct_policy_record_s {
  bool exact_tuple_count;
  bool disabled_configuration;
  bool void_continuation;
} thp_direct_policy_record_t;

static bool thp_direct_policy_case_requires_disabled_configuration(
    thp_direct_policy_case_t selected_case) {
  return selected_case != THP_DIRECT_POLICY_CASE_ALLOW_ENABLED;
}

static bool thp_direct_policy_record_passes(
    thp_direct_policy_case_t selected_case,
    const thp_direct_policy_record_t* record) {
  return record->exact_tuple_count && record->void_continuation
      && (!thp_direct_policy_case_requires_disabled_configuration(selected_case)
          || record->disabled_configuration);
}

static int run_thp_direct_policy_child(
    thp_direct_policy_case_t selected_case, int record_descriptor) {
  thp_direct_policy_record_t record = {0};
  mi_os_mem_config_t config = {0};
  _mi_options_init();
  mi_option_set(
      mi_option_allow_thp,
      selected_case == THP_DIRECT_POLICY_CASE_ALLOW_ENABLED ? 1 : 0);
  thp_direct_policy_probe = (thp_direct_policy_probe_t){
      .active = true,
      .valid = true,
      .selected_case = selected_case,
  };
  _mi_prim_mem_init(&config);
  thp_direct_policy_probe.active = false;

  record.exact_tuple_count = thp_direct_policy_probe.valid
      && thp_direct_policy_probe.calls
          == thp_direct_policy_expected_calls(selected_case);
  record.disabled_configuration = !config.has_transparent_huge_pages;
  record.void_continuation = true;
  if (!write_all(record_descriptor, &record, sizeof(record))) return 1;
  return thp_direct_policy_record_passes(selected_case, &record) ? 0 : 2;
}

static bool capture_thp_direct_policy_child(
    thp_direct_policy_case_t selected_case, thp_direct_policy_record_t* record) {
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
    const int result = run_thp_direct_policy_child(selected_case, descriptors[1]);
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
            "THP direct policy child failed: case=%d bytes=%zu expected=%zu "
            "waited=%ld expected_pid=%ld errno=%d exited=%d status=%d "
            "tuple_count=%d config_disabled=%d void_continuation=%d\\n",
            selected_case, record_bytes, sizeof(*record), (long)waited,
            (long)child, waited < 0 ? errno : 0,
            waited == child && WIFEXITED(status),
            waited == child && WIFEXITED(status) ? WEXITSTATUS(status) : -1,
            record->exact_tuple_count, record->disabled_configuration,
            record->void_continuation);
  }
  return captured;
}

/* The direct retry rows stay below the first-arena child in source ownership,
 * but execute first in `main` as separate COW children. `unix_mmap` owns a
 * function-static retry counter, so each child starts before any selected
 * large map and cannot inherit the first-arena fixture's state. The direct
 * receiver is `_mi_prim_alloc`, not a default-Theap or runtime caller. */
typedef struct large_page_retry_normal_record_s {
  bool source_options_applied;
  bool initial_failed_large_regular_owner;
  bool caller_disables_large_preserves_counter;
  bool ineligible_geometry_preserves_counter;
  bool option_disabled_preserves_counter;
  bool eight_suppressed_regular_owners;
  bool ninth_reopens_large_regular_owner;
} large_page_retry_normal_record_t;

typedef struct large_page_retry_cas_record_s {
  bool source_options_applied;
  bool competing_cas_failure_regular_owner;
  bool competing_cas_seven_then_reopens;
} large_page_retry_cas_record_t;

static bool large_page_retry_prepare_source(
    size_t* length, size_t* alignment) {
  if (length == NULL || alignment == NULL
      || setenv("mimalloc_allow_large_os_pages", "1", 1) != 0
      || setenv("mimalloc_allow_thp", "0", 1) != 0) {
    return false;
  }
  /* This direct primitive receiver needs only the source option/configuration
   * setup. Avoiding `mi_process_init` proves the retry state without creating
   * an unrelated Theap/arena caller before the selected unix_mmap invocation.
   */
  _mi_options_init();
  _mi_os_init();
  const size_t page = _mi_os_page_size();
  const size_t large = _mi_os_large_page_size();
  if (page == 0 || large < page || large % page != 0
      || !_mi_os_canuse_large_page(large, large)
      || !mi_option_is_enabled(mi_option_allow_large_os_pages)
      || mi_option_is_enabled(mi_option_allow_thp)) {
    return false;
  }
  *length = large;
  *alignment = large;
  return true;
}

static void large_page_retry_probe_begin(size_t length) {
  large_page_retry_probe = (large_page_retry_probe_t){
      .active = true,
      .range_consistent = true,
      .expected_length = length,
      .release_exact = true,
      .last_release_result = -1,
  };
}

static void large_page_retry_probe_end(void) {
  large_page_retry_probe.active = false;
  large_page_retry_probe.expected_release_address = NULL;
}

/* Exercise one selected direct source allocation. The regular fallback stays
 * mapped through the explicit liveness check, then `_mi_prim_free` must pass
 * its exact returned address and original length to the real munmap import. */
static bool large_page_retry_regular_owner(
    size_t length, size_t alignment, bool allow_large,
    size_t expected_huge_calls) {
  large_page_retry_probe.call_huge_calls = 0;
  large_page_retry_probe.call_huge_hints[0] = NULL;
  large_page_retry_probe.call_huge_hints[1] = NULL;
  const size_t regular_before = large_page_retry_probe.regular_calls;
  const size_t release_before = large_page_retry_probe.release_calls;
  bool is_large = true;
  bool is_zero = false;
  void* address = (void*)1;
  const int error = _mi_prim_alloc(
      NULL, length, alignment, true, allow_large, &is_large, &is_zero, &address);
  /* With no initialized source Theap, the first direct source call advances
   * the aligned cursor then returns a null hint; its failed huge map has one
   * raw null attempt. Later direct calls use that cursor and expose the usual
   * high-hint/null fallback pair. */
  const bool huge_selection_matches = expected_huge_calls == 0
      || (expected_huge_calls == 1
          && large_page_retry_probe.call_huge_calls == 1
          && large_page_retry_probe.call_huge_hints[0] == NULL)
      || (expected_huge_calls == 2
          && large_page_retry_probe.call_huge_calls == 2
          && large_page_retry_probe.call_huge_hints[0] != NULL
          && large_page_retry_probe.call_huge_hints[1] == NULL);
  const bool ordinary_owner = error == 0 && address != NULL && !is_large && is_zero
      && large_page_retry_probe.range_consistent
      && large_page_retry_probe.call_huge_calls == expected_huge_calls
      && huge_selection_matches
      && large_page_retry_probe.regular_calls == regular_before + 1
      && large_page_retry_probe.last_regular_address == address
      && large_page_retry_probe.last_regular_length == length;
  const bool live_before_release = ordinary_owner
      && mprotect(address, length, PROT_READ | PROT_WRITE) == 0;
  bool released = false;
  if (address != NULL) {
    large_page_retry_probe.expected_release_address = address;
    large_page_retry_probe.expected_release_length = length;
    const int release_error = _mi_prim_free(address, length);
    released = release_error == 0
        && large_page_retry_probe.release_calls == release_before + 1
        && large_page_retry_probe.last_release_address == address
        && large_page_retry_probe.last_release_length == length
        && large_page_retry_probe.release_exact
        && large_page_retry_probe.last_release_result == 0;
    large_page_retry_probe.expected_release_address = NULL;
  }
  return ordinary_owner && live_before_release && released;
}

static bool large_page_retry_without_suppression(
    size_t length, size_t alignment, bool allow_large) {
  large_page_retry_atomic_record = (large_page_retry_atomic_record_t){
      .active = true,
      .counter_consistent = true,
  };
  const bool owner = large_page_retry_regular_owner(
      length, alignment, allow_large, 0);
  const large_page_retry_atomic_record_t record = large_page_retry_atomic_record;
  large_page_retry_atomic_record.active = false;
  return owner && record.counter_consistent && record.counter == NULL
      && record.cas_count == 0;
}

/* An admitted suppression must use exactly one source strong CAS. The wrapper
 * delegates that CAS unchanged, then only records its expected/desired state;
 * successful source CAS leaves `expected` unchanged. */
static bool large_page_retry_suppressed_regular_owner(
    size_t length, size_t alignment, size_t expected_counter) {
  large_page_retry_atomic_record = (large_page_retry_atomic_record_t){
      .active = true,
      .counter_consistent = true,
  };
  const bool owner = large_page_retry_regular_owner(
      length, alignment, true, 0);
  const large_page_retry_atomic_record_t record = large_page_retry_atomic_record;
  large_page_retry_atomic_record.active = false;
  return owner && record.counter_consistent && record.counter != NULL
      && record.cas_count == 1 && record.cas_expected_before == expected_counter
      && record.cas_expected_after == expected_counter
      && record.cas_desired == expected_counter - 1 && record.cas_succeeded
      && atomic_load_explicit(record.counter, memory_order_acquire)
          == expected_counter - 1;
}

static int run_large_page_retry_normal_child(int record_descriptor) {
  large_page_retry_normal_record_t record = {0};
  size_t length = 0;
  size_t alignment = 0;
  if (!large_page_retry_prepare_source(&length, &alignment)) return 1;
  record.source_options_applied = mi_option_is_enabled(
      mi_option_allow_large_os_pages) && !mi_option_is_enabled(mi_option_allow_thp);
  large_page_retry_probe_begin(length);

  record.initial_failed_large_regular_owner = large_page_retry_regular_owner(
      length, alignment, true, 1);
  record.caller_disables_large_preserves_counter =
      large_page_retry_without_suppression(length, alignment, false);
  record.ineligible_geometry_preserves_counter =
      large_page_retry_without_suppression(length, _mi_os_page_size(), true);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  record.option_disabled_preserves_counter =
      large_page_retry_without_suppression(length, alignment, true);
  mi_option_set(mi_option_allow_large_os_pages, 1);

  record.eight_suppressed_regular_owners = true;
  for (size_t counter = LARGE_PAGE_RETRY_SUPPRESSION_COUNT; counter > 0; counter--) {
    record.eight_suppressed_regular_owners &=
        large_page_retry_suppressed_regular_owner(length, alignment, counter);
  }
  const _Atomic(size_t)* const counter = large_page_retry_atomic_record.counter;
  record.ninth_reopens_large_regular_owner =
      record.eight_suppressed_regular_owners
      && large_page_retry_regular_owner(length, alignment, true, 2)
      && counter != NULL
      && atomic_load_explicit(counter, memory_order_acquire)
          == LARGE_PAGE_RETRY_SUPPRESSION_COUNT;
  large_page_retry_probe_end();

  const bool complete = record.source_options_applied
      && record.initial_failed_large_regular_owner
      && record.caller_disables_large_preserves_counter
      && record.ineligible_geometry_preserves_counter
      && record.option_disabled_preserves_counter
      && record.eight_suppressed_regular_owners
      && record.ninth_reopens_large_regular_owner;
  if (!complete) {
    fprintf(stderr,
            "large-page retry normal record failed: options=%d initial=%d allow_false=%d "
            "ineligible=%d option_disabled=%d eight=%d ninth=%d huge=%zu regular=%zu "
            "release=%zu range=%d exact_release=%d\n",
            record.source_options_applied,
            record.initial_failed_large_regular_owner,
            record.caller_disables_large_preserves_counter,
            record.ineligible_geometry_preserves_counter,
            record.option_disabled_preserves_counter,
            record.eight_suppressed_regular_owners,
            record.ninth_reopens_large_regular_owner,
            large_page_retry_probe.huge_calls,
            large_page_retry_probe.regular_calls,
            large_page_retry_probe.release_calls,
            large_page_retry_probe.range_consistent,
            large_page_retry_probe.release_exact);
  }
  if (!write_all(record_descriptor, &record, sizeof(record))) return 2;
  return complete ? 0 : 3;
}

static void* run_large_page_retry_competitor(void* unused) {
  (void)unused;
  pthread_mutex_lock(&large_page_retry_competitor_lock);
  if (!large_page_retry_wait_for_locked(
          &large_page_retry_competitor_ready,
          &large_page_retry_competitor_waiting)) {
    large_page_retry_competitor_succeeded = false;
    large_page_retry_competitor_finished = true;
    pthread_cond_signal(&large_page_retry_competitor_done);
    pthread_mutex_unlock(&large_page_retry_competitor_lock);
    return NULL;
  }
  _Atomic(size_t)* const counter = large_page_retry_competitor_counter;
  size_t expected = large_page_retry_competitor_expected;
  const size_t desired = large_page_retry_competitor_desired;
  pthread_mutex_unlock(&large_page_retry_competitor_lock);

  const bool swapped = counter != NULL && atomic_compare_exchange_strong_explicit(
      counter, &expected, desired, memory_order_acq_rel, memory_order_acquire);

  pthread_mutex_lock(&large_page_retry_competitor_lock);
  large_page_retry_competitor_succeeded = swapped;
  large_page_retry_competitor_finished = true;
  pthread_cond_signal(&large_page_retry_competitor_done);
  pthread_mutex_unlock(&large_page_retry_competitor_lock);
  return NULL;
}

static int run_large_page_retry_cas_child(int record_descriptor) {
  large_page_retry_cas_record_t record = {0};
  size_t length = 0;
  size_t alignment = 0;
  if (!large_page_retry_prepare_source(&length, &alignment)) return 1;
  record.source_options_applied = mi_option_is_enabled(
      mi_option_allow_large_os_pages) && !mi_option_is_enabled(mi_option_allow_thp);
  large_page_retry_probe_begin(length);
  const bool initial_failed_large_regular_owner = large_page_retry_regular_owner(
      length, alignment, true, 1);
  /* Do not spawn the schedule helper until the selected cold null-hint
   * failed-large setup has proved its ordinary fallback. */
  if (!initial_failed_large_regular_owner
      || large_page_retry_probe.huge_calls != 1
      || large_page_retry_probe.regular_calls != 1) {
    large_page_retry_probe_end();
    return 2;
  }

  large_page_retry_atomic_record = (large_page_retry_atomic_record_t){
      .active = true,
      .counter_consistent = true,
  };
  pthread_mutex_lock(&large_page_retry_competitor_lock);
  large_page_retry_competitor_enabled = true;
  large_page_retry_competitor_waiting = false;
  large_page_retry_competitor_finished = false;
  large_page_retry_competitor_counter = NULL;
  large_page_retry_competitor_expected = 0;
  large_page_retry_competitor_desired = 0;
  large_page_retry_competitor_succeeded = false;
  pthread_mutex_unlock(&large_page_retry_competitor_lock);
  pthread_t competitor;
  if (pthread_create(&competitor, NULL, run_large_page_retry_competitor, NULL) != 0) {
    large_page_retry_competitor_enabled = false;
    large_page_retry_atomic_record.active = false;
    large_page_retry_probe_end();
    return 3;
  }
  const bool competing_regular_owner = large_page_retry_regular_owner(
      length, alignment, true, 0);
  const int join_result = pthread_join(competitor, NULL);
  pthread_mutex_lock(&large_page_retry_competitor_lock);
  large_page_retry_competitor_enabled = false;
  const bool competitor_succeeded = large_page_retry_competitor_succeeded;
  pthread_mutex_unlock(&large_page_retry_competitor_lock);
  const large_page_retry_atomic_record_t cas_record = large_page_retry_atomic_record;
  large_page_retry_atomic_record.active = false;
  const _Atomic(size_t)* const counter = cas_record.counter;
  record.competing_cas_failure_regular_owner = competing_regular_owner
      && join_result == 0 && competitor_succeeded
      && cas_record.counter_consistent && counter != NULL
      && cas_record.cas_count == 1
      && cas_record.cas_expected_before == LARGE_PAGE_RETRY_SUPPRESSION_COUNT
      && cas_record.cas_expected_after == LARGE_PAGE_RETRY_SUPPRESSION_COUNT - 1
      && cas_record.cas_desired == LARGE_PAGE_RETRY_SUPPRESSION_COUNT - 1
      && !cas_record.cas_succeeded
      && atomic_load_explicit(counter, memory_order_acquire)
          == LARGE_PAGE_RETRY_SUPPRESSION_COUNT - 1;

  bool seven_suppressed_regular_owners = true;
  for (size_t counter_before = LARGE_PAGE_RETRY_SUPPRESSION_COUNT - 1;
       counter_before > 0; counter_before--) {
    seven_suppressed_regular_owners &= large_page_retry_suppressed_regular_owner(
        length, alignment, counter_before);
  }
  record.competing_cas_seven_then_reopens =
      record.competing_cas_failure_regular_owner
      && seven_suppressed_regular_owners
      && large_page_retry_regular_owner(length, alignment, true, 2)
      && counter != NULL
      && atomic_load_explicit(counter, memory_order_acquire)
          == LARGE_PAGE_RETRY_SUPPRESSION_COUNT;
  large_page_retry_probe_end();

  if (!write_all(record_descriptor, &record, sizeof(record))) return 4;
  return record.source_options_applied
      && record.competing_cas_failure_regular_owner
      && record.competing_cas_seven_then_reopens ? 0 : 5;
}

typedef int (*large_page_retry_child_body_t)(int record_descriptor);

/* This private test-only PID output lets the empty-record harness prove that
 * this exact fixture child was reaped. It is not a source VM observation and
 * never enters the C/Rust trace schema. */
static bool capture_large_page_retry_child_with_exact_child(
    const char* label, large_page_retry_child_body_t child_body,
    void* record, size_t record_size, pid_t* exact_child) {
  if (exact_child != NULL) *exact_child = -1;
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
    const int result = child_body(descriptors[1]);
    close(descriptors[1]);
    _exit(result);
  }
  if (exact_child != NULL) *exact_child = child;
  close(descriptors[1]);
  const size_t record_bytes = read_all(descriptors[0], record, record_size);
  close(descriptors[0]);
  const bool child_reaped = reap_exact_child(label, child);
  const bool captured = record_bytes == record_size && child_reaped;
  if (!captured) {
    fprintf(stderr, "%s capture failed: bytes=%zu expected=%zu\n",
            label, record_bytes, record_size);
  }
  return captured;
}

static bool capture_large_page_retry_child(
    const char* label, large_page_retry_child_body_t child_body,
    void* record, size_t record_size) {
  return capture_large_page_retry_child_with_exact_child(
      label, child_body, record, record_size, NULL);
}

typedef struct large_only_failure_record_s {
  bool first_one_gib_then_two_mib_same_claim_terminal_enomem;
  bool second_only_two_mib_after_sticky_unavailable;
  bool all_raw_maps_are_huge_and_no_regular_owner;
  bool terminal_failures_leave_statistics_and_owners_unpublished;
} large_only_failure_record_t;

/* Run the source upper huge allocator twice in one COW child. The first
 * `unix_mmap` call is the 1-GiB form and its fallback must retain the exact
 * claimed hint; the second upper call proves the source static unavailable bit
 * selects only 2 MiB at its new claim. Every raw mmap is injected as ENOMEM.
 * This records no ambient terminal errno from `_mi_os_alloc_huge_os_pages`:
 * its C contract returns a pointer and output ownership, while ENOMEM belongs
 * to the wrapped primitive observations. */
static int run_large_only_failure_child(int record_descriptor) {
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) return 1;

  const int64_t reserved_before = current_reserved(subproc);
  const int64_t committed_before = current_committed(subproc);
  large_only_failure_probe = (large_only_failure_probe_t){
      .active = true,
  };

  size_t first_pages = SIZE_MAX;
  size_t first_size = SIZE_MAX;
  mi_memid_t first_memid = _mi_memid_none();
  void* const first = _mi_os_alloc_huge_os_pages(
      subproc, 1, -1, 0, &first_pages, &first_size, &first_memid);
  size_t second_pages = SIZE_MAX;
  size_t second_size = SIZE_MAX;
  mi_memid_t second_memid = _mi_memid_none();
  void* const second = _mi_os_alloc_huge_os_pages(
      subproc, 1, -1, 0, &second_pages, &second_size, &second_memid);
  large_only_failure_probe.active = false;
  const int64_t reserved_after = current_reserved(subproc);
  const int64_t committed_after = current_committed(subproc);

  const int huge_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
  large_only_failure_record_t record = {0};
  record.first_one_gib_then_two_mib_same_claim_terminal_enomem = first == NULL
      && first_pages == 0 && first_size == 0 && first_memid.memkind == MI_MEM_NONE
      && large_only_failure_probe.mmap_calls == 3
      && large_only_failure_probe.hints[0] != NULL
      && large_only_failure_probe.hints[1] == large_only_failure_probe.hints[0]
      && large_only_failure_probe.lengths[0] == MI_GiB
      && large_only_failure_probe.protections[0] == (PROT_READ | PROT_WRITE)
      && large_only_failure_probe.flags[0] == (huge_flags | MAP_HUGE_1GB)
      && large_only_failure_probe.lengths[1] == MI_GiB
      && large_only_failure_probe.protections[1] == (PROT_READ | PROT_WRITE)
      && large_only_failure_probe.flags[1] == (huge_flags | MAP_HUGE_2MB)
      && large_only_failure_probe.errors[0] == ENOMEM
      && large_only_failure_probe.errors[1] == ENOMEM;
  record.second_only_two_mib_after_sticky_unavailable = second == NULL
      && second_pages == 0 && second_size == 0 && second_memid.memkind == MI_MEM_NONE
      && large_only_failure_probe.hints[2] != NULL
      && large_only_failure_probe.hints[2] != large_only_failure_probe.hints[0]
      && large_only_failure_probe.lengths[2] == MI_GiB
      && large_only_failure_probe.protections[2] == (PROT_READ | PROT_WRITE)
      && large_only_failure_probe.flags[2] == (huge_flags | MAP_HUGE_2MB)
      && large_only_failure_probe.errors[2] == ENOMEM;
  record.all_raw_maps_are_huge_and_no_regular_owner = first == NULL && second == NULL
      && large_only_failure_probe.mmap_calls == 3
      && (large_only_failure_probe.flags[0] & MAP_HUGETLB) != 0
      && (large_only_failure_probe.flags[1] & MAP_HUGETLB) != 0
      && (large_only_failure_probe.flags[2] & MAP_HUGETLB) != 0;
  record.terminal_failures_leave_statistics_and_owners_unpublished =
      reserved_after == reserved_before && committed_after == committed_before
      && large_only_failure_probe.madvise_calls == 0
      && first_memid.memkind == MI_MEM_NONE && second_memid.memkind == MI_MEM_NONE;

  const bool complete = record.first_one_gib_then_two_mib_same_claim_terminal_enomem
      && record.second_only_two_mib_after_sticky_unavailable
      && record.all_raw_maps_are_huge_and_no_regular_owner
      && record.terminal_failures_leave_statistics_and_owners_unpublished;
  if (!complete) {
    fprintf(stderr,
            "large-only failure record failed: calls=%zu hints=%p/%p/%p flags=%x/%x/%x "
            "lengths=%zu/%zu/%zu first=%p pages=%zu size=%zu kind=%d second=%p pages=%zu "
            "size=%zu kind=%d reserve=%lld/%lld commit=%lld/%lld madvise=%zu\n",
            large_only_failure_probe.mmap_calls,
            large_only_failure_probe.hints[0], large_only_failure_probe.hints[1],
            large_only_failure_probe.hints[2], large_only_failure_probe.flags[0],
            large_only_failure_probe.flags[1], large_only_failure_probe.flags[2],
            large_only_failure_probe.lengths[0], large_only_failure_probe.lengths[1],
            large_only_failure_probe.lengths[2], first, first_pages, first_size,
            first_memid.memkind, second, second_pages, second_size, second_memid.memkind,
            (long long)reserved_before, (long long)reserved_after,
            (long long)committed_before, (long long)committed_after,
            large_only_failure_probe.madvise_calls);
  }
  if (!write_all(record_descriptor, &record, sizeof(record))) return 2;
  return complete ? 0 : 3;
}

typedef struct huge_branch_matrix_record_s {
  bool partial_primitive_failure_retains_one_os_huge_owner_and_stats;
  bool timeout_after_progress_retains_one_os_huge_owner_and_stats;
  bool placement_failure_is_best_effort_and_retains_one_os_huge_owner;
  bool noncontiguous_adjustment_rejects_owner_after_source_cleanup;
  bool free_continues_after_failed_page_and_applies_source_stats;
} huge_branch_matrix_record_t;

/* The normal profile transmits one Boolean per inner COW child: that is the
 * acceptance boundary, but it cannot explain a failed conjunction. This
 * separate, compile-selected control keeps the five literal source arms and
 * serializes the terms already asserted below. It never enters the evidence
 * producer and does not alter the matrix's Boolean acceptance predicate. */
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
typedef struct huge_branch_case_diagnostic_s {
  size_t selected;
  bool complete;
  bool returned;
  bool page_size;
  bool memid;
  bool huge_mmap;
  bool fallback_mmap;
  bool reserved_stats;
  bool committed_stats;
  bool clock;
  bool suppressed_options;
  bool suppressed_relation;
  bool enabled_options;
  bool mbind_tuple;
  bool diagnostics;
  bool cleanup;
  bool free_initial_owner;
  bool free_tuple;
  size_t mmap_calls;
  size_t munmap_calls;
  size_t clock_calls;
  size_t syscall_calls;
  size_t diagnostic_calls;
  size_t diagnostic_first_length;
  size_t diagnostic_second_length;
  int64_t reserved_delta;
  int64_t committed_delta;
  size_t pages;
  size_t size;
  int memkind;
  char diagnostic_first[96];
  char diagnostic_second[192];
} huge_branch_case_diagnostic_t;

static huge_branch_case_diagnostic_t huge_branch_case_diagnostic;
#endif

static bool huge_branch_huge_mmap_arguments(const huge_branch_probe_t* probe,
                                            size_t count, bool two_mib_after_one_gib_retry) {
  const int base_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
  if (!probe->valid || probe->mmap_calls != count) return false;
  for (size_t index = 0; index < count; index++) {
    /* `unix_mmap` retries the failed second 1GiB primitive at the same hint
     * with 2MiB only after setting its 1GiB-unavailable source state. */
    const int page_flag = two_mib_after_one_gib_retry && index >= 2
        ? MAP_HUGE_2MB : MAP_HUGE_1GB;
    if (probe->hints[index] == NULL || probe->lengths[index] != MI_GiB
        || probe->protections[index] != (PROT_READ | PROT_WRITE)
        || probe->flags[index] != (base_flags | page_flag)) {
      return false;
    }
  }
  return true;
}

static bool huge_branch_anonymous_fallback_arguments(
    const huge_branch_probe_t* probe, size_t count,
    bool noncontiguous_adjustment) {
  const int ordinary_flags = MAP_PRIVATE | MAP_ANONYMOUS;
  for (size_t index = 0; index < count; index++) {
    const int expected_flags = noncontiguous_adjustment
        ? ordinary_flags : (ordinary_flags | MAP_FIXED_NOREPLACE);
    const void* const expected_address = noncontiguous_adjustment
        ? NULL : probe->hints[index];
    if (probe->fallback_addresses[index] != expected_address
        || probe->fallback_flags[index] != expected_flags) {
      return false;
    }
  }
  return true;
}

/* The partial source arm makes one successful primitive mapping, then sees a
 * second 1GiB failure and its same-hint 2MiB retry. Keep that raw sequence,
 * its hint relationship, and its only normal fallback in one predicate so the
 * focused profile regression can exercise the exact fixture behavior. */
static bool huge_branch_partial_primitive_failure_relation(const huge_branch_probe_t* probe) {
  return huge_branch_huge_mmap_arguments(probe, 3, true)
      && probe->hints[0] != probe->hints[1] && probe->hints[1] == probe->hints[2]
      && huge_branch_anonymous_fallback_arguments(probe, 1, false);
}

static int run_huge_branch_partial_retry_helper_test(void) {
  const int huge_flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB;
  huge_branch_probe_t probe = {
      .valid = true,
      .mmap_calls = 3,
      .lengths = { MI_GiB, MI_GiB, MI_GiB },
      .protections = { PROT_READ | PROT_WRITE, PROT_READ | PROT_WRITE,
                       PROT_READ | PROT_WRITE },
      .flags = { huge_flags | MAP_HUGE_1GB, huge_flags | MAP_HUGE_1GB,
                 huge_flags | MAP_HUGE_2MB },
      .fallback_flags = { MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE },
  };
  probe.hints[0] = (void*)(uintptr_t)0x100000000ULL;
  probe.hints[1] = (void*)(uintptr_t)0x200000000ULL;
  probe.hints[2] = probe.hints[1];
  probe.fallback_addresses[0] = probe.hints[0];
  const bool accepts_source_sequence = huge_branch_partial_primitive_failure_relation(&probe);

  probe.flags[1] = huge_flags | MAP_HUGE_2MB;
  const bool rejects_former_wrong_second_flag =
      !huge_branch_partial_primitive_failure_relation(&probe);
  probe.flags[1] = huge_flags | MAP_HUGE_1GB;

  probe.flags[2] = huge_flags | MAP_HUGE_1GB;
  const bool rejects_wrong_fallback_flag = !huge_branch_partial_primitive_failure_relation(&probe);
  probe.flags[2] = huge_flags | MAP_HUGE_2MB;

  probe.hints[2] = (void*)(uintptr_t)0x300000000ULL;
  const bool rejects_wrong_same_hint = !huge_branch_partial_primitive_failure_relation(&probe);

  return accepts_source_sequence && rejects_former_wrong_second_flag
      && rejects_wrong_fallback_flag && rejects_wrong_same_hint ? 0 : 3;
}

#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)

/* `stats.c:_mi_clock_start` first calibrates `mi_clock_diff` with two reads,
 * then takes the start reading. The timeout arm must therefore provide four
 * concrete readings: calibration start/diff, allocation start, and its first
 * elapsed check. This helper rejects the prior three-form fixture sequence
 * before a native source child can accept a second huge page by accident. */
static bool huge_branch_timeout_sequence_reaches_source_timeout(
    const mi_msecs_t readings[4]) {
  const mi_msecs_t clock_diff = readings[1] - readings[0];
  const mi_msecs_t elapsed = readings[3] - readings[2] - clock_diff;
  const mi_msecs_t estimate = elapsed * 2;  // one completed page, two requested
  return estimate > 2 && elapsed > 1;
}

static int run_huge_branch_timeout_clock_helper_test(void) {
  static const mi_msecs_t former_fixture_readings[4] = {0, 2, 2, 2};
  static const mi_msecs_t source_timeout_readings[4] = {0, 1, 1, 4};
  huge_branch_probe = (huge_branch_probe_t){
      .active = true,
      .valid = true,
      .selected = HUGE_BRANCH_PROBE_TIMEOUT_AFTER_PROGRESS,
  };
  mi_msecs_t observed[4] = {0, 0, 0, 0};
  for (size_t index = 0; index < 4; index++) {
    struct timespec time = {0};
    if (__wrap_clock_gettime(CLOCK_MONOTONIC, &time) != 0) return 2;
    observed[index] = (mi_msecs_t)time.tv_sec * 1000 + (mi_msecs_t)time.tv_nsec / 1000000;
  }
  huge_branch_probe.active = false;
  const bool observed_is_source_timeout =
      memcmp(observed, source_timeout_readings, sizeof(observed)) == 0
      && huge_branch_probe.clock_calls == 4
      && huge_branch_timeout_sequence_reaches_source_timeout(observed);
  const bool former_fixture_does_not_timeout =
      !huge_branch_timeout_sequence_reaches_source_timeout(former_fixture_readings);
  return observed_is_source_timeout && former_fixture_does_not_timeout ? 0 : 3;
}

/* Exercise the pinned primitive route, not a synthetic formatting helper:
 * `mi_prim_mbind` returns EPERM, `src/prim/unix/prim.c` takes errno, and
 * `_mi_warning_message` reaches the registered same-thread output callback. */
static int run_huge_branch_placement_warning_helper_test(void) {
  huge_branch_probe = (huge_branch_probe_t){
      .valid = true,
      .selected = HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
  };
  mi_process_init();
  mi_option_set_enabled(mi_option_verbose, false);
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_register_output(m2_fault_inventory_output, NULL);
  huge_branch_probe.active = true;
  bool is_zero = false;
  void* mapping = NULL;
  const int error = _mi_prim_alloc_huge_os_pages(
      (void*)(uintptr_t)(32ULL << 40), MI_GiB, 0, &is_zero, &mapping);
  const huge_branch_probe_t probe = huge_branch_probe;
  huge_branch_probe.active = false;
  const bool complete = error == 0 && mapping != NULL && probe.valid
      && probe.syscall_calls == 1 && probe.diagnostic_calls == 2
      && probe.diagnostic_prefix_first && probe.diagnostic_body_second
      && probe.diagnostic_first_length != 0 && probe.diagnostic_second_length != 0;
  if (mapping != NULL) (void)__real_munmap(mapping, MI_GiB);
  return complete ? 0 : 3;
}

#endif

/* The outer matrix child never initializes pinned source state.  It forks one
 * exact inner child for each fixed arm so `unix_mmap`'s static one-GiB retry
 * state is cold for every branch. The direct-include profile rewrites only
 * `mi_prim_mbind`; process initialization keeps its pinned raw syscalls. */
static int run_huge_branch_case_child(int record_descriptor) {
  bool complete = false;
  huge_branch_probe = (huge_branch_probe_t){
      .valid = true,
      .selected = huge_branch_child_case,
  };
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
  huge_branch_case_diagnostic = (huge_branch_case_diagnostic_t){
      .selected = (size_t)huge_branch_child_case,
  };
#endif
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) {
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
    if (!write_all(record_descriptor, &huge_branch_case_diagnostic,
                   sizeof(huge_branch_case_diagnostic))) return 2;
#else
    if (!write_all(record_descriptor, &complete, sizeof(complete))) return 2;
#endif
    return 3;
  }
  const int64_t reserved_before = current_reserved(subproc);
  const int64_t committed_before = current_committed(subproc);
#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)
  /* Registration flushes any delayed buffer while capture is inactive. Those
   * fragments precede this selected fault and cannot count as its warning. */
  huge_branch_registration_callback_calls = 0;
  mi_register_output(m2_fault_inventory_output, NULL);
#endif
  if (huge_branch_child_case != HUGE_BRANCH_PROBE_PLACEMENT_FAILURE) {
    huge_branch_probe.active = true;
  }

  if (huge_branch_child_case == HUGE_BRANCH_PROBE_PARTIAL_PRIMITIVE_FAILURE) {
    size_t pages = SIZE_MAX;
    size_t size = SIZE_MAX;
    mi_memid_t memid = _mi_memid_none();
    void* const partial = _mi_os_alloc_huge_os_pages(
        subproc, 2, -1, 0, &pages, &size, &memid);
    const huge_branch_probe_t probe = huge_branch_probe;
    huge_branch_probe.active = false;
    complete = partial != NULL && pages == 1 && size == MI_GiB
        && memid.memkind == MI_MEM_OS_HUGE && memid.mem.os.base == partial
        && memid.mem.os.size == MI_GiB
        && huge_branch_partial_primitive_failure_relation(&probe)
        && current_reserved(subproc) == reserved_before + (int64_t)MI_GiB
        && current_committed(subproc) == committed_before + (int64_t)MI_GiB;
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
    huge_branch_case_diagnostic.complete = complete;
    huge_branch_case_diagnostic.returned = partial != NULL;
    huge_branch_case_diagnostic.page_size = pages == 1 && size == MI_GiB;
    huge_branch_case_diagnostic.memid = memid.memkind == MI_MEM_OS_HUGE
        && memid.mem.os.base == partial && memid.mem.os.size == MI_GiB;
    huge_branch_case_diagnostic.huge_mmap = huge_branch_huge_mmap_arguments(&probe, 3, true);
    huge_branch_case_diagnostic.fallback_mmap =
        huge_branch_anonymous_fallback_arguments(&probe, 1, false);
    huge_branch_case_diagnostic.reserved_stats =
        current_reserved(subproc) == reserved_before + (int64_t)MI_GiB;
    huge_branch_case_diagnostic.committed_stats =
        current_committed(subproc) == committed_before + (int64_t)MI_GiB;
    huge_branch_case_diagnostic.mmap_calls = probe.mmap_calls;
    huge_branch_case_diagnostic.munmap_calls = probe.munmap_calls;
    huge_branch_case_diagnostic.reserved_delta = current_reserved(subproc) - reserved_before;
    huge_branch_case_diagnostic.committed_delta = current_committed(subproc) - committed_before;
    huge_branch_case_diagnostic.pages = pages;
    huge_branch_case_diagnostic.size = size;
    huge_branch_case_diagnostic.memkind = (int)memid.memkind;
#endif
    if (partial != NULL) _mi_os_free(subproc, partial, size, memid);
  }
  else if (huge_branch_child_case == HUGE_BRANCH_PROBE_TIMEOUT_AFTER_PROGRESS) {
    size_t pages = SIZE_MAX;
    size_t size = SIZE_MAX;
    mi_memid_t memid = _mi_memid_none();
    void* const timed = _mi_os_alloc_huge_os_pages(
        subproc, 2, -1, 1, &pages, &size, &memid);
    const huge_branch_probe_t probe = huge_branch_probe;
    huge_branch_probe.active = false;
    complete = timed != NULL && pages == 1 && size == MI_GiB
        && memid.memkind == MI_MEM_OS_HUGE && probe.clock_calls >= 2
        && huge_branch_huge_mmap_arguments(&probe, 1, false)
        && huge_branch_anonymous_fallback_arguments(&probe, 1, false)
        && current_reserved(subproc) == reserved_before + (int64_t)MI_GiB
        && current_committed(subproc) == committed_before + (int64_t)MI_GiB;
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
    huge_branch_case_diagnostic.complete = complete;
    huge_branch_case_diagnostic.returned = timed != NULL;
    huge_branch_case_diagnostic.page_size = pages == 1 && size == MI_GiB;
    huge_branch_case_diagnostic.memid = memid.memkind == MI_MEM_OS_HUGE;
    huge_branch_case_diagnostic.clock = probe.clock_calls >= 2;
    huge_branch_case_diagnostic.huge_mmap = huge_branch_huge_mmap_arguments(&probe, 1, false);
    huge_branch_case_diagnostic.fallback_mmap =
        huge_branch_anonymous_fallback_arguments(&probe, 1, false);
    huge_branch_case_diagnostic.reserved_stats =
        current_reserved(subproc) == reserved_before + (int64_t)MI_GiB;
    huge_branch_case_diagnostic.committed_stats =
        current_committed(subproc) == committed_before + (int64_t)MI_GiB;
    huge_branch_case_diagnostic.mmap_calls = probe.mmap_calls;
    huge_branch_case_diagnostic.munmap_calls = probe.munmap_calls;
    huge_branch_case_diagnostic.clock_calls = probe.clock_calls;
    huge_branch_case_diagnostic.reserved_delta = current_reserved(subproc) - reserved_before;
    huge_branch_case_diagnostic.committed_delta = current_committed(subproc) - committed_before;
    huge_branch_case_diagnostic.pages = pages;
    huge_branch_case_diagnostic.size = size;
    huge_branch_case_diagnostic.memkind = (int)memid.memkind;
#endif
    if (timed != NULL) _mi_os_free(subproc, timed, size, memid);
  }
  else if (huge_branch_child_case == HUGE_BRANCH_PROBE_PLACEMENT_FAILURE) {
    mi_option_set_enabled(mi_option_verbose, false);
    mi_option_set_enabled(mi_option_show_errors, false);
    const bool diagnostics_suppressed = !mi_option_is_enabled(mi_option_verbose)
        && !mi_option_is_enabled(mi_option_show_errors);
    huge_branch_probe.active = true;
    size_t suppressed_pages = SIZE_MAX;
    size_t suppressed_size = SIZE_MAX;
    mi_memid_t suppressed_memid = _mi_memid_none();
    void* const suppressed = _mi_os_alloc_huge_os_pages(
        subproc, 1, 62, 0, &suppressed_pages, &suppressed_size, &suppressed_memid);
    const huge_branch_probe_t suppressed_probe = huge_branch_probe;
    huge_branch_probe.active = false;
    const bool suppressed_relation = suppressed != NULL && suppressed_pages == 1
        && suppressed_size == MI_GiB && suppressed_memid.memkind == MI_MEM_OS_HUGE
        && huge_branch_huge_mmap_arguments(&suppressed_probe, 1, false)
        && huge_branch_anonymous_fallback_arguments(&suppressed_probe, 1, false)
        && suppressed_probe.syscall_calls == 1 && suppressed_probe.diagnostic_calls == 0;
    if (suppressed != NULL) _mi_os_free(subproc, suppressed, suppressed_size, suppressed_memid);

    mi_option_set_enabled(mi_option_show_errors, true);
    const bool diagnostics_enabled = !mi_option_is_enabled(mi_option_verbose)
        && mi_option_is_enabled(mi_option_show_errors);
    huge_branch_probe = (huge_branch_probe_t){
        .active = true,
        .valid = true,
        .selected = HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
    };
    size_t pages = SIZE_MAX;
    size_t size = SIZE_MAX;
    mi_memid_t memid = _mi_memid_none();
    void* const placed = _mi_os_alloc_huge_os_pages(
        subproc, 1, 62, 0, &pages, &size, &memid);
    const huge_branch_probe_t probe = huge_branch_probe;
    huge_branch_probe.active = false;
    complete = diagnostics_suppressed && suppressed_relation && diagnostics_enabled
        && placed != NULL && pages == 1 && size == MI_GiB
        && memid.memkind == MI_MEM_OS_HUGE
        && huge_branch_huge_mmap_arguments(&probe, 1, false)
        && huge_branch_anonymous_fallback_arguments(&probe, 1, false)
        && probe.syscall_calls == 1 && probe.mbind_start == placed
        && probe.mbind_length == MI_GiB && probe.mbind_mode == MPOL_PREFERRED
        && probe.mbind_mask_nonnull && probe.mbind_mask_value == (1UL << 62)
        && probe.mbind_maxnode == 8 * MI_INTPTR_SIZE && probe.mbind_flags == 0
        && probe.diagnostic_calls == 2 && probe.diagnostic_prefix_first
        && probe.diagnostic_body_second
        && current_reserved(subproc) == reserved_before + (int64_t)MI_GiB
        && current_committed(subproc) == committed_before + (int64_t)MI_GiB;
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
    huge_branch_case_diagnostic.complete = complete;
    huge_branch_case_diagnostic.returned = placed != NULL;
    huge_branch_case_diagnostic.page_size = pages == 1 && size == MI_GiB;
    huge_branch_case_diagnostic.memid = memid.memkind == MI_MEM_OS_HUGE;
    huge_branch_case_diagnostic.huge_mmap = huge_branch_huge_mmap_arguments(&probe, 1, false);
    huge_branch_case_diagnostic.fallback_mmap =
        huge_branch_anonymous_fallback_arguments(&probe, 1, false);
    huge_branch_case_diagnostic.reserved_stats =
        current_reserved(subproc) == reserved_before + (int64_t)MI_GiB;
    huge_branch_case_diagnostic.committed_stats =
        current_committed(subproc) == committed_before + (int64_t)MI_GiB;
    huge_branch_case_diagnostic.suppressed_options = diagnostics_suppressed;
    huge_branch_case_diagnostic.suppressed_relation = suppressed_relation;
    huge_branch_case_diagnostic.enabled_options = diagnostics_enabled;
    huge_branch_case_diagnostic.mbind_tuple = probe.syscall_calls == 1
        && probe.mbind_start == placed && probe.mbind_length == MI_GiB
        && probe.mbind_mode == MPOL_PREFERRED && probe.mbind_mask_nonnull
        && probe.mbind_mask_value == (1UL << 62) && probe.mbind_maxnode == 8 * MI_INTPTR_SIZE
        && probe.mbind_flags == 0;
    huge_branch_case_diagnostic.diagnostics = probe.diagnostic_calls == 2
        && probe.diagnostic_prefix_first && probe.diagnostic_body_second;
    huge_branch_case_diagnostic.mmap_calls = probe.mmap_calls;
    huge_branch_case_diagnostic.munmap_calls = probe.munmap_calls;
    huge_branch_case_diagnostic.syscall_calls = probe.syscall_calls;
    huge_branch_case_diagnostic.diagnostic_calls = probe.diagnostic_calls;
    huge_branch_case_diagnostic.diagnostic_first_length = probe.diagnostic_first_length;
    huge_branch_case_diagnostic.diagnostic_second_length = probe.diagnostic_second_length;
    huge_branch_case_diagnostic.reserved_delta = current_reserved(subproc) - reserved_before;
    huge_branch_case_diagnostic.committed_delta = current_committed(subproc) - committed_before;
    huge_branch_case_diagnostic.pages = pages;
    huge_branch_case_diagnostic.size = size;
    huge_branch_case_diagnostic.memkind = (int)memid.memkind;
    memcpy(huge_branch_case_diagnostic.diagnostic_first, probe.diagnostic_first,
           sizeof(huge_branch_case_diagnostic.diagnostic_first));
    memcpy(huge_branch_case_diagnostic.diagnostic_second, probe.diagnostic_second,
           sizeof(huge_branch_case_diagnostic.diagnostic_second));
#endif
    if (placed != NULL) _mi_os_free(subproc, placed, size, memid);
  }
  else if (huge_branch_child_case == HUGE_BRANCH_PROBE_NONCONTIGUOUS_ADJUSTMENT) {
    size_t pages = SIZE_MAX;
    size_t size = SIZE_MAX;
    mi_memid_t memid = _mi_memid_none();
    void* const noncontiguous = _mi_os_alloc_huge_os_pages(
        subproc, 1, -1, 0, &pages, &size, &memid);
    const huge_branch_probe_t probe = huge_branch_probe;
    huge_branch_probe.active = false;
    complete = noncontiguous == NULL && pages == 0 && size == 0
        && memid.memkind == MI_MEM_NONE
        && huge_branch_huge_mmap_arguments(&probe, 1, false)
        && huge_branch_anonymous_fallback_arguments(&probe, 1, true)
        && probe.munmap_calls == 1
        && probe.munmap_addresses[0] != probe.hints[0]
        && probe.munmap_lengths[0] == MI_GiB
        && current_reserved(subproc) == reserved_before - (int64_t)MI_GiB
        && current_committed(subproc) == committed_before - (int64_t)MI_GiB;
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
    huge_branch_case_diagnostic.complete = complete;
    huge_branch_case_diagnostic.returned = noncontiguous == NULL;
    huge_branch_case_diagnostic.page_size = pages == 0 && size == 0;
    huge_branch_case_diagnostic.memid = memid.memkind == MI_MEM_NONE;
    huge_branch_case_diagnostic.huge_mmap = huge_branch_huge_mmap_arguments(&probe, 1, false);
    huge_branch_case_diagnostic.fallback_mmap =
        huge_branch_anonymous_fallback_arguments(&probe, 1, true);
    huge_branch_case_diagnostic.cleanup = probe.munmap_calls == 1
        && probe.munmap_addresses[0] != probe.hints[0]
        && probe.munmap_lengths[0] == MI_GiB;
    huge_branch_case_diagnostic.reserved_stats =
        current_reserved(subproc) == reserved_before - (int64_t)MI_GiB;
    huge_branch_case_diagnostic.committed_stats =
        current_committed(subproc) == committed_before - (int64_t)MI_GiB;
    huge_branch_case_diagnostic.mmap_calls = probe.mmap_calls;
    huge_branch_case_diagnostic.munmap_calls = probe.munmap_calls;
    huge_branch_case_diagnostic.reserved_delta = current_reserved(subproc) - reserved_before;
    huge_branch_case_diagnostic.committed_delta = current_committed(subproc) - committed_before;
    huge_branch_case_diagnostic.pages = pages;
    huge_branch_case_diagnostic.size = size;
    huge_branch_case_diagnostic.memkind = (int)memid.memkind;
#endif
  }
  else if (huge_branch_child_case == HUGE_BRANCH_PROBE_FREE_CONTINUES_AFTER_FAILURE) {
    size_t pages = SIZE_MAX;
    size_t size = SIZE_MAX;
    mi_memid_t memid = _mi_memid_none();
    void* const release = _mi_os_alloc_huge_os_pages(
        subproc, 2, -1, 0, &pages, &size, &memid);
    if (release != NULL && pages == 2 && size == 2 * MI_GiB
        && memid.memkind == MI_MEM_OS_HUGE) {
      huge_branch_probe.fail_munmap_ordinal = 1;
      _mi_os_free(subproc, release, size, memid);
    }
    else {
      huge_branch_probe.valid = false;
    }
    const huge_branch_probe_t probe = huge_branch_probe;
    huge_branch_probe.active = false;
    complete = huge_branch_huge_mmap_arguments(&probe, 2, false)
        && huge_branch_anonymous_fallback_arguments(&probe, 2, false)
        && probe.munmap_calls == 2 && probe.munmap_addresses[0] == release
        && probe.munmap_addresses[1] == (uint8_t*)release + MI_GiB
        && probe.munmap_lengths[0] == MI_GiB && probe.munmap_lengths[1] == MI_GiB
        && current_reserved(subproc) == reserved_before
        && current_committed(subproc) == committed_before;
#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
    huge_branch_case_diagnostic.complete = complete;
    huge_branch_case_diagnostic.free_initial_owner = release != NULL && pages == 2
        && size == 2 * MI_GiB && memid.memkind == MI_MEM_OS_HUGE;
    huge_branch_case_diagnostic.huge_mmap = huge_branch_huge_mmap_arguments(&probe, 2, false);
    huge_branch_case_diagnostic.fallback_mmap =
        huge_branch_anonymous_fallback_arguments(&probe, 2, false);
    huge_branch_case_diagnostic.free_tuple = probe.munmap_calls == 2
        && probe.munmap_addresses[0] == release
        && probe.munmap_addresses[1] == (uint8_t*)release + MI_GiB
        && probe.munmap_lengths[0] == MI_GiB && probe.munmap_lengths[1] == MI_GiB;
    huge_branch_case_diagnostic.reserved_stats = current_reserved(subproc) == reserved_before;
    huge_branch_case_diagnostic.committed_stats = current_committed(subproc) == committed_before;
    huge_branch_case_diagnostic.mmap_calls = probe.mmap_calls;
    huge_branch_case_diagnostic.munmap_calls = probe.munmap_calls;
    huge_branch_case_diagnostic.reserved_delta = current_reserved(subproc) - reserved_before;
    huge_branch_case_diagnostic.committed_delta = current_committed(subproc) - committed_before;
    huge_branch_case_diagnostic.pages = pages;
    huge_branch_case_diagnostic.size = size;
    huge_branch_case_diagnostic.memkind = (int)memid.memkind;
#endif
    if (release != NULL) (void)__real_munmap(release, MI_GiB);
  }

#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
  if (!write_all(record_descriptor, &huge_branch_case_diagnostic,
                 sizeof(huge_branch_case_diagnostic))) return 2;
#else
  if (!write_all(record_descriptor, &complete, sizeof(complete))) return 2;
#endif
  return complete ? 0 : 3;
}

static bool capture_huge_branch_case(
    huge_branch_probe_case_t selected, bool* result) {
  huge_branch_child_case = selected;
  return capture_large_page_retry_child(
      "huge branch exact source child", run_huge_branch_case_child,
      result, sizeof(*result));
}

#if defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)
/* This fixed child extends the existing source-included huge allocation
 * witness. It drives only `prim.c:630-645` through its actual caller with the
 * profile's one `mbind` seam: valid node 62 and forced EPERM, gate off/on,
 * and invalid node 63. The anonymous raw mapping is an import-boundary test
 * stand-in; it never claims a hardware hugepage or physical NUMA placement. */
typedef struct fault_diagnostic_relation_record_s {
  bool default_mbind;
  bool default_mapping_survives;
  bool default_stats_survive;
  bool default_continuation_flush;
  bool gate_off_mbind;
  bool gate_off_no_output;
  bool gate_off_mapping_survives;
  bool gate_off_stats_survive;
  bool custom_mbind;
  bool custom_fragments;
  bool custom_mapping_survives;
  bool custom_stats_survive;
  bool invalid_no_mbind;
  bool invalid_no_output;
  bool invalid_mapping_survives;
  bool invalid_stats_survive;
  size_t default_continuation_length;
  char default_continuation[192];
  size_t custom_prefix_length;
  size_t custom_body_length;
  char custom_prefix[96];
  char custom_body[192];
  uintptr_t custom_thread_identity;
} fault_diagnostic_relation_record_t;

static bool fault_diagnostic_relation_probe_is_valid(
    const huge_branch_probe_t* probe, void* mapping) {
  return probe->valid && probe->syscall_calls == 1
      && probe->mbind_result == -1 && probe->mbind_errno == EPERM
      && probe->mbind_start == mapping && probe->mbind_length == MI_GiB
      && probe->mbind_mode == MPOL_PREFERRED && probe->mbind_mask_nonnull
      && probe->mbind_mask_value == (1UL << 62)
      && probe->mbind_maxnode == 8 * MI_INTPTR_SIZE && probe->mbind_flags == 0;
}

static int run_fault_diagnostic_relation_child(int record_descriptor) {
  fault_diagnostic_relation_record_t record = {0};
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  if (subproc == NULL) return 1;

  const int64_t reserved_initial = current_reserved(subproc);
  const int64_t committed_initial = current_committed(subproc);
  mi_option_set_enabled(mi_option_verbose, false);
  mi_option_set_enabled(mi_option_show_errors, true);

  huge_branch_probe = (huge_branch_probe_t){
      .active = true, .valid = true, .selected = HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
  };
  size_t pages = SIZE_MAX;
  size_t size = SIZE_MAX;
  mi_memid_t memid = _mi_memid_none();
  void* const default_mapping = _mi_os_alloc_huge_os_pages(
      subproc, 1, 62, 0, &pages, &size, &memid);
  const huge_branch_probe_t default_probe = huge_branch_probe;
  huge_branch_probe.active = false;
  record.default_mbind = default_mapping != NULL
      && fault_diagnostic_relation_probe_is_valid(&default_probe, default_mapping);
  record.default_mapping_survives = default_mapping != NULL && pages == 1 && size == MI_GiB
      && memid.memkind == MI_MEM_OS_HUGE && memid.mem.os.base == default_mapping;
  record.default_stats_survive = current_reserved(subproc) == reserved_initial + (int64_t)MI_GiB
      && current_committed(subproc) == committed_initial + (int64_t)MI_GiB;

  /* The exact post-init transition flushes this delayed source warning through
   * `fputs(stderr)` between literal markers. It then leaves one continuation
   * LF delayed for the following custom registration; that byte is not folded
   * into this default frame. */
  fprintf(stderr, "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_DEFAULT_BEGIN\n");
  fflush(stderr);
  _mi_options_post_init();
  fprintf(stderr, "CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_DEFAULT_END\n");
  fflush(stderr);
  if (default_mapping != NULL) _mi_os_free(subproc, default_mapping, size, memid);
  if (current_reserved(subproc) != reserved_initial
      || current_committed(subproc) != committed_initial) return 2;

  /* `mi_out_buf_flush(..., false)` retains the flushed warning plus a final
   * continuation LF. Registration observes that exact delayed image while
   * inactive before the explicit custom cases below. */
  huge_branch_registration_callback_calls = 0;
  huge_branch_registration_fragment_length = 0;
  huge_branch_registration_fragment[0] = '\0';
  mi_register_output(m2_fault_inventory_output, NULL);
  record.default_continuation_flush = huge_branch_registration_callback_calls == 1
      && m2_fault_inventory_default_continuation(huge_branch_registration_fragment);
  record.default_continuation_length = huge_branch_registration_fragment_length;
  memcpy(record.default_continuation, huge_branch_registration_fragment,
      sizeof(record.default_continuation));
  huge_branch_probe = (huge_branch_probe_t){
      .active = true, .valid = true, .selected = HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
  };
  mi_option_set_enabled(mi_option_show_errors, false);
  pages = SIZE_MAX;
  size = SIZE_MAX;
  memid = _mi_memid_none();
  void* const gate_off_mapping = _mi_os_alloc_huge_os_pages(
      subproc, 1, 62, 0, &pages, &size, &memid);
  const huge_branch_probe_t gate_off_probe = huge_branch_probe;
  huge_branch_probe.active = false;
  record.gate_off_mbind = gate_off_mapping != NULL
      && fault_diagnostic_relation_probe_is_valid(&gate_off_probe, gate_off_mapping);
  record.gate_off_no_output = gate_off_probe.diagnostic_calls == 0;
  record.gate_off_mapping_survives = gate_off_mapping != NULL && pages == 1 && size == MI_GiB
      && memid.memkind == MI_MEM_OS_HUGE && memid.mem.os.base == gate_off_mapping;
  record.gate_off_stats_survive = current_reserved(subproc) == reserved_initial + (int64_t)MI_GiB
      && current_committed(subproc) == committed_initial + (int64_t)MI_GiB;
  if (gate_off_mapping != NULL) _mi_os_free(subproc, gate_off_mapping, size, memid);
  if (current_reserved(subproc) != reserved_initial
      || current_committed(subproc) != committed_initial) return 3;

  mi_option_set_enabled(mi_option_show_errors, true);
  huge_branch_probe = (huge_branch_probe_t){
      .active = true, .valid = true, .selected = HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
  };
  pages = SIZE_MAX;
  size = SIZE_MAX;
  memid = _mi_memid_none();
  void* const custom_mapping = _mi_os_alloc_huge_os_pages(
      subproc, 1, 62, 0, &pages, &size, &memid);
  const huge_branch_probe_t custom_probe = huge_branch_probe;
  huge_branch_probe.active = false;
  record.custom_mbind = custom_mapping != NULL
      && fault_diagnostic_relation_probe_is_valid(&custom_probe, custom_mapping);
  record.custom_fragments = custom_probe.diagnostic_calls == 2
      && custom_probe.diagnostic_prefix_first && custom_probe.diagnostic_body_second;
  record.custom_mapping_survives = custom_mapping != NULL && pages == 1 && size == MI_GiB
      && memid.memkind == MI_MEM_OS_HUGE && memid.mem.os.base == custom_mapping;
  record.custom_stats_survive = current_reserved(subproc) == reserved_initial + (int64_t)MI_GiB
      && current_committed(subproc) == committed_initial + (int64_t)MI_GiB;
  record.custom_prefix_length = custom_probe.diagnostic_first_length;
  record.custom_body_length = custom_probe.diagnostic_second_length;
  memcpy(record.custom_prefix, custom_probe.diagnostic_first, sizeof(record.custom_prefix));
  memcpy(record.custom_body, custom_probe.diagnostic_second, sizeof(record.custom_body));
  record.custom_thread_identity = (uintptr_t)_mi_thread_id();
  if (custom_mapping != NULL) _mi_os_free(subproc, custom_mapping, size, memid);
  if (current_reserved(subproc) != reserved_initial
      || current_committed(subproc) != committed_initial) return 4;

  huge_branch_probe = (huge_branch_probe_t){
      .active = true, .valid = true, .selected = HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
  };
  pages = SIZE_MAX;
  size = SIZE_MAX;
  memid = _mi_memid_none();
  void* const invalid_mapping = _mi_os_alloc_huge_os_pages(
      subproc, 1, 63, 0, &pages, &size, &memid);
  const huge_branch_probe_t invalid_probe = huge_branch_probe;
  huge_branch_probe.active = false;
  record.invalid_no_mbind = invalid_mapping != NULL && invalid_probe.syscall_calls == 0;
  record.invalid_no_output = invalid_probe.diagnostic_calls == 0;
  record.invalid_mapping_survives = invalid_mapping != NULL && pages == 1 && size == MI_GiB
      && memid.memkind == MI_MEM_OS_HUGE && memid.mem.os.base == invalid_mapping;
  record.invalid_stats_survive = current_reserved(subproc) == reserved_initial + (int64_t)MI_GiB
      && current_committed(subproc) == committed_initial + (int64_t)MI_GiB;
  if (invalid_mapping != NULL) _mi_os_free(subproc, invalid_mapping, size, memid);
  if (current_reserved(subproc) != reserved_initial
      || current_committed(subproc) != committed_initial) return 5;

  const bool complete = record.default_mbind && record.default_mapping_survives
      && record.default_stats_survive && record.default_continuation_flush
      && record.gate_off_mbind && record.gate_off_no_output
      && record.gate_off_mapping_survives && record.gate_off_stats_survive
      && record.custom_mbind && record.custom_fragments && record.custom_mapping_survives
      && record.custom_stats_survive && record.invalid_no_mbind && record.invalid_no_output
      && record.invalid_mapping_survives && record.invalid_stats_survive;
  if (!write_all(record_descriptor, &record, sizeof(record))) return 6;
  return complete ? 0 : 7;
}

static bool capture_fault_diagnostic_relation_child(
    fault_diagnostic_relation_record_t* record) {
  return capture_large_page_retry_child(
      "fault diagnostic relation child", run_fault_diagnostic_relation_child,
      record, sizeof(*record));
}

static void fault_diagnostic_relation_print_hex(const char* bytes, size_t length) {
  for (size_t index = 0; index < length; index++) {
    printf("%02x", (unsigned)(unsigned char)bytes[index]);
  }
}
#endif

#if defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)
/* Unlike the accepting matrix, this direct control retains a false result.
 * Exit 3 is the fixed fixture's failed-conjunction status, while any other
 * status is a capture failure and must not be presented as a diagnosis. */
static bool capture_huge_branch_diagnostic_case(
    huge_branch_probe_case_t selected, huge_branch_case_diagnostic_t* record,
    int* exit_status) {
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
    huge_branch_child_case = selected;
    const int result = run_huge_branch_case_child(descriptors[1]);
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
  const bool exited = waited == child && WIFEXITED(status);
  *exit_status = exited ? WEXITSTATUS(status) : -1;
  return record_bytes == sizeof(*record) && exited
      && (*exit_status == 0 || *exit_status == 3);
}

static const char* huge_branch_diagnostic_case_name(huge_branch_probe_case_t selected) {
  switch (selected) {
    case HUGE_BRANCH_PROBE_PARTIAL_PRIMITIVE_FAILURE: return "partial";
    case HUGE_BRANCH_PROBE_TIMEOUT_AFTER_PROGRESS: return "timeout";
    case HUGE_BRANCH_PROBE_PLACEMENT_FAILURE: return "placement";
    case HUGE_BRANCH_PROBE_NONCONTIGUOUS_ADJUSTMENT: return "noncontiguous";
    case HUGE_BRANCH_PROBE_FREE_CONTINUES_AFTER_FAILURE: return "free";
    default: return "invalid";
  }
}

static void huge_branch_diagnostic_print_hex(const char* bytes, size_t length) {
  if (length == 0) {
    fputc('-', stdout);
    return;
  }
  for (size_t index = 0; index < length; index++) {
    printf("%02x", (unsigned)(unsigned char)bytes[index]);
  }
}

static int run_huge_branch_diagnostic_test(void) {
  const huge_branch_probe_case_t selected[] = {
      HUGE_BRANCH_PROBE_PARTIAL_PRIMITIVE_FAILURE,
      HUGE_BRANCH_PROBE_TIMEOUT_AFTER_PROGRESS,
      HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
      HUGE_BRANCH_PROBE_NONCONTIGUOUS_ADJUSTMENT,
      HUGE_BRANCH_PROBE_FREE_CONTINUES_AFTER_FAILURE,
  };
  bool captured_all = true;
  puts("CRABC_MI_M2_FAULT_SEAM_HUGE_DIAG_BEGIN");
  for (size_t index = 0; index < sizeof(selected) / sizeof(selected[0]); index++) {
    huge_branch_case_diagnostic_t record = {0};
    int exit_status = -1;
    const bool captured = capture_huge_branch_diagnostic_case(
        selected[index], &record, &exit_status);
    captured_all = captured_all && captured;
    printf("case=%s selected=%zu captured=%zu exit_status=%d complete=%zu "
           "returned=%zu page_size=%zu memid=%zu huge_mmap=%zu fallback_mmap=%zu "
           "reserved_stats=%zu committed_stats=%zu clock=%zu suppressed_options=%zu "
           "suppressed_relation=%zu enabled_options=%zu mbind_tuple=%zu diagnostics=%zu "
           "cleanup=%zu free_initial_owner=%zu free_tuple=%zu mmap_calls=%zu "
           "munmap_calls=%zu clock_calls=%zu syscall_calls=%zu diagnostic_calls=%zu "
           "reserved_delta=%lld committed_delta=%lld pages=%zu size=%zu memkind=%d "
           "diagnostic_first_length=%zu diagnostic_second_length=%zu diagnostic_first_hex=",
           huge_branch_diagnostic_case_name(selected[index]), (size_t)selected[index],
           (size_t)captured, exit_status, (size_t)record.complete,
           (size_t)record.returned, (size_t)record.page_size, (size_t)record.memid,
           (size_t)record.huge_mmap, (size_t)record.fallback_mmap,
           (size_t)record.reserved_stats, (size_t)record.committed_stats,
           (size_t)record.clock, (size_t)record.suppressed_options,
           (size_t)record.suppressed_relation, (size_t)record.enabled_options,
           (size_t)record.mbind_tuple, (size_t)record.diagnostics,
           (size_t)record.cleanup, (size_t)record.free_initial_owner,
           (size_t)record.free_tuple, record.mmap_calls, record.munmap_calls,
           record.clock_calls, record.syscall_calls, record.diagnostic_calls,
           (long long)record.reserved_delta, (long long)record.committed_delta,
           record.pages, record.size, record.memkind,
           record.diagnostic_first_length, record.diagnostic_second_length);
    huge_branch_diagnostic_print_hex(record.diagnostic_first, record.diagnostic_first_length);
    fputs(" diagnostic_second_hex=", stdout);
    huge_branch_diagnostic_print_hex(record.diagnostic_second, record.diagnostic_second_length);
    fputc('\n', stdout);
  }
  puts("CRABC_MI_M2_FAULT_SEAM_HUGE_DIAG_END");
  return captured_all ? 0 : 4;
}
#endif

static int run_huge_branch_matrix_child(int record_descriptor) {
  huge_branch_matrix_record_t record = {0};
  const bool partial = capture_huge_branch_case(
      HUGE_BRANCH_PROBE_PARTIAL_PRIMITIVE_FAILURE,
      &record.partial_primitive_failure_retains_one_os_huge_owner_and_stats);
  const bool timeout = capture_huge_branch_case(
      HUGE_BRANCH_PROBE_TIMEOUT_AFTER_PROGRESS,
      &record.timeout_after_progress_retains_one_os_huge_owner_and_stats);
  const bool placement = capture_huge_branch_case(
      HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
      &record.placement_failure_is_best_effort_and_retains_one_os_huge_owner);
  const bool noncontiguous = capture_huge_branch_case(
      HUGE_BRANCH_PROBE_NONCONTIGUOUS_ADJUSTMENT,
      &record.noncontiguous_adjustment_rejects_owner_after_source_cleanup);
  const bool free_continues = capture_huge_branch_case(
      HUGE_BRANCH_PROBE_FREE_CONTINUES_AFTER_FAILURE,
      &record.free_continues_after_failed_page_and_applies_source_stats);
  const bool complete = partial && timeout && placement && noncontiguous && free_continues
      && record.partial_primitive_failure_retains_one_os_huge_owner_and_stats
      && record.timeout_after_progress_retains_one_os_huge_owner_and_stats
      && record.placement_failure_is_best_effort_and_retains_one_os_huge_owner
      && record.noncontiguous_adjustment_rejects_owner_after_source_cleanup
      && record.free_continues_after_failed_page_and_applies_source_stats;
  if (!write_all(record_descriptor, &record, sizeof(record))) return 2;
  return complete ? 0 : 3;
}

static bool capture_huge_branch_matrix_child(huge_branch_matrix_record_t* record) {
  return capture_large_page_retry_child(
      "huge branch source matrix child", run_huge_branch_matrix_child,
      record, sizeof(*record));
}

/* A fixture-ownership regression, deliberately separate from the upstream VM
 * trace: an empty child record must reject capture and still leave no waitable
 * exact child. With the old short-circuit this final wait consumes the zombie;
 * with unconditional reaping it reports ECHILD. */
static int run_large_page_retry_empty_record_child(int record_descriptor) {
  (void)record_descriptor;
  return 0;
}

static int run_large_page_retry_empty_record_reap_test(void) {
  uint8_t record = 0;
  pid_t child = -1;
  const bool captured = capture_large_page_retry_child_with_exact_child(
      "large-page retry empty record child",
      run_large_page_retry_empty_record_child,
      &record, sizeof(record), &child);
  if (captured || child <= 0) {
    fprintf(stderr,
            "large-page retry empty-record reap: capture_rejected=%d "
            "exact_child_echild=0\n",
            !captured);
    return 1;
  }

  int status = 0;
  pid_t waited;
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  const bool exact_child_echild = waited == -1 && errno == ECHILD;
  fprintf(stderr,
          "large-page retry empty-record reap: capture_rejected=%d "
          "exact_child_echild=%d\n",
          !captured, exact_child_echild);
  return exact_child_echild ? 0 : 2;
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

#if defined(CRABC_M2_OS_PUBLICATION_PROFILE)
/* Each case starts from the same real process initialization in a COW child.
 * A PageMap fault requires a previously absent lazy submap. If the source's
 * normal high hint shares an already present submap, release that successful
 * setup page and ask the unmodified allocator for the next page. No pointer,
 * metadata, source function, or PageMap slot is fabricated. */
static unsigned os_publication_case;
static int run_os_publication_child(int descriptor) {
  mi_process_init();
  mi_option_set(mi_option_disallow_arena_alloc, 1);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_show_errors, 0);
  mi_theap_t* const theap = _mi_subproc_main()->theap_meta;
  bool facts[8] = {0};
  for (unsigned attempt = 0; attempt < 16; attempt++) {
    memset(&os_publication_probe, 0, sizeof(os_publication_probe));
    os_publication_probe.selected = os_publication_case;
    os_publication_probe.active = true;
    mi_page_t* page = _mi_arenas_page_alloc(theap, 128 * MI_KiB, 128 * MI_KiB);
    if ((os_publication_case == 4 || os_publication_case == 6)
        && os_publication_probe.map_faults == 0 && page != NULL) {
      os_publication_probe.active = false;
      _mi_arenas_page_free(page, theap);
      continue;
    }
    const bool returned_page = page != NULL;
    if (page != NULL) _mi_arenas_page_free(page, theap);
    os_publication_probe.active = false;
    const size_t expected_commits = (os_publication_case == 1 ? 0
        : (os_publication_case == 2 || os_publication_case == 5 ? 1 : 2));
    facts[0] = returned_page == (os_publication_case == 7);
    facts[1] = os_publication_probe.commits == expected_commits;
    facts[2] = (os_publication_probe.map_faults != 0)
        == (os_publication_case == 1 || os_publication_case == 4 || os_publication_case == 6);
    facts[3] = os_publication_probe.releases == (os_publication_case == 1 ? 0 : 1);
    facts[4] = os_publication_probe.retained == (os_publication_case >= 5);
    facts[5] = os_publication_probe.base == NULL
        || _mi_safe_ptr_page((uint8_t*)os_publication_probe.base + 128 * MI_KiB) == NULL;
    facts[6] = true;
    facts[7] = true;
    if (os_publication_probe.retained) {
      const int64_t reserved = _mi_subproc_main()->stats.reserved.current;
      const int64_t committed = _mi_subproc_main()->stats.committed.current;
      /* C's upper free is void and retains no retry token. This exact lower
       * primitive cleanup discharges only the fixture's observed failed range;
       * reentering upper free would repeat source statistics. */
      facts[6] = _mi_prim_free(os_publication_probe.base, os_publication_probe.length) == 0;
      facts[7] = reserved == _mi_subproc_main()->stats.reserved.current
          && committed == _mi_subproc_main()->stats.committed.current;
    }
    for (size_t i = 0; i < 8; i++) if (!facts[i]) return (int)(20 + i);
    return write(descriptor, facts, sizeof(facts)) == sizeof(facts) ? 0 : 40;
  }
  return 41;
}

int main(void) {
  const char* fields[] = {"page_result", "commit_branch", "map_branch", "release_once",
      "cleanup_retention", "unreachable", "raw_retry", "retry_statistics"};
  puts("CRABC_MI_M2_OS_PUBLICATION_TRACE_BEGIN");
  for (unsigned selected = 1; selected <= 7; selected++) {
    bool facts[8] = {0};
    os_publication_case = selected;
    if (!capture_large_page_retry_child("OS publication child", run_os_publication_child,
        facts, sizeof(facts))) return 1;
    for (size_t i = 0; i < 8; i++)
      printf("os_publication.%u.%s=%u\n", selected, fields[i], (unsigned)facts[i]);
  }
  puts("CRABC_MI_M2_OS_PUBLICATION_TRACE_END");
  return 0;
}
#elif defined(CRABC_M2_FAULT_SEAM_MBIND_BOUNDARY_TEST)

int main(void) {
  huge_branch_probe = (huge_branch_probe_t){
      .valid = true,
      .selected = HUGE_BRANCH_PROBE_PLACEMENT_FAILURE,
  };
  mi_process_init();
  const bool initialization_skipped_mbind_capture = huge_branch_probe.syscall_calls == 0;
  const unsigned long mask = 1;
  void* const address = (void*)(uintptr_t)0x100000000ULL;
  huge_branch_probe.active = true;
  errno = 0;
  const long result = mi_prim_mbind(
      address, MI_GiB, MPOL_PREFERRED, &mask, 8 * MI_INTPTR_SIZE, 0);
  const bool complete = initialization_skipped_mbind_capture
      && result == -1 && errno == EPERM && huge_branch_probe.valid
      && huge_branch_probe.syscall_calls == 1
      && huge_branch_probe.mbind_start == address
      && huge_branch_probe.mbind_length == MI_GiB
      && huge_branch_probe.mbind_mode == MPOL_PREFERRED
      && huge_branch_probe.mbind_mask_nonnull && huge_branch_probe.mbind_mask_value == 1UL
      && huge_branch_probe.mbind_maxnode == 8 * MI_INTPTR_SIZE
      && huge_branch_probe.mbind_flags == 0;
  if (complete) puts("allocator fault seam mbind boundary: PASS");
  return complete ? 0 : 3;
}

#elif defined(CRABC_M2_FAULT_SEAM_RETRY_HELPER_TEST)

int main(void) {
  const int result = run_huge_branch_partial_retry_helper_test();
  if (result == 0) puts("allocator fault seam partial huge retry helper: PASS");
  return result;
}

#elif defined(CRABC_M2_FAULT_SEAM_TIMEOUT_CLOCK_HELPER_TEST)

int main(void) {
  const int result = run_huge_branch_timeout_clock_helper_test();
  if (result == 0) puts("allocator fault seam timeout clock helper: PASS");
  return result;
}

#elif defined(CRABC_M2_FAULT_SEAM_PLACEMENT_WARNING_HELPER_TEST)

int main(void) {
  const int result = run_huge_branch_placement_warning_helper_test();
  if (result == 0) puts("allocator fault seam placement warning helper: PASS");
  return result;
}

#elif defined(CRABC_M2_FAULT_SEAM_HUGE_DIAGNOSTIC_TEST)

int main(void) {
  return run_huge_branch_diagnostic_test();
}

#elif defined(CRABC_M2_FAULT_SEAM_INVENTORY_PROFILE)

/* This output is intentionally distinct from the broad VM trace. It records
 * only source branch relations which a normal anonymous mapping can simulate
 * at the import boundary; no row represents a successful hardware hugepage
 * or NUMA placement. The placement arm does register the pinned C output
 * callback and requires its one selected source warning. */
int main(void) {
  huge_branch_matrix_record_t record = {0};
  fault_diagnostic_relation_record_t diagnostic = {0};
  if (!capture_huge_branch_matrix_child(&record)) return 1;
  if (!capture_fault_diagnostic_relation_child(&diagnostic)) return 2;
  puts("CRABC_MI_M2_FAULT_SEAM_INVENTORY_C_TRACE_BEGIN");
  U("m2.fault.c.huge.partial_primitive_failure_retains_one_os_huge_owner_and_stats",
      record.partial_primitive_failure_retains_one_os_huge_owner_and_stats);
  U("m2.fault.c.huge.timeout_after_progress_retains_one_os_huge_owner_and_stats",
      record.timeout_after_progress_retains_one_os_huge_owner_and_stats);
  U("m2.fault.c.huge.noncontiguous_adjustment_rejects_owner_after_source_cleanup",
      record.noncontiguous_adjustment_rejects_owner_after_source_cleanup);
  U("m2.fault.c.huge.placement_failure_is_best_effort_and_retains_one_os_huge_owner",
      record.placement_failure_is_best_effort_and_retains_one_os_huge_owner);
  U("m2.fault.c.huge.free_continues_after_failed_page_and_applies_source_stats",
      record.free_continues_after_failed_page_and_applies_source_stats);
  puts("CRABC_MI_M2_FAULT_SEAM_INVENTORY_C_TRACE_END");
  puts("CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_TRACE_BEGIN");
  U("default_mbind", diagnostic.default_mbind);
  U("default_mapping_survives", diagnostic.default_mapping_survives);
  U("default_stats_survive", diagnostic.default_stats_survive);
  U("default_continuation_flush", diagnostic.default_continuation_flush);
  U("gate_off_mbind", diagnostic.gate_off_mbind);
  U("gate_off_no_output", diagnostic.gate_off_no_output);
  U("gate_off_mapping_survives", diagnostic.gate_off_mapping_survives);
  U("gate_off_stats_survive", diagnostic.gate_off_stats_survive);
  U("custom_mbind", diagnostic.custom_mbind);
  U("custom_fragments", diagnostic.custom_fragments);
  U("custom_mapping_survives", diagnostic.custom_mapping_survives);
  U("custom_stats_survive", diagnostic.custom_stats_survive);
  U("invalid_no_mbind", diagnostic.invalid_no_mbind);
  U("invalid_no_output", diagnostic.invalid_no_output);
  U("invalid_mapping_survives", diagnostic.invalid_mapping_survives);
  U("invalid_stats_survive", diagnostic.invalid_stats_survive);
  printf("custom_thread_identity=%zu\n", (size_t)diagnostic.custom_thread_identity);
  fputs("default_continuation_hex=", stdout);
  fault_diagnostic_relation_print_hex(
      diagnostic.default_continuation, diagnostic.default_continuation_length);
  fputc('\n', stdout);
  fputs("custom_prefix_hex=", stdout);
  fault_diagnostic_relation_print_hex(diagnostic.custom_prefix, diagnostic.custom_prefix_length);
  fputc('\n', stdout);
  fputs("custom_body_hex=", stdout);
  fault_diagnostic_relation_print_hex(diagnostic.custom_body, diagnostic.custom_body_length);
  fputc('\n', stdout);
  puts("CRABC_MI_M2_FAULT_DIAGNOSTIC_RELATION_C_TRACE_END");
  return 0;
}

#elif defined(CRABC_M2_LARGE_PAGE_RETRY_CAPTURE_REAP_TEST)

int main(void) {
  return run_large_page_retry_empty_record_reap_test();
}

#elif defined(CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE)

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
  /* These selected children run before the first-arena option row. Their directly
   * included `unix_mmap` static retry state therefore begins at zero in each
   * selected source process; neither record inherits a prior large failure. */
  large_page_retry_normal_record_t large_page_retry_normal_record = {0};
  if (!capture_large_page_retry_child(
          "large-page retry normal child", run_large_page_retry_normal_child,
          &large_page_retry_normal_record,
          sizeof(large_page_retry_normal_record))) return 41;
  large_page_retry_cas_record_t large_page_retry_cas_record = {0};
  if (!capture_large_page_retry_child(
          "large-page retry CAS child", run_large_page_retry_cas_child,
          &large_page_retry_cas_record,
          sizeof(large_page_retry_cas_record))) return 42;
  large_only_failure_record_t large_only_failure_record = {0};
  if (!capture_large_page_retry_child(
          "large-only one-GiB failure child", run_large_only_failure_child,
          &large_only_failure_record,
          sizeof(large_only_failure_record))) return 43;

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
  thp_direct_policy_record_t thp_direct_policy_records[8] = {{0}};
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_ALLOW_ENABLED, &thp_direct_policy_records[0])) return 44;
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_QUERY_PERM, &thp_direct_policy_records[1])) return 44;
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_QUERY_INVAL, &thp_direct_policy_records[2])) return 44;
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_QUERY_NONZERO_ONE, &thp_direct_policy_records[3])) return 44;
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_QUERY_NONZERO_THREE, &thp_direct_policy_records[4])) return 44;
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_SET_SUCCESS, &thp_direct_policy_records[5])) return 44;
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_SET_PERM, &thp_direct_policy_records[6])) return 44;
  if (!capture_thp_direct_policy_child(
          THP_DIRECT_POLICY_CASE_SET_INVAL, &thp_direct_policy_records[7])) return 44;
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

  /* The source reset cache starts at MADV_FREE. The child owns the isolated
   * fallback-EAGAIN row, preserving the parent's FREE cache for the two
   * succeeding rows below. It proves the source does not loop the fallback
   * `MADV_DONTNEED` call after an EAGAIN. */
  const bool reset_fallback_eagain_returns_error_after_one_fallback_attempt =
      capture_reset_fallback_eagain_child(subproc, reserved, page);
  if (!reset_fallback_eagain_returns_error_after_one_fallback_attempt) return 17;

  /* First, an EAGAIN retries the original snapshot and leaves the global
   * source advice at FREE. The script's final zero still reaches the actual
   * Linux madvise import. */
  const reset_madvise_step_t retry_free_steps[] = {
    { MADV_FREE, EAGAIN },
    { MADV_FREE, 0 },
  };
  const int64_t reset_retry_before = current_reset(subproc);
  const int64_t reset_retry_calls_before = current_reset_calls(subproc);
  captured_transition_madvise_calls = 0;
  capture_transition_madvise = true;
  const bool reset_retry_began = reset_madvise_script_begin(retry_free_steps, 2);
  const bool reset_eagain_succeeds =
      reset_retry_began && _mi_os_reset(subproc, reserved, page);
  const bool reset_retry_complete = reset_madvise_script_finish();
  capture_transition_madvise = false;
  const bool reset_eagain_retries_initial_madv_free = reset_eagain_succeeds
      && reset_retry_complete
      && captured_transition_madvise_calls == 2
      && captured_transition_madvise_exact_range(reserved, page, 2)
      && captured_transition_advices[0] == MADV_FREE
      && captured_transition_advices[1] == MADV_FREE
      && current_reset_calls(subproc) == reset_retry_calls_before + 1
      && current_reset(subproc) == reset_retry_before + (int64_t)page
      && mprotect(reserved, page, PROT_READ | PROT_WRITE) == 0;
  if (!reset_eagain_retries_initial_madv_free) return 17;

  /* Then FREE/EINVAL follows one EAGAIN retry, stores the global
   * MADV_DONTNEED state, and makes exactly one succeeding fallback call. */
  const reset_madvise_step_t fallback_steps[] = {
    { MADV_FREE, EAGAIN },
    { MADV_FREE, EINVAL },
    { MADV_DONTNEED, 0 },
  };
  const int64_t reset_fallback_before = current_reset(subproc);
  const int64_t reset_fallback_calls_before = current_reset_calls(subproc);
  captured_transition_madvise_calls = 0;
  capture_transition_madvise = true;
  const bool reset_fallback_began = reset_madvise_script_begin(fallback_steps, 3);
  const bool reset_fallback_succeeds =
      reset_fallback_began && _mi_os_reset(subproc, reserved, page);
  const bool reset_fallback_complete = reset_madvise_script_finish();
  capture_transition_madvise = false;
  const bool reset_free_einval_falls_back_to_dontneed = reset_fallback_succeeds
      && reset_fallback_complete
      && captured_transition_madvise_calls == 3
      && captured_transition_madvise_exact_range(reserved, page, 3)
      && captured_transition_advices[0] == MADV_FREE
      && captured_transition_advices[1] == MADV_FREE
      && captured_transition_advices[2] == MADV_DONTNEED
      && current_reset_calls(subproc) == reset_fallback_calls_before + 1
      && current_reset(subproc) == reset_fallback_before + (int64_t)page
      && mprotect(reserved, page, PROT_READ | PROT_WRITE) == 0;
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
  const reset_madvise_step_t purge_reset_error_steps[] = {
    { MADV_DONTNEED, EAGAIN },
    { MADV_DONTNEED, ENOMEM },
  };
  const int64_t purge_reset_calls_before = current_purge_calls(subproc);
  const int64_t purge_reset_bytes_before = current_purged(subproc);
  const int64_t purge_reset_reset_calls_before = current_reset_calls(subproc);
  const int64_t purge_reset_reset_before = current_reset(subproc);
  const int64_t purge_reset_committed_before = current_committed(subproc);
  captured_transition_madvise_calls = 0;
  const bool purge_reset_began = reset_madvise_script_begin(purge_reset_error_steps, 2);
  const bool purge_reset_failure_is_consumed =
      purge_reset_began && !_mi_os_purge(subproc, reserved, page);
  const bool purge_reset_complete = reset_madvise_script_finish();
  const bool reset_dontneed_persists_to_no_callback_purge = purge_reset_complete
      && captured_transition_madvise_calls == 2
      && captured_transition_madvise_exact_range(reserved, page, 2)
      && captured_transition_advices[0] == MADV_DONTNEED
      && captured_transition_advices[1] == MADV_DONTNEED;
  const bool purge_reset_eagain_then_error_is_consumed_and_owner_retained =
      purge_reset_failure_is_consumed
      && reset_dontneed_persists_to_no_callback_purge
      && current_purge_calls(subproc) == purge_reset_calls_before + 1
      && current_purged(subproc) == purge_reset_bytes_before + (int64_t)page
      && current_reset_calls(subproc) == purge_reset_reset_calls_before + 1
      && current_reset(subproc) == purge_reset_reset_before + (int64_t)page
      && current_committed(subproc) == purge_reset_committed_before
      && mprotect(reserved, page, PROT_READ | PROT_WRITE) == 0;
  capture_transition_madvise = false;
  if (!purge_decommit_failure_no_recommit || !purge_decommit_retry_no_recommit
      || !purge_reset_eagain_then_error_is_consumed_and_owner_retained) {
    fprintf(stderr,
            "purge_decommit_failure_no_recommit=%d "
            "purge_decommit_retry_no_recommit=%d "
            "purge_reset_failure_is_consumed=%d persistent_dontneed=%d "
            "purge_reset_eagain_then_error=%d purge_decommits=%ld "
            "purge_delay=%ld\n",
            purge_decommit_failure_no_recommit,
            purge_decommit_retry_no_recommit,
            purge_reset_failure_is_consumed,
            reset_dontneed_persists_to_no_callback_purge,
            purge_reset_eagain_then_error_is_consumed_and_owner_retained,
            mi_option_get(mi_option_purge_decommits),
            mi_option_get(mi_option_purge_delay));
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
  U("m2.vm.thp_direct.allow_enabled_zero_calls_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_ALLOW_ENABLED, &thp_direct_policy_records[0]));
  U("m2.vm.thp_direct.query_perm_get_only_disabled_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_QUERY_PERM, &thp_direct_policy_records[1]));
  U("m2.vm.thp_direct.query_inval_get_only_disabled_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_QUERY_INVAL, &thp_direct_policy_records[2]));
  U("m2.vm.thp_direct.query_nonzero_one_get_only_disabled_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_QUERY_NONZERO_ONE, &thp_direct_policy_records[3]));
  U("m2.vm.thp_direct.query_nonzero_three_get_only_disabled_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_QUERY_NONZERO_THREE, &thp_direct_policy_records[4]));
  U("m2.vm.thp_direct.set_success_exact_get_set_disabled_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_SET_SUCCESS, &thp_direct_policy_records[5]));
  U("m2.vm.thp_direct.set_perm_exact_get_set_disabled_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_SET_PERM, &thp_direct_policy_records[6]));
  U("m2.vm.thp_direct.set_inval_exact_get_set_disabled_and_continues",
      thp_direct_policy_record_passes(
          THP_DIRECT_POLICY_CASE_SET_INVAL, &thp_direct_policy_records[7]));
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
  U("m2.vm.reserved.reset.eagain_retries_initial_madv_free",
      reset_eagain_retries_initial_madv_free);
  U("m2.vm.reserved.reset.fallback_eagain_returns_error_after_one_fallback_attempt",
      reset_fallback_eagain_returns_error_after_one_fallback_attempt);
  U("m2.vm.reserved.reset_success", 1);
  U("m2.vm.reserved.purge.decommit_failure_no_recommit",
      purge_decommit_failure_no_recommit);
  U("m2.vm.reserved.purge.decommit_retry_no_recommit",
      purge_decommit_retry_no_recommit);
  U("m2.vm.reserved.purge.reset_failure_is_consumed",
      purge_reset_failure_is_consumed);
  U("m2.vm.reserved.reset.dontneed_persists_to_no_callback_purge",
      reset_dontneed_persists_to_no_callback_purge);
  U("m2.vm.reserved.purge.reset_eagain_then_error_is_consumed_and_owner_retained",
      purge_reset_eagain_then_error_is_consumed_and_owner_retained);
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
  U("m2.vm.large_retry.initial_failed_large_regular_owner",
      large_page_retry_normal_record.initial_failed_large_regular_owner);
  U("m2.vm.large_retry.allow_large_false_preserves_counter",
      large_page_retry_normal_record.caller_disables_large_preserves_counter);
  U("m2.vm.large_retry.ineligible_geometry_preserves_counter",
      large_page_retry_normal_record.ineligible_geometry_preserves_counter);
  U("m2.vm.large_retry.option_disabled_preserves_counter",
      large_page_retry_normal_record.option_disabled_preserves_counter);
  U("m2.vm.large_retry.eight_suppressed_regular_owners",
      large_page_retry_normal_record.eight_suppressed_regular_owners);
  U("m2.vm.large_retry.ninth_reopens_large_regular_owner",
      large_page_retry_normal_record.ninth_reopens_large_regular_owner);
  U("m2.vm.large_retry.competing_cas_failure_regular_owner",
      large_page_retry_cas_record.competing_cas_failure_regular_owner);
  U("m2.vm.large_retry.competing_cas_seven_then_reopens",
      large_page_retry_cas_record.competing_cas_seven_then_reopens);
  U("m2.vm.large_only.first_one_gib_then_two_mib_same_claim_terminal_enomem",
      large_only_failure_record.first_one_gib_then_two_mib_same_claim_terminal_enomem);
  U("m2.vm.large_only.second_only_two_mib_after_sticky_unavailable",
      large_only_failure_record.second_only_two_mib_after_sticky_unavailable);
  U("m2.vm.large_only.all_raw_maps_are_huge_and_no_regular_owner",
      large_only_failure_record.all_raw_maps_are_huge_and_no_regular_owner);
  U("m2.vm.large_only.terminal_failures_leave_statistics_and_owners_unpublished",
      large_only_failure_record.terminal_failures_leave_statistics_and_owners_unpublished);
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
#endif  /* CRABC_M2_LARGE_PAGE_RETRY_CAPTURE_REAP_TEST ||
             CRABC_M2_ALIGNED_HINT_SOURCE_PROFILE */

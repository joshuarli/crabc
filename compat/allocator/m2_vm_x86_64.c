/* Native x86-64 M2 VM-primitives oracle.
 *
 * This intentionally includes the fixed v3.5.0 `src/os.c` and `src/arena.c`
 * into the probe so their private configuration, OS-allocation, and first
 * arena-reserve bodies are observed directly. The Python producer omits those
 * two ordinary source objects from the link list. It records address-free
 * fixed-profile facts for the regular lifecycle and one bounded, child-only
 * source-option/first-arena policy record. It does not qualify ambient
 * retries, huge-page success/placement, diagnostics, or general arena use.
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
#include <unistd.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

/* Resolved through `-I <pinned-source>/src`; keep each private source body
 * singular by omitting `src/os.c` and `src/arena.c` from the ordinary C
 * source list. */
#include "os.c"
#include "arena.c"

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
static bool capture_transition_madvise = false;
static size_t captured_transition_madvise_calls = 0;
static int captured_transition_advices[4];
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

typedef struct policy_child_record_s {
  bool source_options_applied;
  size_t first_arena_size;
  bool first_arena_initially_committed;
  bool large_high_hint_failed;
  bool large_null_hint_retry_failed;
  bool regular_hinted_map_after_large_fallback;
  bool thp_advice_failure_ignored;
} policy_child_record_t;

int __real_munmap(void* address, size_t length);
void* __real_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset);
int __real_madvise(void* address, size_t length, int advice);
int __real_mprotect(void* address, size_t length, int protection);

int __wrap_munmap(void* address, size_t length) {
  wrapped_munmap_calls++;
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
    captured_transition_advices[captured_transition_madvise_calls] = advice;
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

int main(void) {
  policy_child_record_t policy_record = {0};
  if (!capture_policy_child(&policy_record)) return 8;
  /* Keep the source's real startup ordering but suppress prim.c's automatic
   * constructor in the producer build.  `_mi_os_*` updates its subprocess
   * statistics even at MI_STAT=0, so it needs the real initialized owner. */
  _mi_detect_cpu_features();
  _mi_options_init();
  /* Select the source `allow_thp=0` option before the exact `_mi_os_init`
   * call. This executable is its own native evidence process, so its
   * process-local `PR_SET_THP_DISABLE` transition cannot alter the runner. */
  mi_option_set(mi_option_allow_thp, 0);
  _mi_stats_init();
  _mi_os_init();
  mi_subproc_t* const subproc = _mi_subproc_main_init();
  if (subproc == NULL) return 10;

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
  U("m2.vm.numa.count_at_least_one", numa_count >= 1);
  U("m2.vm.numa.current_lt_count", numa_current < numa_count);
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
  return 0;
}

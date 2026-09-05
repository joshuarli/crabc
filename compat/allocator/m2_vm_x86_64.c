/* Native x86-64 M2 VM-primitives oracle.
 *
 * This intentionally includes the fixed v3.5.0 `src/os.c` into the probe so
 * that its private configuration and OS-allocation wrappers are observed
 * directly.  The Python producer omits that one ordinary source object from
 * the link list.  It records only address-independent, fixed-profile facts:
 * the regular reserved lifecycle; ordinary, aligned, and offset-aligned OS
 * owners; and normalized NUMA observation.  It does not exercise options,
 * hints, THP process policy, huge pages, placement, or diagnostics.
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include <mimalloc.h>
#include <mimalloc/internal.h>
#include <mimalloc/prim.h>

/* Resolved through `-I <pinned-source>/src`; keep the private source body
 * singular by omitting `src/os.c` from the ordinary C source list. */
#include "os.c"

/* The producer links with `--wrap=munmap`.  This controlled one-shot seam
 * reaches the unchanged pinned `_mi_prim_free` call inside `src/prim/unix/prim.c`;
 * it does not replace a source function or make the fault path a host model.
 * Keep it disabled through startup and every success record, then enable it
 * only around the source `_mi_os_free` call selected below. */
static bool fail_next_munmap = false;
static size_t wrapped_munmap_calls = 0;
static int last_real_munmap_result = -1;
/* The ordinary lifecycle above also frees mappings through this wrapper.
 * Capture only the selected failed full-MemoryId release and its retry, so
 * the address-free trace can prove both source calls used the retained base
 * and full length rather than merely observing two `munmap` attempts. */
static bool capture_release_munmap = false;
static size_t captured_release_munmap_calls = 0;
static void* captured_release_munmap_addresses[2];
static size_t captured_release_munmap_lengths[2];

int __real_munmap(void* address, size_t length);

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

#define U(name, value) printf(name "=%zu\n", (size_t)(value))

static int64_t current_reserved(const mi_subproc_t* subproc) {
  return mi_atomic_loadi64_relaxed((_Atomic(int64_t)*)(&subproc->stats.reserved.current));
}

static int64_t current_committed(const mi_subproc_t* subproc) {
  return mi_atomic_loadi64_relaxed((_Atomic(int64_t)*)(&subproc->stats.committed.current));
}

int main(void) {
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
  bool commit_is_zero = true;
  if (!_mi_os_commit(subproc, reserved, page, &commit_is_zero)) return 13;
  if (!_mi_os_decommit(subproc, reserved, page)) return 14;
  /* `Mapping::purge` deliberately owns the fixed `_mi_prim_reset` advisory
   * slice.  Do not substitute `_mi_os_purge`: its default option-driven
   * decommit/reset decision is an explicitly unqualified policy branch. */
  if (!_mi_os_reset(subproc, reserved, page)) return 15;
  _mi_os_reuse(subproc, reserved, page);
  if (!_mi_os_protect(reserved, page)) return 16;
  if (!_mi_os_unprotect(reserved, page)) return 17;
  _mi_os_free(subproc, reserved, page, reserved_id);

  mi_memid_t normal_id = _mi_memid_none();
  void* const normal = _mi_os_alloc(subproc, page + 1, &normal_id);
  const size_t normal_size = _mi_os_good_alloc_size(page + 1);
  if (normal == NULL || normal_id.mem.os.base != normal || normal_id.mem.os.size != normal_size
      || !normal_id.initially_committed || !normal_id.initially_zero) return 18;
  _mi_os_free(subproc, normal, page + 1, normal_id);

  mi_memid_t aligned_id = _mi_memid_none();
  void* const aligned = _mi_os_alloc_aligned(
      subproc, page, alignment, true /* commit */, false /* allow_large */, &aligned_id);
  const size_t aligned_size = _mi_os_good_alloc_size(page);
  if (aligned == NULL || ((uintptr_t)aligned % alignment) != 0
      || aligned_id.mem.os.base != aligned || aligned_id.mem.os.size != aligned_size) return 19;
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
      || offset_id.mem.os.size != offset_size) return 20;
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
      || failed_release_id.mem.os.size == 0) return 21;
  const size_t failed_release_prefix =
      (size_t)((uint8_t*)failed_release_client - (uint8_t*)failed_release_id.mem.os.base);
  if (failed_release_prefix >= failed_release_id.mem.os.size) return 22;
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
    return 23;
  }
  /* A successful range-wide protection change proves the full base/length
   * mapping remains live after the injected primitive error. */
  if (mprotect(failed_release_id.mem.os.base, failed_release_id.mem.os.size,
               PROT_READ | PROT_WRITE) != 0) return 24;
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
    return 25;
  }
  capture_release_munmap = false;

  const int numa_count = _mi_os_numa_node_count();
  const int numa_current = _mi_os_numa_node();
  if (numa_count < 1 || numa_current < 0 || numa_current >= numa_count) return 26;

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
  U("m2.vm.reserved.commit_not_known_zero", !commit_is_zero);
  U("m2.vm.reserved.decommit_no_recommit", 1);
  U("m2.vm.reserved.reset_success", 1);
  U("m2.vm.reserved.reuse_linux_noop", 1);
  U("m2.vm.reserved.protect_success", 1);
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
  puts("CRABC_MI_M2_VM_TRACE_END");
  return 0;
}

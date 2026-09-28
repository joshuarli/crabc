/* Pinned-source aligned OS page claim with one failed suffix trim. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "static.c"

#ifndef MAP_FIXED_NOREPLACE
#error "the aligned caller receiver requires MAP_FIXED_NOREPLACE"
#endif

int __real_munmap(void* address, size_t length);
void* __real_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset);

static struct {
  bool active;
  unsigned phase;
  void* direct;
  void* over;
  size_t maps;
  size_t frees;
  void* free_address[4];
  size_t free_length[4];
  bool fail_terminal;
} probe;

void* __wrap_mmap(void* address, size_t length, int protection, int flags,
                  int descriptor, off_t offset) {
  if (!probe.active) return __real_mmap(address, length, protection, flags, descriptor, offset);
  (void)address;
  void* const selected = probe.phase++ == 0 ? probe.direct : probe.over;
  probe.maps++;
  return __real_mmap(selected, length, protection, flags | MAP_FIXED_NOREPLACE,
                     descriptor, offset);
}

int __wrap_munmap(void* address, size_t length) {
  if (!probe.active) return __real_munmap(address, length);
  const size_t ordinal = probe.frees++;
  if (ordinal < 4) {
    probe.free_address[ordinal] = address;
    probe.free_length[ordinal] = length;
  }
  if (ordinal == 2 || (probe.fail_terminal && ordinal == 3)) {
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(address, length);
}

static struct {
  size_t fragments;
  size_t bodies;
  size_t fallback;
  size_t free_failure;
  bool ordered;
  bool body_exact;
  int64_t reserved_at_suffix;
  int64_t committed_at_suffix;
  int64_t reserved_at_terminal;
  int64_t committed_at_terminal;
  mi_subproc_t* subprocess;
} warnings;

static void capture_warning(const char* message, void* argument) {
  (void)argument;
  if (message == NULL) return;
  warnings.fragments++;
  if (strncmp(message, "unable to allocate aligned OS memory directly", 45) == 0) {
    warnings.ordered &= warnings.bodies == 0;
    warnings.fallback++;
    warnings.bodies++;
  } else if (strncmp(message, "unable to free OS memory", 24) == 0) {
    const size_t ordinal = warnings.free_failure == 0 ? 2 : 3;
    char expected[192];
    snprintf(expected, sizeof(expected),
        "unable to free OS memory (error: %d (0x%02X), size: 0x%zx bytes, address: 0x%lX)\n",
        ENOMEM, ENOMEM, probe.free_length[ordinal],
        (unsigned long)(uintptr_t)probe.free_address[ordinal]);
    warnings.body_exact &= strcmp(message, expected) == 0;
    if (warnings.free_failure == 0) {
      warnings.ordered &= warnings.bodies == 1;
      warnings.reserved_at_suffix = warnings.subprocess->stats.reserved.current;
      warnings.committed_at_suffix = warnings.subprocess->stats.committed.current;
    } else {
      warnings.ordered &= warnings.bodies == 2;
      warnings.reserved_at_terminal = warnings.subprocess->stats.reserved.current;
      warnings.committed_at_terminal = warnings.subprocess->stats.committed.current;
    }
    warnings.free_failure++;
    warnings.bodies++;
  }
}

static bool live(void* address, size_t page) {
  unsigned char byte = 0;
  return mincore(address, page, &byte) == 0;
}

int main(void) {
  mi_process_init();
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_option_set_enabled(mi_option_verbose, false);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(capture_warning, NULL);
  mi_subproc_t* const subprocess = _mi_subproc_main();
  mi_theap_t* const theap = subprocess->theap_meta;
  const size_t page = _mi_os_page_size();
  const size_t alignment = MI_PAGE_META_ALIGNMENT;
  const size_t length = MI_ARENA_SLICE_SIZE + 128 * MI_KiB;
  const size_t over_length = length + alignment;
  const size_t span = 6 * alignment + over_length + page;
  void* const reservation = __real_mmap(NULL, span, PROT_NONE,
      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (reservation == MAP_FAILED) return 10;
  const uintptr_t aligned = ((uintptr_t)reservation + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const uintptr_t direct = aligned + page;
  const uintptr_t over = aligned + 4 * alignment + page;
  if (over + over_length > (uintptr_t)reservation + span
      || __real_munmap(reservation, span) != 0) return 11;
  const uintptr_t middle = (over + alignment - 1) & ~(uintptr_t)(alignment - 1);
  const size_t prefix = middle - over;
  const size_t suffix = over_length - prefix - length;
  if (prefix == 0 || suffix == 0) return 12;

  const int64_t reserved_before = subprocess->stats.reserved.current;
  const int64_t committed_before = subprocess->stats.committed.current;
  const int64_t mmap_before = subprocess->stats.mmap_calls.total;
  memset(&warnings, 0, sizeof(warnings));
  warnings.ordered = true;
  warnings.body_exact = true;
  warnings.subprocess = subprocess;
  probe.active = true;
  probe.direct = (void*)direct;
  probe.over = (void*)over;
  mi_memid_t memory = _mi_memid_none();
  mi_arena_pages_t* arena_pages = NULL;
  uint8_t* const start = mi_arenas_page_alloc_fresh_area(theap, 1, 1,
      128 * MI_KiB, true, true, &memory, &arena_pages);
  if (start == NULL) return 13;
  const int64_t reserved_claim = subprocess->stats.reserved.current - reserved_before;
  const int64_t committed_claim = subprocess->stats.committed.current - committed_before;
  const int64_t mmap_claim = subprocess->stats.mmap_calls.total - mmap_before;
  const bool suffix_exact = probe.frees == 3 && probe.free_address[2] == (void*)(middle + length)
      && probe.free_length[2] == suffix && live((void*)(middle + length), page);
  const bool memory_exact = memory.memkind == MI_MEM_OS && memory.mem.os.base == (void*)middle
      && memory.mem.os.size == length && memory.initially_committed
      && start == (uint8_t*)middle + 128 * MI_KiB && arena_pages == NULL;
  probe.fail_terminal = true;
  _mi_arenas_free(subprocess, start, MI_ARENA_SLICE_SIZE, memory);
  probe.active = false;
  const int64_t reserved_final = subprocess->stats.reserved.current - reserved_before;
  const int64_t committed_final = subprocess->stats.committed.current - committed_before;
  const bool terminal_exact = probe.frees == 4 && probe.free_address[3] == (void*)middle
      && probe.free_length[3] == length && live((void*)middle, page);
  const bool warning_order = warnings.ordered && warnings.body_exact
      && warnings.bodies == 3 && warnings.fallback == 1 && warnings.free_failure == 2;
  const bool warning_before_stats = warnings.reserved_at_suffix
          == reserved_before + (int64_t)(length + suffix)
      && warnings.committed_at_suffix == committed_before
      && warnings.reserved_at_terminal == reserved_before + (int64_t)length
      && warnings.committed_at_terminal == committed_before + MI_ARENA_SLICE_SIZE;
  const bool raw_middle = __real_munmap((void*)middle, length) == 0;
  const bool raw_suffix = __real_munmap((void*)(middle + length), suffix) == 0;
  const bool raw_no_stats = reserved_final == subprocess->stats.reserved.current - reserved_before
      && committed_final == subprocess->stats.committed.current - committed_before;
  printf("legacy.claim.memory_exact=%u\n", memory_exact);
  printf("legacy.claim.suffix_exact=%u\n", suffix_exact);
  printf("legacy.claim.terminal_exact=%u\n", terminal_exact);
  printf("legacy.claim.middle_length=%zu\n", length);
  printf("legacy.claim.escaped_suffix_length=%zu\n", suffix);
  printf("legacy.claim.reserved_claim=%lld\n", (long long)reserved_claim);
  printf("legacy.claim.committed_claim=%lld\n", (long long)committed_claim);
  printf("legacy.claim.mmap_claim=%lld\n", (long long)mmap_claim);
  printf("legacy.claim.reserved_final=%lld\n", (long long)reserved_final);
  printf("legacy.claim.committed_final=%lld\n", (long long)committed_final);
  printf("legacy.claim.warning_fragments=%zu\n", warnings.fragments);
  printf("legacy.claim.warning_bodies=%zu\n", warnings.bodies);
  printf("legacy.claim.warning_order=%u\n", warning_order);
  printf("legacy.claim.warning_before_stats=%u\n", warning_before_stats);
  printf("legacy.claim.raw_middle=%u\n", raw_middle);
  printf("legacy.claim.raw_suffix=%u\n", raw_suffix);
  printf("legacy.claim.raw_no_stats=%u\n", raw_no_stats);
  return memory_exact && suffix_exact && terminal_exact && raw_middle && raw_suffix ? 0 : 14;
}

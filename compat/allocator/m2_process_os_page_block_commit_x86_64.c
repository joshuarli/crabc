/* A failed fresh OS page-area block commit retains its mapping when rollback unmap fails. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "static.c"

int __real_mprotect(void* address, size_t length, int protection);
int __real_munmap(void* address, size_t length);

static struct {
  bool active;
  unsigned commits;
  unsigned releases;
  void* base;
  void* block;
  size_t block_length;
  void* released;
  size_t released_length;
} probe;

int __wrap_mprotect(void* address, size_t length, int protection) {
  if (probe.active && protection == (PROT_READ | PROT_WRITE)) {
    probe.commits++;
    if (probe.commits == 1) probe.base = address;
    if (probe.commits == 2) {
      probe.block = address;
      probe.block_length = length;
      errno = ENOMEM;
      return -1;
    }
  }
  return __real_mprotect(address, length, protection);
}

int __wrap_munmap(void* address, size_t length) {
  if (probe.active && probe.commits == 2 && address == probe.base
      && length == 2 * MI_ARENA_SLICE_SIZE) {
    probe.releases++;
    probe.released = address;
    probe.released_length = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(address, length);
}

static struct {
  mi_subproc_t* subprocess;
  bool prefix;
  bool ordered;
  unsigned bodies;
  int64_t reserved_at_commit;
  int64_t reserved_at_free;
  int64_t committed_at_free;
} warnings;

static void capture_warning(const char* message, void* argument) {
  (void)argument;
  if (message == NULL) return;
  if (strncmp(message, "mimalloc: warning: thread 0x", 27) == 0) {
    warnings.prefix = true;
  }
  else if (strncmp(message, "cannot commit OS memory", 23) == 0) {
    warnings.ordered &= warnings.prefix && warnings.bodies == 0;
    warnings.prefix = false;
    warnings.bodies++;
    warnings.reserved_at_commit = warnings.subprocess->stats.reserved.current;
  }
  else if (strncmp(message, "unable to free OS memory", 24) == 0) {
    warnings.ordered &= warnings.prefix && warnings.bodies == 1;
    warnings.prefix = false;
    warnings.bodies++;
    warnings.reserved_at_free = warnings.subprocess->stats.reserved.current;
    warnings.committed_at_free = warnings.subprocess->stats.committed.current;
  }
}

static bool live(void* address, size_t page) {
  unsigned char byte = 0;
  return mincore(address, page, &byte) == 0;
}

int main(void) {
  mi_process_init();
  mi_option_set_enabled(mi_option_disallow_arena_alloc, true);
  mi_option_set_enabled(mi_option_allow_large_os_pages, false);
  mi_option_set_enabled(mi_option_show_errors, true);
  mi_option_set(mi_option_max_warnings, 100);
  mi_subproc_t* const subprocess = _mi_subproc_main();
  warnings.subprocess = subprocess;
  warnings.ordered = true;
  mi_register_output(capture_warning, NULL);

  const int64_t reserved_before = subprocess->stats.reserved.current;
  const int64_t committed_before = subprocess->stats.committed.current;
  const int64_t calls_before = subprocess->stats.commit_calls.total;
  mi_memid_t memory = _mi_memid_none();
  mi_arena_pages_t* arena_pages = NULL;
  probe.active = true;
  uint8_t* const start = mi_arenas_page_alloc_fresh_area(
      subprocess->theap_meta, 1, 1, 1, false, true, &memory, &arena_pages);
  probe.active = false;
  const size_t length = 2 * MI_ARENA_SLICE_SIZE;
  const int64_t reserved_final = subprocess->stats.reserved.current - reserved_before;
  const int64_t committed_final = subprocess->stats.committed.current - committed_before;
  const int64_t commit_calls = subprocess->stats.commit_calls.total - calls_before;
  const bool release_exact = start == NULL && arena_pages == NULL
      && memory.memkind == MI_MEM_OS && memory.mem.os.base == probe.base
      && memory.mem.os.size == length && probe.releases == 1
      && probe.released == probe.base && probe.released_length == length
      && probe.commits == 2 && probe.block == (uint8_t*)probe.base + MI_ARENA_SLICE_SIZE
      && probe.block_length == MI_ARENA_SLICE_SIZE;
  const bool retained = live(probe.base, _mi_os_page_size());
  const bool warning_order = warnings.ordered && warnings.bodies == 2;
  const bool warning_before_stats = warnings.reserved_at_commit
          == reserved_before + (int64_t)length
      && warnings.reserved_at_free == reserved_before + (int64_t)length
      && warnings.committed_at_free == committed_before;
  const bool raw_release = __real_munmap(probe.base, length) == 0;
  const bool raw_no_stats = subprocess->stats.reserved.current - reserved_before == reserved_final
      && subprocess->stats.committed.current - committed_before == committed_final;

  printf("block.rollback.mapping_length=%zu\n", length);
  printf("block.rollback.reserved_final=%lld\n", (long long)reserved_final);
  printf("block.rollback.committed_final=%lld\n", (long long)committed_final);
  printf("block.rollback.commit_calls=%lld\n", (long long)commit_calls);
  printf("block.rollback.warning_fragments=%u\n", warnings.bodies * 2);
  printf("block.rollback.release_exact=%u\n", release_exact);
  printf("block.rollback.retained=%u\n", retained);
  printf("block.rollback.warning_order=%u\n", warning_order);
  printf("block.rollback.warning_before_stats=%u\n", warning_before_stats);
  printf("block.rollback.raw_release=%u\n", raw_release);
  printf("block.rollback.raw_no_stats=%u\n", raw_no_stats);
  return release_exact && retained && warning_order && warning_before_stats
      && raw_release && raw_no_stats ? 0 : 14;
}

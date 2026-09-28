/* Pinned source commit failure and retry beside a live second-arena claim. */
#define _GNU_SOURCE 1
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct owner_s { mi_subproc_t subproc; mi_heap_t heap; } owner_t;
static owner_t owner;
static mi_arena_t* selected_arena;
static size_t failed_slice;
static size_t protect_calls;
static size_t protect_exact;
static bool fail_next_protect;
static size_t warning_calls;
static size_t warning_after_counter;
static int64_t commit_calls_before;
static int64_t committed_before;

int __real_mprotect(void* address, size_t length, int protection);
int __wrap_mprotect(void* address, size_t length, int protection) {
  if (selected_arena != NULL) {
    protect_calls++;
    protect_exact += address == mi_arena_slice_start(selected_arena, failed_slice)
        && length == MI_ARENA_SLICE_SIZE
        && protection == (PROT_READ | PROT_WRITE);
    if (fail_next_protect) {
      fail_next_protect = false;
      errno = EIO;
      return -1;
    }
  }
  return __real_mprotect(address, length, protection);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (strstr(message, "cannot commit OS memory") != NULL) {
    warning_calls++;
    warning_after_counter += owner.subproc.stats.commit_calls.total == commit_calls_before + 1
        && owner.subproc.stats.committed.current == committed_before
        && strstr(message, "error: 5 (0x05)") != NULL
        && strstr(message, "size: 0x10000 bytes") != NULL;
  }
}

static void emit(const char* field, long long value) {
  printf("m2.second_commit_retry.%s=%lld\n", field, value);
}

static bool live_page(void* base) {
  unsigned char residence = 0;
  return mincore(base, (size_t)sysconf(_SC_PAGESIZE), &residence) == 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  mi_process_init();
  os_preloading = false;
  memset(&owner, 0, sizeof(owner));
  mi_lock_init(&owner.subproc.arena_reserve_lock);
  mi_atomic_store_relaxed(&owner.subproc.heap_count, 1);
  owner.heap.subproc = &owner.subproc;
  mi_os_mem_config.has_overcommit = true;
  mi_os_mem_config.has_transparent_huge_pages = false;
  mi_option_set(mi_option_arena_reserve, MI_ARENA_MIN_SIZE / MI_KiB);
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_allow_thp, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_purge_delay, 100000);
  mi_option_set(mi_option_arena_purge_mult, 1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);

  mi_memid_t ids[4];
  void* claims[4];
  for (size_t i = 0; i < 4; i++) {
    ids[i] = _mi_memid_none();
    claims[i] = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                   false, true, NULL, 0, -1, &ids[i]);
    if (claims[i] == NULL || ids[i].memkind != MI_MEM_ARENA) return 2;
  }
  mi_arena_t* first = ids[0].mem.arena.arena;
  mi_arena_t* second = ids[3].mem.arena.arena;
  if (mi_arenas_get_count(&owner.subproc) != 2 || first == second) return 3;
  mi_memid_t survivor_id = _mi_memid_none();
  void* survivor = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                      false, true, second, 0, -1, &survivor_id);
  if (survivor == NULL || survivor_id.mem.arena.arena != second) return 4;
  const size_t survivor_slice = survivor_id.mem.arena.slice_index;
  failed_slice = survivor_slice + 1;
  const bool setup = survivor_slice == 265 && failed_slice == 266
      && mi_bbitmap_is_clearN(second->slices_free, survivor_slice, 1)
      && mi_bbitmap_is_setN(second->slices_free, failed_slice, 1)
      && mi_bitmap_is_clearN(second->slices_dirty, failed_slice, 1)
      && mi_bitmap_is_clearN(second->slices_committed, failed_slice, 1);
  const int64_t reserved_before = owner.subproc.stats.reserved.current;
  commit_calls_before = owner.subproc.stats.commit_calls.total;
  committed_before = owner.subproc.stats.committed.current;
  const int64_t purge_before = owner.subproc.stats.purge_calls.total;
  const int64_t arena_purges_before = owner.subproc.stats.arena_purges.total;
  selected_arena = second;
  fail_next_protect = true;
  mi_memid_t failed_id = _mi_memid_none();
  void* failed = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                    true, true, second, 0, -1, &failed_id);
  const bool failed_null = failed == NULL;
  const bool failed_free = mi_bbitmap_is_setN(second->slices_free, failed_slice, 1)
      && mi_bbitmap_is_clearN(second->slices_free, survivor_slice, 1);
  const bool failed_dirty = mi_bitmap_is_setN(second->slices_dirty, failed_slice, 1);
  const bool failed_uncommitted = mi_bitmap_is_clearN(second->slices_committed, failed_slice, 1)
      && mi_bitmap_is_clearN(second->slices_purge, failed_slice, 1);
  const size_t failed_protect_calls = protect_calls;
  const size_t failed_protect_exact = protect_exact;
  const size_t failed_warnings = warning_calls;
  const size_t failed_warning_order = warning_after_counter;
  const int64_t failed_commit_calls = owner.subproc.stats.commit_calls.total - commit_calls_before;
  const int64_t failed_committed_delta = owner.subproc.stats.committed.current - committed_before;

  mi_memid_t retry_id = _mi_memid_none();
  void* retry = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                   true, true, second, 0, -1, &retry_id);
  if (retry == NULL) return 5;
  const bool retry_same = retry == mi_arena_slice_start(second, failed_slice)
      && retry_id.mem.arena.arena == second
      && retry_id.mem.arena.slice_index == failed_slice;
  const bool retry_committed = mi_bitmap_is_setN(second->slices_committed, failed_slice, 1)
      && retry_id.initially_committed;
  const bool retry_dirty = mi_bitmap_is_setN(second->slices_dirty, failed_slice, 1);
  const bool retry_zero_flag = !retry_id.initially_zero;
  const bool maps_live = live_page(first->start) && live_page(second->start)
      && owner.subproc.stats.reserved.current == reserved_before
      && mi_arenas_get_count(&owner.subproc) == 2
      && mi_bbitmap_is_clearN(second->slices_free, survivor_slice, 1)
      && mi_bbitmap_is_clearN(second->slices_free, failed_slice, 1);
  emit("setup", setup); emit("failed_null", failed_null);
  emit("failed_free", failed_free); emit("failed_dirty", failed_dirty);
  emit("failed_uncommitted", failed_uncommitted);
  emit("failed_protect_calls", failed_protect_calls);
  emit("failed_protect_exact", failed_protect_exact);
  emit("failed_warnings", failed_warnings);
  emit("failed_warning_order", failed_warning_order);
  emit("failed_commit_calls", failed_commit_calls);
  emit("failed_committed_delta", failed_committed_delta);
  emit("retry_same", retry_same); emit("retry_committed", retry_committed);
  emit("retry_dirty", retry_dirty); emit("retry_zero_flag", retry_zero_flag);
  emit("protect_calls", protect_calls); emit("protect_exact", protect_exact);
  emit("warning_calls", warning_calls);
  emit("commit_calls", owner.subproc.stats.commit_calls.total - commit_calls_before);
  emit("committed_delta", owner.subproc.stats.committed.current - committed_before);
  emit("purge_calls", owner.subproc.stats.purge_calls.total - purge_before);
  emit("arena_purges", owner.subproc.stats.arena_purges.total - arena_purges_before);
  emit("reserved_delta", owner.subproc.stats.reserved.current - reserved_before);
  emit("maps_live", maps_live);
  emit("failed_slice", failed_slice); emit("survivor_slice", survivor_slice);
  return setup && failed_null && failed_free && failed_dirty && failed_uncommitted
      && failed_protect_calls == 1 && failed_protect_exact == 1
      && failed_warnings == 1 && failed_warning_order == 1
      && retry_same && retry_committed && retry_dirty && retry_zero_flag
      && protect_calls == 2 && protect_exact == 2 && warning_calls == 1
      && maps_live ? 0 : 1;
}

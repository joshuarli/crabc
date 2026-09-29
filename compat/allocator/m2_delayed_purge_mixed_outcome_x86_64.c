/* Two disjoint delayed purge ranges keep independent advisory outcomes. */
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
typedef struct advice_s { void* address; size_t length; int kind; } advice_t;
static owner_t owner;
static advice_t advice_seen[3];
static size_t advice_count;
static bool fail_first;
static size_t captured_warnings;
static size_t warning_order;
static size_t warning_stats;
static int64_t before_calls;
static int64_t before_bytes;
static int64_t before_visits;
static int64_t before_committed;

int __real_madvise(void* address, size_t length, int advice);
int __wrap_madvise(void* address, size_t length, int advice) {
  if (fail_first || advice_count != 0) {
    if (advice_count < 3) advice_seen[advice_count] = (advice_t){ address, length, advice };
    advice_count++;
    if (fail_first) {
      fail_first = false;
      errno = EIO;
      return -1;
    }
  }
  return __real_madvise(address, length, advice);
}

static void warning(const char* message, void* argument) {
  MI_UNUSED(argument);
  if (strstr(message, "cannot decommit OS memory") != NULL) {
    captured_warnings++;
    warning_order += advice_count == 1;
    warning_stats += owner.subproc.stats.purge_calls.total == before_calls + 1
        && owner.subproc.stats.purged.total == before_bytes + MI_ARENA_SLICE_SIZE
        && owner.subproc.stats.arena_purges.total == before_visits + 1
        && owner.subproc.stats.committed.current == before_committed
        && strstr(message, "error: 5 (0x05)") != NULL
        && strstr(message, "size: 0x10000 bytes") != NULL;
  }
}

static void emit(const char* name, long long value) {
  printf("m2.delayed_purge_mixed.%s=%lld\n", name, value);
}
static bool live(void* address) {
  unsigned char residency = 0;
  return mincore(address, (size_t)sysconf(_SC_PAGESIZE), &residency) == 0;
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
  mi_option_set(mi_option_purge_decommits, 1);
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);

  mi_memid_t ids[3];
  void* claims[3];
  for (size_t i = 0; i < 3; i++) {
    ids[i] = _mi_memid_none();
    claims[i] = mi_arenas_try_alloc(&owner.heap, 1, MI_ARENA_SLICE_ALIGN,
                                   true, true, i == 0 ? NULL : ids[0].mem.arena.arena,
                                   0, -1, &ids[i]);
    if (claims[i] == NULL || ids[i].memkind != MI_MEM_ARENA) return 2;
  }
  mi_arena_t* arena = ids[0].mem.arena.arena;
  const size_t a = ids[0].mem.arena.slice_index;
  const size_t neighbor = ids[1].mem.arena.slice_index;
  const size_t b = ids[2].mem.arena.slice_index;
  const bool setup = mi_arenas_get_count(&owner.subproc) == 1
      && ids[1].mem.arena.arena == arena && ids[2].mem.arena.arena == arena
      && arena->memid.memkind == MI_MEM_OS && a == 9 && neighbor == 10 && b == 11
      && live(arena->start) && live(claims[0]) && live(claims[1]) && live(claims[2]);
  *(volatile unsigned char*)claims[1] = 0x7b;
  const int64_t before_reserved = owner.subproc.stats.reserved.current;
  before_committed = owner.subproc.stats.committed.current;
  before_calls = owner.subproc.stats.purge_calls.total;
  before_bytes = owner.subproc.stats.purged.total;
  before_visits = owner.subproc.stats.arena_purges.total;
  _mi_arenas_free(&owner.subproc, claims[0], MI_ARENA_SLICE_SIZE, ids[0]);
  _mi_arenas_free(&owner.subproc, claims[2], MI_ARENA_SLICE_SIZE, ids[2]);
  const bool pending = mi_bitmap_is_setN(arena->slices_purge, a, 1)
      && mi_bitmap_is_setN(arena->slices_purge, b, 1)
      && mi_bitmap_is_clearN(arena->slices_purge, neighbor, 1)
      && mi_bitmap_is_setN(arena->slices_committed, a, 1)
      && mi_bitmap_is_setN(arena->slices_committed, b, 1)
      && mi_bbitmap_is_setN(arena->slices_free, a, 1)
      && mi_bbitmap_is_setN(arena->slices_free, b, 1)
      && mi_bbitmap_is_clearN(arena->slices_free, neighbor, 1)
      && mi_atomic_loadi64_relaxed(&arena->purge_expire) > 0;
  const bool pending_quiet = advice_count == 0 && captured_warnings == 0
      && owner.subproc.stats.purge_calls.total == before_calls;
  fail_first = true;
  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  const bool ordered = advice_count == 2
      && advice_seen[0].address == claims[0] && advice_seen[1].address == claims[2]
      && advice_seen[0].length == MI_ARENA_SLICE_SIZE
      && advice_seen[1].length == MI_ARENA_SLICE_SIZE
      && advice_seen[0].kind == MADV_DONTNEED
      && advice_seen[1].kind == MADV_DONTNEED;
  const bool bitmaps = mi_bitmap_is_clearN(arena->slices_purge, a, 1)
      && mi_bitmap_is_clearN(arena->slices_purge, b, 1)
      && mi_bitmap_is_setN(arena->slices_committed, a, 1)
      && mi_bitmap_is_setN(arena->slices_committed, b, 1)
      && mi_bbitmap_is_setN(arena->slices_free, a, 1)
      && mi_bbitmap_is_setN(arena->slices_free, b, 1)
      && mi_bbitmap_is_clearN(arena->slices_free, neighbor, 1)
      && mi_atomic_loadi64_relaxed(&arena->purge_expire) == 0;
  const long long collected_calls = owner.subproc.stats.purge_calls.total - before_calls;
  const long long collected_bytes = owner.subproc.stats.purged.total - before_bytes;
  const long long collected_visits = owner.subproc.stats.arena_purges.total - before_visits;
  const long long committed_delta = owner.subproc.stats.committed.current - before_committed;
  mi_arenas_try_purge(true, true, &owner.subproc, 0);
  const bool no_retry = advice_count == 2 && captured_warnings == 1
      && owner.subproc.stats.purge_calls.total - before_calls == collected_calls
      && owner.subproc.stats.arena_purges.total - before_visits == collected_visits;
  const bool survivor = live(arena->start) && live(claims[1])
      && *(volatile unsigned char*)claims[1] == 0x7b
      && mi_bbitmap_is_clearN(arena->slices_free, neighbor, 1)
      && mi_arenas_get_count(&owner.subproc) == 1;
  _mi_arenas_free(&owner.subproc, claims[1], MI_ARENA_SLICE_SIZE, ids[1]);
  const bool terminal = live(arena->start) && mi_arenas_get_count(&owner.subproc) == 1
      && mi_bbitmap_is_setN(arena->slices_free, neighbor, 1)
      && owner.subproc.stats.reserved.current == before_reserved;
  emit("setup", setup); emit("pending", pending); emit("pending_quiet", pending_quiet);
  emit("ordered", ordered); emit("bitmaps", bitmaps);
  emit("advice_count", advice_count); emit("warning_count", captured_warnings);
  emit("warning_order", warning_order); emit("warning_stats", warning_stats);
  emit("collected_calls", collected_calls); emit("collected_bytes", collected_bytes);
  emit("collected_visits", collected_visits); emit("committed_delta", committed_delta);
  emit("no_retry", no_retry); emit("survivor", survivor); emit("terminal", terminal);
  emit("a_slice", a); emit("neighbor_slice", neighbor); emit("b_slice", b);
  emit("registry", mi_arenas_get_count(&owner.subproc));
  emit("reserved_delta", owner.subproc.stats.reserved.current - before_reserved);
  emit("purge_calls", owner.subproc.stats.purge_calls.total - before_calls);
  emit("purged_bytes", owner.subproc.stats.purged.total - before_bytes);
  emit("arena_purges", owner.subproc.stats.arena_purges.total - before_visits);
  return setup && pending && pending_quiet && ordered && bitmaps
      && no_retry && survivor && terminal ? 0 : 1;
}

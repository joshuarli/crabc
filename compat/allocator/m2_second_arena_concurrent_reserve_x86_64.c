/* Pinned source worker claims after a regular arena has no fitting span. */
#define _GNU_SOURCE 1
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "static.c"

typedef struct owner_s { mi_subproc_t subproc; mi_heap_t heap; } owner_t;
typedef struct worker_s {
  pthread_barrier_t* start;
  pthread_barrier_t* claimed;
  pthread_barrier_t* release;
  void* claim;
  mi_memid_t id;
  bool released;
} worker_t;

static owner_t owner;
static _Atomic bool capture_warnings;
static _Atomic size_t warning_calls;

static void warning(const char* message, void* argument) {
  MI_UNUSED(message);
  MI_UNUSED(argument);
  if (atomic_load_explicit(&capture_warnings, memory_order_acquire)) {
    atomic_fetch_add_explicit(&warning_calls, 1, memory_order_acq_rel);
  }
}

static void* claim_worker(void* argument) {
  worker_t* worker = (worker_t*)argument;
  worker->id = _mi_memid_none();
  pthread_barrier_wait(worker->start);
  worker->claim = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                      false, true, NULL, 0, -1, &worker->id);
  pthread_barrier_wait(worker->claimed);
  pthread_barrier_wait(worker->release);
  if (worker->claim != NULL) {
    _mi_arenas_free(&owner.subproc, worker->claim,
                    256 * MI_ARENA_SLICE_SIZE, worker->id);
    worker->released = true;
  }
  return NULL;
}

static void emit(const char* field, long long value) {
  printf("m2.second_concurrent.%s=%lld\n", field, value);
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
  mi_option_set(mi_option_show_errors, 1);
  mi_option_set(mi_option_max_warnings, 100);
  mi_register_output(warning, NULL);

  mi_memid_t initial_ids[3];
  void* initial_claims[3];
  for (size_t i = 0; i < 3; i++) {
    initial_ids[i] = _mi_memid_none();
    initial_claims[i] = mi_arenas_try_alloc(&owner.heap, 256, MI_ARENA_SLICE_ALIGN,
                                            false, true, NULL, 0, -1, &initial_ids[i]);
    if (initial_claims[i] == NULL || initial_ids[i].memkind != MI_MEM_ARENA) return 2;
  }
  mi_arena_t* first = mi_arena_from_index(&owner.subproc, 0);
  size_t first_free_slices = 0;
  for (size_t index = 0; index < first->slice_count; index++) {
    first_free_slices += mi_bbitmap_is_setN(first->slices_free, index, 1);
  }
  const bool first_full = mi_arenas_get_count(&owner.subproc) == 1
      && first_free_slices < 256
      && initial_ids[0].mem.arena.arena == first
      && initial_ids[1].mem.arena.arena == first
      && initial_ids[2].mem.arena.arena == first;
  const int64_t reserved_before = owner.subproc.stats.reserved.current;
  const int64_t committed_before = owner.subproc.stats.committed.current;
  const int64_t mmap_before = owner.subproc.stats.mmap_calls.total;
  const int64_t commit_before = owner.subproc.stats.commit_calls.total;
  const int64_t purge_before = owner.subproc.stats.purge_calls.total;
  const int64_t arena_before = owner.subproc.stats.arena_count.total;

  pthread_barrier_t start, claimed, release;
  pthread_barrier_init(&start, NULL, 3);
  pthread_barrier_init(&claimed, NULL, 3);
  pthread_barrier_init(&release, NULL, 3);
  worker_t workers[2] = {
    {.start = &start, .claimed = &claimed, .release = &release},
    {.start = &start, .claimed = &claimed, .release = &release},
  };
  pthread_t threads[2];
  atomic_store_explicit(&capture_warnings, true, memory_order_release);
  for (size_t i = 0; i < 2; i++) {
    if (pthread_create(&threads[i], NULL, claim_worker, &workers[i]) != 0) return 3;
  }
  pthread_barrier_wait(&start);
  pthread_barrier_wait(&claimed);
  atomic_store_explicit(&capture_warnings, false, memory_order_release);

  const size_t registry_claimed = mi_arenas_get_count(&owner.subproc);
  mi_arena_t* second = registry_claimed == 2 ? mi_arena_from_index(&owner.subproc, 1) : NULL;
  const bool registry_order = mi_arena_from_index(&owner.subproc, 0) == first
      && second != NULL && second != first;
  const bool both_claimed = workers[0].claim != NULL && workers[1].claim != NULL
      && workers[0].id.memkind == MI_MEM_ARENA
      && workers[1].id.memkind == MI_MEM_ARENA;
  const bool both_second = both_claimed && second != NULL
      && workers[0].id.mem.arena.arena == second
      && workers[1].id.mem.arena.arena == second;
  const size_t slice0 = both_claimed ? workers[0].id.mem.arena.slice_index : 0;
  const size_t slice1 = both_claimed ? workers[1].id.mem.arena.slice_index : 0;
  const size_t low_slice = slice0 < slice1 ? slice0 : slice1;
  const size_t high_slice = slice0 < slice1 ? slice1 : slice0;
  const bool distinct_claims = both_second && low_slice == 9 && high_slice == 512
      && workers[0].claim != workers[1].claim
      && mi_bbitmap_is_clearN(second->slices_free, slice0, 256)
      && mi_bbitmap_is_clearN(second->slices_free, slice1, 256);
  const bool first_claims_live = mi_bbitmap_is_clearN(first->slices_free,
      initial_ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, initial_ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_clearN(first->slices_free, initial_ids[2].mem.arena.slice_index, 256);
  const bool mapped_both = second != NULL && live_page(first->start) && live_page(second->start);
  void* const first_base = first->start;
  void* const second_base = second == NULL ? NULL : second->start;
  const int64_t reserved_delta = owner.subproc.stats.reserved.current - reserved_before;
  const int64_t committed_delta = owner.subproc.stats.committed.current - committed_before;
  const int64_t mmap_calls = owner.subproc.stats.mmap_calls.total - mmap_before;
  const int64_t commit_calls = owner.subproc.stats.commit_calls.total - commit_before;
  const int64_t purge_calls = owner.subproc.stats.purge_calls.total - purge_before;
  const int64_t arena_delta = owner.subproc.stats.arena_count.total - arena_before;

  pthread_barrier_wait(&release);
  for (size_t i = 0; i < 2; i++) pthread_join(threads[i], NULL);
  const bool worker_released = workers[0].released && workers[1].released && second != NULL
      && mi_bbitmap_is_setN(second->slices_free, slice0, 256)
      && mi_bbitmap_is_setN(second->slices_free, slice1, 256);
  for (size_t i = 0; i < 3; i++) {
    _mi_arenas_free(&owner.subproc, initial_claims[i],
                    256 * MI_ARENA_SLICE_SIZE, initial_ids[i]);
  }
  const bool initial_released = mi_bbitmap_is_setN(first->slices_free,
      initial_ids[0].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(first->slices_free, initial_ids[1].mem.arena.slice_index, 256)
      && mi_bbitmap_is_setN(first->slices_free, initial_ids[2].mem.arena.slice_index, 256);
  const bool retained_both = second != NULL && live_page(first_base) && live_page(second_base)
      && mi_arenas_get_count(&owner.subproc) == 2;
  _mi_arenas_unsafe_destroy_all(&owner.subproc);
  const bool terminal_unmapped = !live_page(first_base)
      && second_base != NULL && !live_page(second_base);
  const size_t terminal_registry = mi_arenas_get_count(&owner.subproc);
  const int64_t terminal_reserved_delta = owner.subproc.stats.reserved.current - reserved_before;
  const int64_t terminal_committed_delta = owner.subproc.stats.committed.current - committed_before;

  emit("first_full", first_full); emit("registry_claimed", registry_claimed);
  emit("registry_order", registry_order); emit("both_claimed", both_claimed);
  emit("both_second", both_second); emit("distinct_claims", distinct_claims);
  emit("low_slice", low_slice); emit("high_slice", high_slice);
  emit("first_claims_live", first_claims_live); emit("mapped_both", mapped_both);
  emit("warnings", atomic_load_explicit(&warning_calls, memory_order_acquire));
  emit("reserved_delta", reserved_delta); emit("committed_delta", committed_delta);
  emit("mmap_calls", mmap_calls); emit("commit_calls", commit_calls);
  emit("purge_calls", purge_calls); emit("arena_delta", arena_delta);
  emit("worker_released", worker_released); emit("initial_released", initial_released);
  emit("retained_both", retained_both); emit("terminal_unmapped", terminal_unmapped);
  emit("terminal_registry", terminal_registry);
  emit("terminal_reserved_delta", terminal_reserved_delta);
  emit("terminal_committed_delta", terminal_committed_delta);
  return 0;
}

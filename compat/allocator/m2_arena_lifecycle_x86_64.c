/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/*
  Pinned v3.5.0 arena reservation, registry search, slice claim, and release
  lifecycle. Every scenario drives the unchanged static source routines from
  `src/arena.c` (`mi_arenas_try_alloc`, `mi_arena_reserve`,
  `mi_reserve_os_memory_ex2`, `mi_manage_os_memory_ex2`,
  `mi_arena_initialize`, `mi_arenas_add`, `mi_arena_try_alloc_at`, and
  `_mi_arenas_free`) against its own zeroed subprocess registry, so the first
  scenario's arenas never satisfy a later search.

  `mmap` is wrapped only to fail regular requests at or above a selected byte
  threshold. That reproduces a clean source-primitive failure of both the
  direct and the over-allocated aligned attempt of a large primary reservation
  while the smaller source fallback still maps. The fixed configuration
  records overcommit explicitly and disables transparent huge pages so the
  Rust receiver can use the same `mi_os_mem_config` facts independent of the
  host. Emitted fields are address-free source relations: counts, slice
  indices and geometry, memory-ID flags, and exact `current` statistics deltas.
  Kernel alignment luck may change `mmap_calls`, so that counter is excluded.
*/
#include "static.c"
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

static size_t field;
static void emit(int64_t value) {
  printf("m2.arena.lifecycle.%zu=%lld\n", field++, (long long)value);
}

static void require_at(bool condition, int line) {
  if (!condition) {
    fflush(stdout);
    fprintf(stderr, "m2_arena_lifecycle_x86_64.c:%d: requirement failed\n", line);
    abort();
  }
}
#define require(condition) require_at((condition), __LINE__)

/* ------------------------------------------------------------------------ */
/* Deterministic regular-mapping failure seam.                               */

void* __real_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset);
static size_t fail_mmap_at_or_above;  // 0 disables the seam
static size_t failed_mmap_calls;

void* __wrap_mmap(void* addr, size_t length, int prot, int flags, int fd, off_t offset) {
  if (fail_mmap_at_or_above != 0 && length >= fail_mmap_at_or_above) {
    failed_mmap_calls++;
    errno = ENOMEM;
    return MAP_FAILED;
  }
  return __real_mmap(addr, length, prot, flags, fd, offset);
}

/* Deterministic commit failure: the Nth `mprotect` after arming fails, which
   is exactly one source `_mi_prim_commit` on Linux. */
int __real_mprotect(void* addr, size_t length, int prot);
static size_t fail_mprotect_ordinal;  // 0 disables the seam
static size_t mprotect_calls;

static bool mprotect_failed;

int __wrap_mprotect(void* addr, size_t length, int prot) {
  if (fail_mprotect_ordinal != 0 && ++mprotect_calls == fail_mprotect_ordinal) {
    mprotect_failed = true;
    errno = ENOMEM;
    return -1;
  }
  return __real_mprotect(addr, length, prot);
}

/* Unmap failure seam. Aligned OS allocation may trim with a varying number of
   `munmap` calls, so a cleanup failure is armed only after the selected
   commit failure; a release failure is armed directly around one release.
   The failed range stays mapped and is recorded for the fixture to return. */
int __real_munmap(void* addr, size_t length);
static bool fail_munmap_after_mprotect;
static bool fail_next_munmap;
static size_t munmap_calls;
static void* retained_addr;
static size_t retained_length;

int __wrap_munmap(void* addr, size_t length) {
  munmap_calls++;
  if (fail_next_munmap || (fail_munmap_after_mprotect && mprotect_failed)) {
    fail_next_munmap = false;
    fail_munmap_after_mprotect = false;
    retained_addr = addr;
    retained_length = length;
    errno = ENOMEM;
    return -1;
  }
  return __real_munmap(addr, length);
}

/* Every `madvise` (decommit and reset both reach it) is recorded with its
   advice; the Nth call after arming fails with the selected errno instead of
   reaching the kernel, so the source warning/retry/fallback branches run. */
int __real_madvise(void* addr, size_t length, int advice);
static size_t madvise_calls;
static int madvise_advices[4];
static size_t fail_madvise_ordinal;  // 0 disables the seam
static int fail_madvise_errno;

int __wrap_madvise(void* addr, size_t length, int advice) {
  if (madvise_calls < 4) madvise_advices[madvise_calls] = advice;
  if (++madvise_calls == fail_madvise_ordinal) {
    errno = fail_madvise_errno;
    return -1;
  }
  return __real_madvise(addr, length, advice);
}

static void arm_madvise(size_t ordinal, int error) {
  madvise_calls = 0;
  for (size_t i = 0; i < 4; i++) madvise_advices[i] = -1;
  fail_madvise_ordinal = ordinal;
  fail_madvise_errno = error;
}

/* The recorded call count and up to four advice values, padded with -1. */
static void emit_madvise_record(void) {
  emit((int64_t)madvise_calls);
  for (size_t i = 0; i < 4; i++) emit(i < madvise_calls ? madvise_advices[i] : -1);
  fail_madvise_ordinal = 0;
}

/* ------------------------------------------------------------------------ */
/* Isolated source subprocess registries.                                    */

typedef struct lifecycle_owner_s {
  mi_subproc_t subproc;
  mi_heap_t heap;
} lifecycle_owner_t;

static lifecycle_owner_t owners[32];
static size_t owner_count;

static lifecycle_owner_t* fresh_owner(void) {
  require(owner_count < sizeof(owners) / sizeof(owners[0]));
  lifecycle_owner_t* const owner = &owners[owner_count++];
  memset(owner, 0, sizeof(*owner));
  mi_lock_init(&owner->subproc.arena_reserve_lock);
  mi_atomic_store_relaxed(&owner->subproc.heap_count, 1);
  owner->heap.subproc = &owner->subproc;
  return owner;
}

static void configure(bool overcommit, long reserve_kib, long eager_commit, bool disallow_os_alloc) {
  mi_os_mem_config.has_overcommit = overcommit;
  mi_os_mem_config.has_transparent_huge_pages = false;
  mi_option_set(mi_option_arena_reserve, reserve_kib);
  mi_option_set(mi_option_arena_eager_commit, eager_commit);
  mi_option_set(mi_option_disallow_os_alloc, disallow_os_alloc ? 1 : 0);
  mi_option_set(mi_option_disallow_arena_alloc, 0);
  mi_option_set(mi_option_arena_is_numa_local, 0);
  mi_option_set(mi_option_allow_large_os_pages, 0);
  mi_option_set(mi_option_purge_delay, -1);
}

typedef struct lifecycle_stats_s {
  int64_t reserved;
  int64_t committed;
  int64_t commit_calls;
  int64_t arena_count;
} lifecycle_stats_t;

static lifecycle_stats_t stats_of(lifecycle_owner_t* owner) {
  lifecycle_stats_t stats = {
    owner->subproc.stats.reserved.current,
    owner->subproc.stats.committed.current,
    owner->subproc.stats.commit_calls.total,
    owner->subproc.stats.arena_count.total,
  };
  return stats;
}

typedef struct purge_counters_s {
  int64_t purge_calls;
  int64_t purged;
  int64_t reset_calls;
  int64_t reset;
  int64_t arena_purges;
} purge_counters_t;

static purge_counters_t purge_counters_of(lifecycle_owner_t* owner) {
  purge_counters_t counters = {
    owner->subproc.stats.purge_calls.total,
    owner->subproc.stats.purged.total,
    owner->subproc.stats.reset_calls.total,
    owner->subproc.stats.reset.total,
    owner->subproc.stats.arena_purges.total,
  };
  return counters;
}

static void emit_purge_counters_delta(lifecycle_owner_t* owner, purge_counters_t before) {
  const purge_counters_t after = purge_counters_of(owner);
  emit(after.purge_calls - before.purge_calls);
  emit(after.purged - before.purged);
  emit(after.reset_calls - before.reset_calls);
  emit(after.reset - before.reset);
  emit(after.arena_purges - before.arena_purges);
}

static void emit_stats_delta(lifecycle_owner_t* owner, lifecycle_stats_t before) {
  const lifecycle_stats_t after = stats_of(owner);
  emit(after.reserved - before.reserved);
  emit(after.committed - before.committed);
  emit(after.commit_calls - before.commit_calls);
  emit(after.arena_count - before.arena_count);
}

static size_t free_slice_count(mi_arena_t* arena) {
  size_t count = 0;
  for (size_t index = 0; index < arena->slice_count; index++) {
    if (mi_bbitmap_is_setN(arena->slices_free, index, 1)) count++;
  }
  return count;
}

/* Every arena published since `first`: geometry, provenance, and identity. */
static void emit_arenas_from(lifecycle_owner_t* owner, size_t first) {
  const size_t count = mi_arenas_get_count(&owner->subproc);
  for (size_t index = first; index < count; index++) {
    mi_arena_t* const arena = mi_arena_from_index(&owner->subproc, index);
    require(arena != NULL);
    emit((int64_t)index);
    emit((int64_t)arena->arena_idx);
    emit((int64_t)arena->slice_count);
    emit((int64_t)arena->info_slices);
    emit((int64_t)(arena->total_size / MI_ARENA_SLICE_SIZE));
    emit(arena->parent == NULL);
    emit(arena->memid.memkind == MI_MEM_OS);
    emit(arena->memid.initially_committed);
    emit(arena->memid.initially_zero);
    emit(arena->memid.is_pinned);
    emit(arena->is_exclusive);
    emit(arena->numa_node);
    emit(_mi_is_aligned(arena->start, MI_ARENA_ALIGNMENT));
    emit((int64_t)free_slice_count(arena));
    emit((int64_t)mi_bitmap_popcount(arena->slices_committed));
    emit((int64_t)mi_bitmap_popcount(arena->slices_dirty));
  }
}

typedef struct lifecycle_claim_s {
  void* start;
  mi_memid_t memid;
  size_t slices;
} lifecycle_claim_t;

/* Source `mi_arenas_try_alloc` plus one complete claim/registry record. */
static lifecycle_claim_t claim(lifecycle_owner_t* owner, size_t slices, bool commit, mi_arena_t* requested, int numa_node) {
  const lifecycle_stats_t before = stats_of(owner);
  const size_t arenas_before = mi_arenas_get_count(&owner->subproc);
  lifecycle_claim_t result = { NULL, _mi_memid_none(), slices };
  result.start = mi_arenas_try_alloc(&owner->heap, slices, MI_ARENA_SLICE_ALIGN, commit,
                                     true /* allow_large */, requested, 0 /* tseq */,
                                     numa_node, &result.memid);
  emit(result.start != NULL);
  emit((int64_t)mi_arenas_get_count(&owner->subproc));
  if (result.start != NULL) {
    mi_arena_t* const arena = result.memid.mem.arena.arena;
    require(result.memid.memkind == MI_MEM_ARENA);
    require(result.start == mi_arena_slice_start(arena, result.memid.mem.arena.slice_index));
    emit((int64_t)arena->arena_idx);
    emit((int64_t)result.memid.mem.arena.slice_index);
    emit((int64_t)result.memid.mem.arena.slice_count);
    emit(result.memid.initially_committed);
    emit(result.memid.initially_zero);
    emit(result.memid.is_pinned);
    emit(mi_bitmap_is_setN(arena->slices_committed, result.memid.mem.arena.slice_index, slices));
  }
  else {
    for (int i = 0; i < 7; i++) emit(-1);
  }
  emit_stats_delta(owner, before);
  emit_arenas_from(owner, arenas_before);
  return result;
}

/* Source `_mi_arenas_alloc_aligned` in a requested arena: the result, the
   source errno on refusal, and the same claim/registry record as `claim`. */
static lifecycle_claim_t object(lifecycle_owner_t* owner, size_t size, size_t alignment, size_t align_offset,
                                mi_arena_t* requested, int numa_node) {
  const lifecycle_stats_t before = stats_of(owner);
  const size_t arenas_before = mi_arenas_get_count(&owner->subproc);
  lifecycle_claim_t result = { NULL, _mi_memid_none(), 0 };
  errno = 0;
  result.start = _mi_arenas_alloc_aligned(&owner->heap, size, alignment, align_offset, true /* commit */,
                                          true /* allow_large */, requested, 0 /* tseq */, numa_node,
                                          &result.memid);
  emit(result.start != NULL);
  emit(result.start != NULL ? 0 : errno);
  emit((int64_t)mi_arenas_get_count(&owner->subproc));
  if (result.start != NULL) {
    mi_arena_t* const arena = result.memid.mem.arena.arena;
    require(result.memid.memkind == MI_MEM_ARENA);
    require(result.start == mi_arena_slice_start(arena, result.memid.mem.arena.slice_index));
    result.slices = result.memid.mem.arena.slice_count;
    emit((int64_t)arena->arena_idx);
    emit((int64_t)result.memid.mem.arena.slice_index);
    emit((int64_t)result.memid.mem.arena.slice_count);
    emit(result.memid.initially_committed);
    emit(result.memid.initially_zero);
    emit(mi_bitmap_is_setN(arena->slices_committed, result.memid.mem.arena.slice_index, result.slices));
  }
  else {
    for (int i = 0; i < 6; i++) emit(-1);
  }
  emit_stats_delta(owner, before);
  emit_arenas_from(owner, arenas_before);
  return result;
}

/* Source `_mi_theap_alloc` for `heap->exclusive_arena` with a caller TLD's
   thread sequence and NUMA node: the result, the same claim record as
   `object` (minus errno, which the caller only reports), and the registry. */
static lifecycle_claim_t theap_alloc(lifecycle_owner_t* owner, mi_arena_t* exclusive, int numa_node) {
  const lifecycle_stats_t before = stats_of(owner);
  const size_t arenas_before = mi_arenas_get_count(&owner->subproc);
  mi_tld_t tld;
  memset(&tld, 0, sizeof(tld));
  tld.subproc = &owner->subproc;
  tld.thread_seq = 0;
  tld.numa_node = numa_node;
  owner->heap.exclusive_arena = exclusive;
  mi_theap_t* const theap = _mi_theap_alloc(&owner->heap, &tld);
  owner->heap.exclusive_arena = NULL;
  lifecycle_claim_t result = { theap, theap != NULL ? theap->memid : _mi_memid_none(), 0 };
  emit(theap != NULL);
  emit((int64_t)mi_arenas_get_count(&owner->subproc));
  if (theap != NULL) {
    mi_arena_t* const arena = result.memid.mem.arena.arena;
    require(result.memid.memkind == MI_MEM_ARENA && arena == exclusive);
    require(result.start == mi_arena_slice_start(arena, result.memid.mem.arena.slice_index));
    result.slices = result.memid.mem.arena.slice_count;
    emit((int64_t)result.memid.mem.arena.slice_index);
    emit((int64_t)result.slices);
    emit(result.memid.initially_committed);
    emit(result.memid.initially_zero);
    emit(mi_bitmap_is_setN(arena->slices_committed, result.memid.mem.arena.slice_index, result.slices));
  }
  else {
    for (int i = 0; i < 5; i++) emit(-1);
  }
  emit_stats_delta(owner, before);
  emit_arenas_from(owner, arenas_before);
  return result;
}

/* One of eight concurrent workers in scenario 14: source `mi_arenas_try_alloc`
   of one slice with its own thread sequence, then release after the parent
   has recorded the combined result. */
typedef struct concurrent_worker_s {
  lifecycle_owner_t* owner;
  pthread_barrier_t* start;
  pthread_barrier_t* claimed;
  pthread_barrier_t* release;
  size_t tseq;
  void* p;
  mi_memid_t memid;
} concurrent_worker_t;

static void* concurrent_worker(void* raw) {
  concurrent_worker_t* const worker = (concurrent_worker_t*)raw;
  worker->memid = _mi_memid_none();
  pthread_barrier_wait(worker->start);
  worker->p = mi_arenas_try_alloc(&worker->owner->heap, 1, MI_ARENA_SLICE_ALIGN, false, true, NULL,
                                  worker->tseq, -1, &worker->memid);
  pthread_barrier_wait(worker->claimed);
  pthread_barrier_wait(worker->release);
  if (worker->p != NULL) {
    _mi_arenas_free(&worker->owner->subproc, worker->p, MI_ARENA_SLICE_SIZE, worker->memid);
  }
  return NULL;
}

/* Source `_mi_meta_free` of one metadata block (`theap.c:353` for an
   exclusive-arena Theap): its no-free predicate, then the same release
   record as `release`. */
static void meta_release(lifecycle_owner_t* owner, lifecycle_claim_t* item) {
  require(item->start != NULL);
  const lifecycle_stats_t before = stats_of(owner);
  mi_arena_t* const arena = item->memid.mem.arena.arena;
  const size_t index = item->memid.mem.arena.slice_index;
  emit(mi_memid_needs_no_free(item->memid));
  _mi_meta_free(&owner->subproc, item->start, item->memid);
  emit(mi_bbitmap_is_setN(arena->slices_free, index, item->slices));
  emit(mi_bitmap_is_setN(arena->slices_purge, index, item->slices));
  emit_stats_delta(owner, before);
  item->start = NULL;
}

/* Source `_mi_arenas_free` of one live claim. */
static void release(lifecycle_owner_t* owner, lifecycle_claim_t* item) {
  require(item->start != NULL);
  const lifecycle_stats_t before = stats_of(owner);
  mi_arena_t* const arena = item->memid.mem.arena.arena;
  const size_t index = item->memid.mem.arena.slice_index;
  _mi_arenas_free(&owner->subproc, item->start, mi_size_of_slices(item->slices), item->memid);
  emit(mi_bbitmap_is_setN(arena->slices_free, index, item->slices));
  emit(mi_bitmap_is_setN(arena->slices_purge, index, item->slices));
  emit_stats_delta(owner, before);
  item->start = NULL;
}

static void emit_marker(int64_t scenario) {
  emit(-1000 - scenario);
}

/* ------------------------------------------------------------------------ */

int main(void) {
  _mi_auto_process_init();

  /* 1. Reserved-growth: automatic reservation, registry growth, and the
        exponential arena-count scaling after eight arenas. */
  emit_marker(1);
  {
    configure(true, 128 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t claims[40];
    size_t live = 0;
    while (live < 40 && mi_arenas_get_count(&owner->subproc) < 10) {
      claims[live] = claim(owner, MI_BCHUNK_BITS, false, NULL, -1);
      require(claims[live].start != NULL);
      live++;
    }
    emit((int64_t)live);
    for (size_t i = 0; i < live; i++) release(owner, &claims[i]);
  }

  /* 2. Commit transitions: fresh commit, uncommitted claim, already
        committed reuse, and release/reclaim of the same span. */
  emit_marker(2);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t first = claim(owner, 1, true, NULL, -1);
    lifecycle_claim_t second = claim(owner, 2, false, NULL, -1);
    lifecycle_claim_t third = claim(owner, 4, true, NULL, -1);
    release(owner, &first);
    lifecycle_claim_t again = claim(owner, 1, true, NULL, -1);
    lifecycle_claim_t again_uncommitted = claim(owner, 1, false, NULL, -1);
    release(owner, &second);
    lifecycle_claim_t mixed = claim(owner, 3, false, NULL, -1);
    release(owner, &third);
    release(owner, &again);
    release(owner, &again_uncommitted);
    release(owner, &mixed);
  }

  /* 3. Eager-commit option matrix under both overcommit observations. */
  for (int variant = 0; variant < 5; variant++) {
    static const struct { bool overcommit; long eager; } variants[5] = {
      { true, 1 }, { true, 2 }, { false, 2 }, { false, 1 }, { true, 0 },
    };
    emit_marker(3);
    emit(variant);
    configure(variants[variant].overcommit, 32 * 1024, variants[variant].eager, false);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t committed = claim(owner, 2, true, NULL, -1);
    lifecycle_claim_t uncommitted = claim(owner, 2, false, NULL, -1);
    release(owner, &committed);
    lifecycle_claim_t reused = claim(owner, 2, true, NULL, -1);
    release(owner, &uncommitted);
    release(owner, &reused);
  }

  /* 4. disallow_os_alloc refuses the fresh reservation after exhaustion,
        then a later permitted request reserves the next arena. */
  emit_marker(4);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t claims[4];
    size_t live = 0;
    claims[live++] = claim(owner, MI_BCHUNK_BITS, false, NULL, -1);
    mi_option_set(mi_option_disallow_os_alloc, 1);
    claims[live] = claim(owner, MI_BCHUNK_BITS, false, NULL, -1);
    require(claims[live].start == NULL);
    mi_option_set(mi_option_disallow_os_alloc, 0);
    claims[live] = claim(owner, MI_BCHUNK_BITS, false, NULL, -1);
    require(claims[live].start != NULL);
    live++;
    for (size_t i = 0; i < live; i++) release(owner, &claims[i]);
  }

  /* 5. Requested and exclusive arenas. A requested full arena never
        reserves; an exclusive arena is skipped by unrequested searches. */
  emit_marker(5);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t full = claim(owner, MI_BCHUNK_BITS, false, NULL, -1);
    mi_arena_t* const first = full.memid.mem.arena.arena;
    lifecycle_claim_t requested_full = claim(owner, MI_BCHUNK_BITS, false, first, -1);
    require(requested_full.start == NULL);
    lifecycle_claim_t requested_small = claim(owner, 1, false, first, -1);

    const lifecycle_stats_t before = stats_of(owner);
    const size_t arenas_before = mi_arenas_get_count(&owner->subproc);
    mi_arena_id_t exclusive_id = _mi_arena_id_none();
    const int err = mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MIN_SIZE, false,
                                             false, true /* exclusive */, &exclusive_id);
    emit(err);
    emit(exclusive_id != _mi_arena_id_none());
    emit_stats_delta(owner, before);
    emit_arenas_from(owner, arenas_before);
    mi_arena_t* const exclusive = _mi_arena_from_id(exclusive_id);
    lifecycle_claim_t unrequested = claim(owner, MI_BCHUNK_BITS, false, NULL, -1);
    require(unrequested.start == NULL || unrequested.memid.mem.arena.arena != exclusive);
    lifecycle_claim_t in_exclusive = claim(owner, 2, true, exclusive, -1);
    require(in_exclusive.start != NULL && in_exclusive.memid.mem.arena.arena == exclusive);
    release(owner, &in_exclusive);
    if (unrequested.start != NULL) release(owner, &unrequested);
    release(owner, &requested_small);
    release(owner, &full);
  }

  /* 6. Requests too large for the bounded reservation or arena. */
  emit_marker(6);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t spanning = claim(owner, 1500, false, NULL, -1);
    lifecycle_claim_t oversized = claim(owner, (MI_ARENA_MAX_SIZE / MI_ARENA_SLICE_SIZE) - 64, false, NULL, -1);
    require(oversized.start == NULL);
    lifecycle_claim_t impossible = claim(owner, (MI_ARENA_MAX_SIZE / MI_ARENA_SLICE_SIZE) + 1, false, NULL, -1);
    require(impossible.start == NULL);
    if (spanning.start != NULL) release(owner, &spanning);
  }

  /* 7. Clean primary reservation failure. A failed 1-GiB primary takes the
        source 128-MiB fallback; a failed 128-MiB primary has no eligible
        smaller fallback and leaves the registry and statistics unchanged
        until a later request succeeds. Both run under reserved and eagerly
        committed (overcommit-adjusted) policies. */
  for (int variant = 0; variant < 2; variant++) {
    const long eager = (variant == 0 ? 0 : 1);
    emit_marker(7);
    emit(variant);
    configure(true, 1024 * 1024, eager, false);
    lifecycle_owner_t* const owner = fresh_owner();
    fail_mmap_at_or_above = 512 * MI_MiB;
    failed_mmap_calls = 0;
    lifecycle_claim_t fallback = claim(owner, 1, true, NULL, -1);
    require(fallback.start != NULL);
    emit(failed_mmap_calls > 0);
    fail_mmap_at_or_above = 0;
    release(owner, &fallback);

    configure(true, 128 * 1024, eager, false);
    lifecycle_owner_t* const bounded = fresh_owner();
    fail_mmap_at_or_above = 64 * MI_MiB;
    failed_mmap_calls = 0;
    lifecycle_claim_t refused = claim(bounded, 1, true, NULL, -1);
    require(refused.start == NULL);
    emit(failed_mmap_calls > 0);
    fail_mmap_at_or_above = 0;
    lifecycle_claim_t retried = claim(bounded, 1, true, NULL, -1);
    require(retried.start != NULL);
    release(bounded, &retried);
  }

  /* 8. A NUMA-local reservation records the current node, and a request for
        a different node reaches it only through the second source pass. */
  emit_marker(8);
  {
    configure(true, 32 * 1024, 0, false);
    mi_option_set(mi_option_arena_is_numa_local, 1);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t local = claim(owner, 1, false, NULL, 0);
    mi_arena_t* const arena = local.memid.mem.arena.arena;
    emit(arena->numa_node >= 0);
    lifecycle_claim_t remote = claim(owner, 1, false, NULL, arena->numa_node + 5);
    require(remote.start != NULL && remote.memid.mem.arena.arena == arena);
    release(owner, &remote);
    release(owner, &local);
    mi_option_set(mi_option_arena_is_numa_local, 0);
  }

  /* 9. An exclusive explicit reservation above MI_ARENA_MAX_SIZE spans a
        parent and one sub-arena that inherits exclusivity; a request naming
        the parent searches only the parent, while an unrequested search skips
        both and reserves a fresh shared arena. */
  emit_marker(9);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    const lifecycle_stats_t before = stats_of(owner);
    mi_arena_id_t parent_id = _mi_arena_id_none();
    const int err = mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MAX_SIZE + MI_GiB, false,
                                             false, true /* exclusive */, &parent_id);
    emit(err);
    emit(parent_id != _mi_arena_id_none());
    emit_stats_delta(owner, before);
    emit_arenas_from(owner, 0);
    mi_arena_t* const parent = _mi_arena_from_id(parent_id);
    require(parent != NULL && mi_arenas_get_count(&owner->subproc) == 2);
    require(mi_arena_from_index(&owner->subproc, 1)->parent == parent);
    lifecycle_claim_t in_parent = claim(owner, 1, false, parent, -1);
    require(in_parent.start != NULL && in_parent.memid.mem.arena.arena == parent);
    lifecycle_claim_t shared = claim(owner, 1, false, NULL, -1);
    require(shared.start != NULL && shared.memid.mem.arena.arena->parent == NULL
            && shared.memid.mem.arena.arena != parent);
    release(owner, &shared);
    release(owner, &in_parent);
  }

  /* 10. Registry exhaustion: explicit reservations fill all MI_MAX_ARENAS
         entries, the next one fails after mapping, and an automatic
         reservation is refused once more than MI_MAX_ARENAS - 4 exist. */
  emit_marker(10);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    size_t reserved = 0;
    int err = 0;
    lifecycle_stats_t before = stats_of(owner);
    while (reserved <= MI_MAX_ARENAS) {
      before = stats_of(owner);
      err = mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MIN_SIZE, false, false, false, NULL);
      if (err != 0) break;
      reserved++;
    }
    emit((int64_t)reserved);
    emit(err);
    emit((int64_t)mi_arenas_get_count(&owner->subproc));
    emit_stats_delta(owner, before);
    lifecycle_claim_t refused = claim(owner, MI_BCHUNK_BITS, false, NULL, -1);
    require(refused.start == NULL);
    lifecycle_claim_t fits = claim(owner, 1, false, NULL, -1);
    require(fits.start != NULL);
    release(owner, &fits);
  }

  /* 11. Sub-arena publication failure after a published parent: with
         MI_MAX_ARENAS - 1 entries taken, a spanning reservation publishes
         its parent in the last entry, the sub-arena's mi_arenas_add fails,
         and the reservation still succeeds with the parent's total_size
         reduced to the managed prefix. */
  emit_marker(11);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    for (size_t i = 0; i < MI_MAX_ARENAS - 1; i++) {
      require(mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MIN_SIZE, false, false, false, NULL) == 0);
    }
    const lifecycle_stats_t before = stats_of(owner);
    mi_arena_id_t parent_id = _mi_arena_id_none();
    const int err = mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MAX_SIZE + MI_GiB, false,
                                             false, false, &parent_id);
    emit(err);
    emit(parent_id != _mi_arena_id_none());
    emit_stats_delta(owner, before);
    emit_arenas_from(owner, MI_MAX_ARENAS - 1);
    mi_arena_t* const parent = _mi_arena_from_id(parent_id);
    require(parent != NULL);
    lifecycle_claim_t in_parent = claim(owner, 2, true, parent, -1);
    require(in_parent.start != NULL && in_parent.memid.mem.arena.arena == parent);
    release(owner, &in_parent);
  }

  /* 12. Sub-arena metadata commit failure after a published parent: the
         second source commit of a reserved spanning reservation fails in
         mi_arena_initialize, and the reservation succeeds with only the
         parent published. */
  emit_marker(12);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    const lifecycle_stats_t before = stats_of(owner);
    mi_arena_id_t parent_id = _mi_arena_id_none();
    mprotect_calls = 0;
    fail_mprotect_ordinal = 2;
    const int err = mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MAX_SIZE + MI_GiB, false,
                                             false, false, &parent_id);
    emit(mprotect_calls >= 2);
    fail_mprotect_ordinal = 0;
    emit(err);
    emit(parent_id != _mi_arena_id_none());
    emit_stats_delta(owner, before);
    emit_arenas_from(owner, 0);
    mi_arena_t* const parent = _mi_arena_from_id(parent_id);
    require(parent != NULL && mi_arenas_get_count(&owner->subproc) == 1);
    lifecycle_claim_t in_parent = claim(owner, 2, true, parent, -1);
    require(in_parent.start != NULL && in_parent.memid.mem.arena.arena == parent);
    lifecycle_claim_t shared = claim(owner, 1, false, NULL, -1);
    require(shared.start != NULL);
    release(owner, &shared);
    release(owner, &in_parent);
  }

  /* 13. `_mi_arenas_alloc(_aligned)` for a requested (exclusive) arena, the
         shape of its sole caller `_mi_theap_alloc`: the arena arm and each
         gate that skips it, exhaustion without reservation, the NUMA second
         pass, and the OS fallback that refuses every requested-arena miss. */
  emit_marker(13);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    mi_arena_id_t exclusive_id = _mi_arena_id_none();
    require(mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MIN_SIZE, false, false, true, &exclusive_id) == 0);
    mi_arena_t* const exclusive = _mi_arena_from_id(exclusive_id);
    lifecycle_claim_t theap = object(owner, MI_ARENA_MIN_OBJ_SIZE, MI_ARENA_SLICE_SIZE, 0, exclusive, -1);
    require(theap.start != NULL);
    lifecycle_claim_t largest = object(owner, 2 * MI_MiB, MI_ARENA_SLICE_SIZE, 0, exclusive, 2);
    require(largest.start != NULL);
    emit((int64_t)(mi_arena_max_object_size() / MI_ARENA_SLICE_SIZE));
    lifecycle_claim_t at_max = object(owner, mi_arena_max_object_size(), MI_ARENA_SLICE_SIZE, 0, exclusive, -1);
    if (at_max.start != NULL) release(owner, &at_max);
    require(object(owner, MI_ARENA_MIN_OBJ_SIZE - 1, MI_ARENA_SLICE_SIZE, 0, exclusive, -1).start == NULL);
    require(object(owner, mi_arena_max_object_size() + 1, MI_ARENA_SLICE_SIZE, 0, exclusive, -1).start == NULL);
    require(object(owner, MI_ARENA_MIN_OBJ_SIZE, 2 * MI_ARENA_SLICE_SIZE, 0, exclusive, -1).start == NULL);
    require(object(owner, MI_ARENA_MIN_OBJ_SIZE, MI_ARENA_SLICE_SIZE, 16, exclusive, -1).start == NULL);
    mi_option_set(mi_option_disallow_arena_alloc, 1);
    require(object(owner, MI_ARENA_MIN_OBJ_SIZE, MI_ARENA_SLICE_SIZE, 0, exclusive, -1).start == NULL);
    mi_option_set(mi_option_disallow_arena_alloc, 0);
    lifecycle_claim_t fill[16];
    size_t filled = 0;
    while (filled < 16) {
      fill[filled] = object(owner, 2 * MI_MiB, MI_ARENA_SLICE_SIZE, 0, exclusive, -1);
      if (fill[filled].start == NULL) break;
      filled++;
    }
    emit((int64_t)filled);
    for (size_t i = 0; i < filled; i++) release(owner, &fill[i]);
    release(owner, &largest);
    release(owner, &theap);
  }

  /* 14. Concurrent fresh reservation: with the only arena exhausted, eight
         workers enter mi_arenas_try_alloc together. The arena_reserve_lock
         unchanged-count check serializes reservation but does not make it
         unique: a worker whose search failed before another's publication
         but whose count read follows it reserves again. Only
         interleaving-independent relations are recorded: every worker
         claims a distinct slice of a fresh arena, between one and eight
         identically sized arenas are reserved, and statistics account for
         exactly those arenas. */
  emit_marker(14);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    mi_arena_id_t existing_id = _mi_arena_id_none();
    require(mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MIN_SIZE, false, false, false, &existing_id) == 0);
    mi_arena_t* const existing = _mi_arena_from_id(existing_id);
    lifecycle_claim_t fillers[MI_ARENA_MIN_SIZE / MI_ARENA_SLICE_SIZE];
    size_t filled = 0;
    for (;;) {
      require(filled < sizeof(fillers) / sizeof(fillers[0]));
      fillers[filled].slices = 1;
      fillers[filled].start = mi_arenas_try_alloc(&owner->heap, 1, MI_ARENA_SLICE_ALIGN, false, true, existing,
                                                  0, -1, &fillers[filled].memid);
      if (fillers[filled].start == NULL) break;
      filled++;
    }
    emit((int64_t)filled);
    pthread_barrier_t start, claimed, release_all;
    pthread_barrier_init(&start, NULL, 8);
    pthread_barrier_init(&claimed, NULL, 9);
    pthread_barrier_init(&release_all, NULL, 9);
    concurrent_worker_t workers[8];
    pthread_t threads[8];
    const lifecycle_stats_t before = stats_of(owner);
    for (size_t i = 0; i < 8; i++) {
      workers[i] = (concurrent_worker_t){ owner, &start, &claimed, &release_all, i, NULL, _mi_memid_none() };
      require(pthread_create(&threads[i], NULL, concurrent_worker, &workers[i]) == 0);
    }
    pthread_barrier_wait(&claimed);
    const lifecycle_stats_t after = stats_of(owner);
    const int64_t fresh = (int64_t)mi_arenas_get_count(&owner->subproc) - 1;
    mi_arena_t* const first_fresh = mi_arena_from_index(&owner->subproc, 1);
    size_t claimed_count = 0;
    bool in_fresh = true, distinct = true;
    for (size_t i = 0; i < 8; i++) {
      if (workers[i].p == NULL) continue;
      claimed_count++;
      in_fresh = in_fresh && workers[i].memid.mem.arena.arena != existing
                 && workers[i].memid.mem.arena.arena->arena_idx >= 1;
      for (size_t j = 0; j < i; j++) distinct = distinct && workers[j].p != workers[i].p;
    }
    bool same_geometry = true;
    for (int64_t index = 1; index <= fresh; index++) {
      mi_arena_t* const arena = mi_arena_from_index(&owner->subproc, (size_t)index);
      same_geometry = same_geometry && arena->slice_count == first_fresh->slice_count
                      && arena->info_slices == first_fresh->info_slices && arena->parent == NULL;
    }
    emit((int64_t)claimed_count);
    emit(in_fresh);
    emit(distinct);
    emit(fresh >= 1 && fresh <= 8);
    emit(same_geometry);
    emit((int64_t)first_fresh->slice_count);
    emit((int64_t)first_fresh->info_slices);
    emit((after.reserved - before.reserved) / fresh);
    emit((after.reserved - before.reserved) % fresh);
    emit((after.committed - before.committed) / fresh);
    emit((after.committed - before.committed) % fresh);
    emit(after.commit_calls - before.commit_calls == fresh);
    emit(after.arena_count - before.arena_count == fresh);
    pthread_barrier_wait(&release_all);
    for (size_t i = 0; i < 8; i++) require(pthread_join(threads[i], NULL) == 0);
    bool all_free = true;
    for (int64_t index = 1; index <= fresh; index++) {
      mi_arena_t* const arena = mi_arena_from_index(&owner->subproc, (size_t)index);
      all_free = all_free && free_slice_count(arena) == arena->slice_count - arena->info_slices;
    }
    emit(all_free);
    for (size_t i = 0; i < filled; i++) release(owner, &fillers[i]);
  }

  /* 15. `_mi_theap_alloc` in a reserved exclusive arena: its commit fails
         once. With a negative NUMA node the one requested-arena pass
         refuses; with a nonnegative node the second source pass repeats the
         same parent and commits. disallow_arena_alloc refuses before any
         search, and every refusal skips the OS (the arena is requested).
         The committed Theap is returned through `_mi_meta_free`'s Arena
         branch, as `theap.c:353` does. */
  emit_marker(15);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    mi_arena_id_t exclusive_id = _mi_arena_id_none();
    require(mi_reserve_os_memory_ex2(&owner->subproc, MI_ARENA_MIN_SIZE, false, false, true, &exclusive_id) == 0);
    mi_arena_t* const exclusive = _mi_arena_from_id(exclusive_id);
    mprotect_calls = 0;
    fail_mprotect_ordinal = 1;
    lifecycle_claim_t one_pass = theap_alloc(owner, exclusive, -1);
    emit((int64_t)mprotect_calls);
    fail_mprotect_ordinal = 0;
    require(one_pass.start == NULL);
    mprotect_calls = 0;
    fail_mprotect_ordinal = 1;
    lifecycle_claim_t second_pass = theap_alloc(owner, exclusive, 0);
    emit((int64_t)mprotect_calls);
    fail_mprotect_ordinal = 0;
    require(second_pass.start != NULL);
    mi_option_set(mi_option_disallow_arena_alloc, 1);
    lifecycle_claim_t disallowed = theap_alloc(owner, exclusive, 0);
    mi_option_set(mi_option_disallow_arena_alloc, 0);
    require(disallowed.start == NULL);
    meta_release(owner, &second_pass);
  }

  /* 16. A committed claim whose first-arena commit fails: the unchanged
         registry count makes the source reserve a fresh arena (its metadata
         commit succeeds), and the second search commits in the first arena.
         Every attempted commit counts a commit call. */
  emit_marker(16);
  {
    configure(true, 32 * 1024, 0, false);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t first = claim(owner, 1, false, NULL, -1);
    mprotect_calls = 0;
    fail_mprotect_ordinal = 1;
    lifecycle_claim_t retried = claim(owner, 1, true, NULL, -1);
    emit((int64_t)mprotect_calls);
    fail_mprotect_ordinal = 0;
    require(retried.start != NULL && retried.memid.mem.arena.arena == first.memid.mem.arena.arena);
    release(owner, &retried);
    release(owner, &first);
  }

  /* 17. Immediate purge on release (`purge_delay == 0`) through decommit:
         a failed MADV_DONTNEED is only a warning, a successful one keeps
         Linux's no-recommit result, and a mixed-commitment range loses its
         committed bits either way. */
  emit_marker(17);
  {
    configure(true, 32 * 1024, 0, false);
    mi_option_set(mi_option_purge_delay, 0);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t failing = claim(owner, 2, true, NULL, -1);
    lifecycle_claim_t succeeding = claim(owner, 2, true, NULL, -1);
    lifecycle_claim_t mixed = claim(owner, 2, false, NULL, -1);
    lifecycle_claim_t* const order[3] = { &failing, &succeeding, &mixed };
    for (size_t i = 0; i < 3; i++) {
      const purge_counters_t before = purge_counters_of(owner);
      arm_madvise(i == 0 ? 1 : 0, ENOMEM);
      release(owner, order[i]);
      emit_madvise_record();
      emit_purge_counters_delta(owner, before);
      emit_arenas_from(owner, 0);
    }
    mi_option_set(mi_option_purge_delay, -1);
  }

  /* 18. Immediate purge through reset (`purge_decommits == 0`): EAGAIN
         retries the same advice, another error is only a warning, and a
         range that is not fully committed is not reset at all. */
  emit_marker(18);
  {
    configure(true, 32 * 1024, 0, false);
    mi_option_set(mi_option_purge_delay, 0);
    mi_option_set(mi_option_purge_decommits, 0);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t again = claim(owner, 2, true, NULL, -1);
    lifecycle_claim_t failing = claim(owner, 2, true, NULL, -1);
    lifecycle_claim_t mixed = claim(owner, 2, false, NULL, -1);
    lifecycle_claim_t* const order[3] = { &again, &failing, &mixed };
    const int errors[3] = { EAGAIN, ENOMEM, ENOMEM };
    for (size_t i = 0; i < 3; i++) {
      const purge_counters_t before = purge_counters_of(owner);
      arm_madvise(i < 2 ? 1 : 0, errors[i]);
      release(owner, order[i]);
      emit_madvise_record();
      emit_purge_counters_delta(owner, before);
      emit_arenas_from(owner, 0);
    }
    mi_option_set(mi_option_purge_decommits, 1);
    mi_option_set(mi_option_purge_delay, -1);
  }

  /* 19. A delayed purge whose forced collection decommit fails: the source
         consumes the schedule (purge bits and expiry clear), keeps the range
         free, and a second forced collection has nothing to retry. */
  emit_marker(19);
  {
    configure(true, 32 * 1024, 0, false);
    mi_option_set(mi_option_purge_delay, 10);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t scheduled = claim(owner, 2, true, NULL, -1);
    mi_arena_t* const arena = scheduled.memid.mem.arena.arena;
    release(owner, &scheduled);
    emit(mi_atomic_loadi64_relaxed(&arena->purge_expire) != 0);
    for (int pass = 0; pass < 2; pass++) {
      const purge_counters_t before = purge_counters_of(owner);
      arm_madvise(pass == 0 ? 1 : 0, ENOMEM);
      mi_arenas_try_purge(true, true, &owner->subproc, 0);
      emit_madvise_record();
      emit_purge_counters_delta(owner, before);
      emit(mi_atomic_loadi64_relaxed(&arena->purge_expire) == 0);
      emit((int64_t)mi_bitmap_popcount(arena->slices_purge));
      emit_arenas_from(owner, 0);
    }
    mi_option_set(mi_option_purge_delay, -1);
  }

  /* 20. Reset EINVAL: MADV_FREE is replaced by MADV_DONTNEED for the same
         call and every later reset. This process-global switch runs last. */
  emit_marker(20);
  {
    configure(true, 32 * 1024, 0, false);
    mi_option_set(mi_option_purge_delay, 0);
    mi_option_set(mi_option_purge_decommits, 0);
    lifecycle_owner_t* const owner = fresh_owner();
    lifecycle_claim_t first = claim(owner, 2, true, NULL, -1);
    lifecycle_claim_t later = claim(owner, 2, true, NULL, -1);
    lifecycle_claim_t* const order[2] = { &first, &later };
    for (size_t i = 0; i < 2; i++) {
      const purge_counters_t before = purge_counters_of(owner);
      arm_madvise(i == 0 ? 1 : 0, EINVAL);
      release(owner, order[i]);
      emit_madvise_record();
      emit_purge_counters_delta(owner, before);
    }
    mi_option_set(mi_option_purge_decommits, 1);
    mi_option_set(mi_option_purge_delay, -1);
  }

  /* 21. The fresh OS page caller (`mi_arenas_page_alloc_fresh_area` with
         arena allocation disallowed, one 4-KiB-block small page, committed):
         success and release; a metadata or page-area commit failure whose
         `_mi_os_free` cleanup succeeds or fails; and a release whose unmap
         fails. Pinned `mi_os_prim_free` applies statistics whether or not the
         unmap succeeds and leaks the failed range; Rust accounts once and
         retains the range for a raw retry, which adds no statistics. */
  emit_marker(21);
  {
    configure(true, 32 * 1024, 0, false);
    mi_option_set(mi_option_disallow_arena_alloc, 1);
    lifecycle_owner_t* const owner = fresh_owner();
    owner->heap.numa_node = -1;
    static mi_tld_t tld;
    static mi_theap_t theap;
    memset(&tld, 0, sizeof(tld));
    memset(&theap, 0, sizeof(theap));
    tld.subproc = &owner->subproc;
    tld.numa_node = -1;
    theap.tld = &tld;
    mi_atomic_store_ptr_relaxed(mi_heap_t, &theap.heap, &owner->heap);
    mi_atomic_store_ptr_relaxed(mi_subproc_t, &theap.subproc, &owner->subproc);
    /* variant: 0 success, 1/2 commit failure at that call with cleanup
       success, 3/4 the same with cleanup failure, 5 release failure. */
    for (int variant = 0; variant < 6; variant++) {
      const lifecycle_stats_t before = stats_of(owner);
      const size_t commit_failure = (variant == 1 || variant == 3 ? 1 : variant == 2 || variant == 4 ? 2 : 0);
      mprotect_calls = 0;
      mprotect_failed = false;
      fail_mprotect_ordinal = (commit_failure != 0 ? commit_failure : SIZE_MAX);  /* count only */
      fail_munmap_after_mprotect = (variant == 3 || variant == 4);
      retained_addr = NULL;
      mi_memid_t memid = _mi_memid_none();
      mi_arena_pages_t* arena_pages = NULL;
      uint8_t* const start = mi_arenas_page_alloc_fresh_area(&theap, 1, 1, 1, false, true, &memid, &arena_pages);
      fail_mprotect_ordinal = 0;
      fail_munmap_after_mprotect = false;
      emit(variant);
      emit(start != NULL);
      emit((int64_t)mprotect_calls);
      emit(retained_addr != NULL);
      emit_stats_delta(owner, before);
      if (retained_addr != NULL) {
        require(__real_munmap(retained_addr, retained_length) == 0);
        emit_stats_delta(owner, before);
      }
      if (start == NULL) continue;
      emit(memid.memkind == MI_MEM_OS);
      emit(memid.initially_committed);
      emit(start == (uint8_t*)memid.mem.os.base + MI_PAGE_ALIGN);
      const lifecycle_stats_t after_alloc = stats_of(owner);
      fail_next_munmap = (variant == 5);
      munmap_calls = 0;
      retained_addr = NULL;
      _mi_os_free(&owner->subproc, memid.mem.os.base, memid.mem.os.size, memid);
      fail_next_munmap = false;
      emit((int64_t)munmap_calls);
      emit(retained_addr != NULL);
      emit_stats_delta(owner, after_alloc);
      if (retained_addr != NULL) {
        require(__real_munmap(retained_addr, retained_length) == 0);
        emit_stats_delta(owner, after_alloc);
      }
    }
    mi_option_set(mi_option_disallow_arena_alloc, 0);
  }

  emit_marker(22);
  return 0;
}

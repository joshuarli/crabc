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

/* ------------------------------------------------------------------------ */
/* Isolated source subprocess registries.                                    */

typedef struct lifecycle_owner_s {
  mi_subproc_t subproc;
  mi_heap_t heap;
} lifecycle_owner_t;

static lifecycle_owner_t owners[16];
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

  emit_marker(10);
  return 0;
}

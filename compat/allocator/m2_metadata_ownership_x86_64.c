/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/*
  Pinned v3.5.0 metadata ownership: `src/subproc.c` `_mi_meta_zalloc`,
  `_mi_meta_free`, and `_mi_meta_is_meta_page` driven through `static.c`
  without stubs. `meta::ownership_tests::emit_native_metadata_ownership_trace` emits the
  same ordered, address-free `m2.metadata.ownership.N=V` fields.

  1. The `_mi_meta_free` no-free predicate for every memory kind.
  2. A non-main subprocess (`mi_subproc_new`): its image and metadata Theap
     are parent metadata, while its own metadata blocks live on its own
     metadata pages in its own arenas, without growing the parent's arenas.
  3. A deterministic allocation/release overlap on the main subprocess: one
     allocation is held inside `theap_meta_lock` (the fixture owns the lock
     and waits until the allocating thread arrives at it), a published block
     is released by a third thread during that allocation, and only then is
     the lock returned. Source `_mi_meta_free` of a Malloc block is a
     lock-free `mi_free`, so the release completes inside the window; the
     Rust release instead reaches its backing lock there (see
     known-differences.md). Only the facts that hold for both are emitted.
  4. `_mi_meta_free`'s non-Malloc (Arena) branch for an exclusive-arena Theap
     slice, against Rust's typed exclusive-arena Theap reservation.

  `pthread_mutex_lock` is wrapped only to count arrivals at the one armed
  mutex; the real lock is always taken.
*/
#include "static.c"
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t field;
static void emit(int64_t value) {
  printf("m2.metadata.ownership.%zu=%lld\n", field++, (long long)value);
}

static void require_at(bool condition, int line) {
  if (!condition) {
    fflush(stdout);
    fprintf(stderr, "m2_metadata_ownership_x86_64.c:%d: requirement failed\n", line);
    abort();
  }
}
#define require(condition) require_at((condition), __LINE__)

static void emit_marker(int64_t scenario) { emit(-1000 - scenario); }

int __real_pthread_mutex_lock(pthread_mutex_t* mutex);
static pthread_mutex_t* _Atomic armed_mutex;
static atomic_size_t armed_arrivals;

int __wrap_pthread_mutex_lock(pthread_mutex_t* mutex) {
  if (mutex == atomic_load(&armed_mutex)) atomic_fetch_add(&armed_arrivals, 1);
  return __real_pthread_mutex_lock(mutex);
}

static bool all_bytes(const void* p, size_t size, unsigned char value) {
  const unsigned char* bytes = p;
  for (size_t i = 0; i < size; i++) if (bytes[i] != value) return false;
  return true;
}

/* ------------------------------------------------------------------------ */

typedef struct published_s {
  mi_subproc_t* subproc;
  void* block;
  mi_memid_t memid;
} published_t;

static void* publish(void* raw) {
  published_t* const item = raw;
  item->block = _mi_meta_zalloc(item->subproc, 64, &item->memid);
  require(item->block != NULL && all_bytes(item->block, 64, 0));
  memset(item->block, 0xa5, 64);
  return NULL;
}

typedef struct allocation_s {
  mi_subproc_t* subproc;
  size_t size;
  void* block;
  mi_memid_t memid;
} allocation_t;

static void* allocate(void* raw) {
  allocation_t* const item = raw;
  item->block = _mi_meta_zalloc(item->subproc, item->size, &item->memid);
  return NULL;
}

typedef struct release_s {
  published_t* published;
  bool payload_intact;
  atomic_bool done;
} release_t;

static void* release_published(void* raw) {
  release_t* const item = raw;
  item->payload_intact = all_bytes(item->published->block, 64, 0xa5);
  _mi_meta_free(item->published->subproc, item->published->block, item->published->memid);
  atomic_store(&item->done, true);
  return NULL;
}

int main(void) {
  mi_process_init();
  mi_option_set(mi_option_arena_reserve, (long)(MI_ARENA_MIN_SIZE / MI_KiB));
  mi_option_set(mi_option_arena_eager_commit, 0);
  mi_option_set(mi_option_purge_delay, -1);
  mi_subproc_t* const main_subproc = _mi_subproc_main();

  /* 1. `_mi_meta_free` returns without freeing exactly for these kinds. */
  emit_marker(1);
  for (int kind = MI_MEM_NONE; kind <= MI_MEM_MALLOC; kind++) {
    mi_memid_t memid = _mi_memid_none();
    memid.memkind = (mi_memkind_t)kind;
    emit(mi_memid_needs_no_free(memid));
  }

  /* 2. Non-main subprocess metadata ownership. */
  emit_marker(2);
  {
    mi_subproc_t* const child = _mi_subproc_from_id(mi_subproc_new());
    require(child != NULL);
    /* Parent arenas are counted after the parent issued the child image. */
    const size_t main_arenas_before = mi_arenas_get_count(main_subproc);
    emit(_mi_meta_is_meta_page(main_subproc, _mi_ptr_page(child)));
    emit(_mi_meta_is_meta_page(child, _mi_ptr_page(child)));
    emit(_mi_meta_is_meta_page(main_subproc, _mi_ptr_page(child->theap_meta)));
    emit((int64_t)mi_arenas_get_count(child));
    const size_t sizes[4] = { 1, 64, 1025, 131073 };
    void* blocks[4];
    mi_memid_t memids[4];
    for (size_t i = 0; i < 4; i++) {
      blocks[i] = _mi_meta_zalloc(child, sizes[i], &memids[i]);
      require(blocks[i] != NULL && memids[i].memkind == MI_MEM_MALLOC);
      mi_page_t* const page = _mi_ptr_page(blocks[i]);
      emit(all_bytes(blocks[i], sizes[i], 0));
      emit(_mi_meta_is_meta_page(child, page));
      emit(_mi_meta_is_meta_page(main_subproc, page));
      emit(page->memid.memkind == MI_MEM_ARENA && mi_memid_arena(page->memid)->subproc == child);
      emit((int64_t)mi_arenas_get_count(child));
      emit((int64_t)mi_arenas_get_count(main_subproc) - (int64_t)main_arenas_before);
      memset(blocks[i], 0x5a, sizes[i]);
    }
    for (size_t i = 0; i < 4; i++) {
      emit(all_bytes(blocks[i], sizes[i], 0x5a));
      _mi_meta_free(child, blocks[i], memids[i]);
    }
    emit((int64_t)mi_arenas_get_count(child));
    emit((int64_t)mi_arenas_get_count(main_subproc) - (int64_t)main_arenas_before);
    mi_subproc_destroy(_mi_subproc_to_id(child));
  }

  /* 3. Deterministic allocation/release overlap on the main subprocess. */
  emit_marker(3);
  {
    mi_option_set(mi_option_page_commit_on_demand, 0);
    published_t published = { main_subproc, NULL, _mi_memid_none() };
    pthread_t publisher;
    require(pthread_create(&publisher, NULL, publish, &published) == 0);
    require(pthread_join(publisher, NULL) == 0);
    const size_t arenas_before = mi_arenas_get_count(main_subproc);

    mi_lock_acquire(&main_subproc->theap_meta_lock);
    atomic_store(&armed_arrivals, 0);
    atomic_store(&armed_mutex, &main_subproc->theap_meta_lock.mutex);
    allocation_t allocation = { main_subproc, 2 * MI_ARENA_MIN_SIZE, NULL, _mi_memid_none() };
    pthread_t allocator;
    require(pthread_create(&allocator, NULL, allocate, &allocation) == 0);
    while (atomic_load(&armed_arrivals) == 0) sched_yield();
    emit(1);  /* the allocation is waiting on theap_meta_lock */
    emit((int64_t)(mi_arenas_get_count(main_subproc) - arenas_before));

    release_t release = { &published, false, false };
    pthread_t releaser;
    require(pthread_create(&releaser, NULL, release_published, &release) == 0);
    /* C synchronization point: the lock-free Malloc release completes. */
    while (!atomic_load(&release.done)) sched_yield();
    emit(allocation.block == NULL);  /* still inside the held lock */
    atomic_store(&armed_mutex, NULL);
    mi_lock_release(&main_subproc->theap_meta_lock);
    require(pthread_join(allocator, NULL) == 0);
    require(pthread_join(releaser, NULL) == 0);

    emit(release.payload_intact);
    emit(allocation.block != NULL && allocation.memid.memkind == MI_MEM_MALLOC);
    emit(all_bytes(allocation.block, allocation.size, 0));
    emit(_mi_meta_is_meta_page(main_subproc, _mi_ptr_page(allocation.block)));
    emit(allocation.block != published.block);
    emit((int64_t)(mi_arenas_get_count(main_subproc) - arenas_before));
    _mi_meta_free(main_subproc, allocation.block, allocation.memid);
  }

  /* 4. `_mi_meta_free`'s non-Malloc branch: an exclusive-arena Theap slice
        (the `theap.c:318-325` producer, `_mi_arenas_alloc` with a requested
        arena) returns through `_mi_arenas_free` (`theap.c:353`). */
  emit_marker(4);
  {
    mi_arena_id_t arena_id = _mi_arena_id_none();
    require(mi_reserve_os_memory_ex2(main_subproc, MI_ARENA_MIN_SIZE, false, false, true, &arena_id) == 0);
    mi_arena_t* const arena = _mi_arena_from_id(arena_id);
    const int64_t committed_before = main_subproc->stats.committed.current;
    const int64_t reserved_before = main_subproc->stats.reserved.current;
    mi_memid_t memid = _mi_memid_none();
    void* const theap = _mi_arenas_alloc(_mi_subproc_heap_main(main_subproc), MI_ARENA_MIN_OBJ_SIZE,
                                         true, true, arena, 0, -1, &memid);
    require(theap != NULL);
    const size_t index = memid.mem.arena.slice_index;
    const size_t count = memid.mem.arena.slice_count;
    emit(memid.memkind == MI_MEM_ARENA && mi_memid_arena(memid) == arena);
    emit(mi_memid_needs_no_free(memid));
    emit((int64_t)count);
    emit(mi_bbitmap_is_clearN(arena->slices_free, index, count));
    emit(main_subproc->stats.committed.current - committed_before);
    _mi_meta_free(main_subproc, theap, memid);
    emit(mi_bbitmap_is_setN(arena->slices_free, index, count));
    emit(mi_bitmap_is_setN(arena->slices_purge, index, count));
    emit(main_subproc->stats.committed.current - committed_before);
    emit(main_subproc->stats.reserved.current - reserved_before);
  }

  emit_marker(5);
  return 0;
}

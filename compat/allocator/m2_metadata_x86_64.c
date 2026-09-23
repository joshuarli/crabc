/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT
 * Direct pinned-v3.5.0 metadata callers; static.c supplies the real detached
 * Theap, arena/OS policy, PageMap, and release implementation, without stubs.
 */
#include "static.c"
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdint.h>

/* Joining an allocating thread publishes payload and exact typed provenance
 * to a different releasing thread. Failed source rezalloc clears its output
 * memid, so preserve the old allocation's release identity separately. */
struct published_metadata {
  void* pointer;
  mi_memid_t memory;
  size_t usable;
};
struct metadata_worker {
  mi_subproc_t* subproc;
  size_t index;
  pthread_barrier_t* phase;
  struct published_metadata published[24];
  int error;
};
static void* publish_metadata(void* argument) {
  struct metadata_worker* worker = argument;
  const size_t sizes[] = {0, 1, 63, 1025, 4097, 131073};
  const size_t alignments[] = {8, 64, 4096, 65536};
  for (size_t i = 0; i < 12; i++) {
    const size_t size = sizes[i % 6];
    const size_t alignment = alignments[(worker->index + i) % 4];
    struct published_metadata* item = &worker->published[i];
    item->pointer = (i % 2 == 0
      ? _mi_meta_zalloc(worker->subproc, size, &item->memory)
      : _mi_meta_zalloc_aligned(worker->subproc, size, alignment, &item->memory));
    if (item->pointer == NULL || item->memory.memkind != MI_MEM_MALLOC
        || _mi_memid_size(item->memory) != size
        || !item->memory.initially_zero
        || (i % 2 != 0 && (uintptr_t)item->pointer % alignment != 0)) {
      worker->error = 10;
      return NULL;
    }
    const unsigned char* bytes = item->pointer;
    for (size_t j = 0; j < size; j++) {
      if (bytes[j] != 0) { worker->error = 11; return NULL; }
    }
    item->usable = mi_usable_size(item->pointer);
    memset(item->pointer, 0xa5, item->usable);
  }
  pthread_barrier_wait(worker->phase);
  /* Keep real peer allocations live while three peers continue allocating.
   * This joins source _mi_meta_rezalloc/free with concurrent _mi_meta_zalloc
   * calls, rather than postponing every release until all producers join. */
  if (worker->index == 0) {
    struct metadata_worker* const peers = worker - worker->index;
    for (size_t other = 1; other < 4; other++) {
      for (size_t i = 0; i < 6; i++) {
        struct published_metadata* item = &peers[other].published[i];
        mi_memid_t output_memory = item->memory;
        if (_mi_meta_rezalloc(worker->subproc, item->pointer, SIZE_MAX, &output_memory) != NULL
            || output_memory.memkind != MI_MEM_NONE) { worker->error = 20; return NULL; }
        const size_t newsize = (i % 2 == 0 ? item->usable + 47 : item->usable / 2);
        output_memory = item->memory;
        unsigned char* replacement = _mi_meta_rezalloc(worker->subproc, item->pointer, newsize, &output_memory);
        if (replacement == NULL || output_memory.memkind != MI_MEM_MALLOC) { worker->error = 21; return NULL; }
        const size_t copied = (newsize < item->usable ? newsize : item->usable);
        for (size_t k = 0; k < newsize; k++) {
          if (replacement[k] != (k < copied ? 0xa5 : 0)) { worker->error = 22; return NULL; }
        }
        _mi_meta_free(worker->subproc, replacement, output_memory);
        item->pointer = NULL; /* sole release capability was consumed above */
      }
    }
  }
  for (size_t i = 12; i < 24; i++) {
    const size_t size = sizes[i % 6];
    const size_t alignment = alignments[(worker->index + i) % 4];
    struct published_metadata* item = &worker->published[i];
    item->pointer = (i % 2 == 0
      ? _mi_meta_zalloc(worker->subproc, size, &item->memory)
      : _mi_meta_zalloc_aligned(worker->subproc, size, alignment, &item->memory));
    if (item->pointer == NULL || item->memory.memkind != MI_MEM_MALLOC
        || _mi_memid_size(item->memory) != size || !item->memory.initially_zero
        || (i % 2 != 0 && (uintptr_t)item->pointer % alignment != 0)) {
      worker->error = 23; return NULL;
    }
    const unsigned char* bytes = item->pointer;
    for (size_t j = 0; j < size; j++) if (bytes[j] != 0) { worker->error = 24; return NULL; }
    item->usable = mi_usable_size(item->pointer);
    memset(item->pointer, 0xa5, item->usable);
  }
  return NULL;
}
static int metadata_lifecycle(mi_subproc_t* subproc) {
  pthread_barrier_t phase;
  if (pthread_barrier_init(&phase, NULL, 4) != 0) return 12;
  struct metadata_worker workers[4] = {0};
  pthread_t threads[4];
  for (size_t i = 0; i < 4; i++) {
    workers[i].subproc = subproc;
    workers[i].index = i;
    workers[i].phase = &phase;
    if (pthread_create(&threads[i], NULL, publish_metadata, &workers[i]) != 0) return 13;
  }
  for (size_t i = 0; i < 4; i++) {
    if (pthread_join(threads[i], NULL) != 0) return 14;
    if (workers[i].error != 0) return workers[i].error;
    for (size_t j = 0; j < 24; j++) {
      struct published_metadata* item = &workers[i].published[j];
      if (item->pointer == NULL) continue;
      mi_memid_t output_memory = item->memory;
      if (_mi_meta_rezalloc(subproc, item->pointer, SIZE_MAX, &output_memory) != NULL
          || output_memory.memkind != MI_MEM_NONE) return 15;
      if (!_mi_meta_is_meta_page(subproc, _mi_ptr_page(item->pointer))) return 16;
      const size_t newsize = (j % 2 == 0 ? item->usable + 47 : item->usable / 2);
      output_memory = item->memory;
      unsigned char* replacement = _mi_meta_rezalloc(subproc, item->pointer, newsize, &output_memory);
      if (replacement == NULL || output_memory.memkind != MI_MEM_MALLOC) return 17;
      const size_t copied = (newsize < item->usable ? newsize : item->usable);
      for (size_t k = 0; k < newsize; k++) {
        if (replacement[k] != (k < copied ? 0xa5 : 0)) return 18;
      }
      _mi_meta_free(subproc, replacement, output_memory);
    }
  }
  if (pthread_barrier_destroy(&phase) != 0) return 19;
  puts("CRABC_MI_M2_METADATA_LIFECYCLE_TRACE_BEGIN");
  puts("m2.metadata.lifecycle.workers=4");
  puts("m2.metadata.lifecycle.published=96");
  puts("m2.metadata.lifecycle.failed_replacement_preserved=96");
  puts("m2.metadata.lifecycle.replaced_released=96");
  puts("m2.metadata.lifecycle.midrun_peer_replacements=18");
  puts("CRABC_MI_M2_METADATA_LIFECYCLE_TRACE_END");
  return 0;
}

int main(void) {
  mi_process_init();
  mi_subproc_t* const subproc = _mi_subproc_main();
  mi_option_set(mi_option_arena_reserve, 64 * 1024); /* source KiB option */
  mi_option_set(mi_option_page_commit_on_demand, 0);
  mi_memid_t first_memory = _mi_memid_none();
  void* const first = _mi_meta_zalloc(subproc, 64, &first_memory);
  if (first == NULL || mi_atomic_load_relaxed(&subproc->arena_count) != 1) return 5;
  const size_t size = 2 * MI_ARENA_MIN_SIZE;
  mi_memid_t memory = _mi_memid_none();
  unsigned char* const p = _mi_meta_zalloc(subproc, size, &memory);
  if (p == NULL) return 1;
  if (mi_atomic_load_relaxed(&subproc->arena_count) != 2) return 6;
  if (memory.memkind != MI_MEM_MALLOC) return 2;
  for (size_t i = 0; i < size; i++) {
    if (p[i] != 0) return 3;
  }
  if (!_mi_meta_is_meta_page(subproc, _mi_ptr_page(p))) return 4;
  _mi_meta_free(subproc, p, memory);
  _mi_meta_free(subproc, first, first_memory);
  printf("m2.metadata.capacity.bytes=%zu\n", size);
  printf("m2.metadata.capacity.zeroed_malloc_released=1\n");
  return metadata_lifecycle(subproc);
}

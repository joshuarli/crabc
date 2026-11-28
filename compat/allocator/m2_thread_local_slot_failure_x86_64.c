/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned regular thread-local slot growth failure: the first Heap Theap of a
   thread sets its regular key, mi_thread_locals_expand's metadata request is
   refused (src/threadlocal.c:104-147), and mi_heap_init_theap still returns
   the linked Theap (src/heap.c:60-99). Its first page records the Heap's
   arena pages through the main Heap (src/arena.c:1661-1665), which moves the
   cached Theap, so the next lookup finds no slot and creates a second Theap
   whose slot growth succeeds. Only the slot table's _mi_meta_rezalloc call
   is intercepted. Printed in the field order of
   subproc::main_heaps::tests::emit_m2_thread_local_slot_failure_c_rust_trace. */
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim.h"
#include "mimalloc/prim-tls.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#if !defined(__linux__) || !(defined(__x86_64__) || defined(__aarch64__))
#error this fixture requires native Linux x86-64 or AArch64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif

static bool slot_refuse;
static size_t slot_refusals;
static size_t slot_expected_size;

static void* slot_rezalloc(mi_subproc_t* subproc, void* old, size_t size, mi_memid_t* memid) {
  if (slot_refuse) {
    if (subproc != _mi_subproc_main() || old != NULL || size != slot_expected_size || memid == NULL) abort();
    slot_refuse = false;
    slot_refusals++;
    *memid = _mi_memid_none();
    return NULL;
  }
  return _mi_meta_rezalloc(subproc, old, size, memid);
}

#define _mi_meta_rezalloc(subproc, old, size, memid) slot_rezalloc(subproc, old, size, memid)
#include "threadlocal.c"
#undef _mi_meta_rezalloc

static size_t efault_reports;
static size_t other_reports;

static void count_error(int error, void* argument) {
  (void)argument;
  if (error == EFAULT) efault_reports++;
  else other_reports++;
}

static void emit(const char* field, size_t value) {
  printf("m2.thread_local_slot_failure.%s=%zu\n", field, value);
}

static size_t heap_theap_count(const mi_heap_t* heap) {
  size_t count = 0;
  for (const mi_theap_t* theap = heap->theaps; theap != NULL; theap = theap->hnext) count++;
  return count;
}

int main(void) {
  mi_process_init();
  mi_register_error(&count_error, NULL);
  mi_heap_t* const heap = mi_heap_new();
  if (heap == NULL) abort();
  emit("setup.key_first_slot", mi_key_index(heap->theap) == 0 && mi_key_version(heap->theap) == 1);
  emit("setup.table_empty", mi_thread_locals_peek()->count == 0);
  emit("setup.no_heap_theap", heap->theaps == NULL);

  slot_expected_size = sizeof(mi_thread_locals_t) + 16 * sizeof(mi_tls_slot_t);
  slot_refuse = true;
  void* const first = mi_heap_malloc(heap, 64);
  mi_theap_t* const first_theap = heap->theaps;
  emit("failure.refused", slot_refusals == 1 && !slot_refuse);
  emit("failure.allocated", first != NULL);
  emit("failure.theap_linked", first_theap != NULL && first_theap->heap == heap);
  emit("failure.table_empty", mi_thread_locals_peek()->count == 0);
  emit("failure.slot_unset", _mi_thread_local_get(heap->theap) == NULL);
  emit("failure.heap_theaps", heap_theap_count(heap));
  emit("failure.cached_main", _mi_theap_cached() == _mi_theap_default());

  void* const retried = mi_heap_malloc(heap, 64);
  mi_theap_t* const second_theap = _mi_theap_cached();
  emit("retry.allocated", retried != NULL);
  emit("retry.second_theap", second_theap != first_theap && second_theap->heap == heap
      && heap->theaps == second_theap);
  emit("retry.heap_theaps", heap_theap_count(heap));
  emit("retry.slot_set", _mi_thread_local_get(heap->theap) == second_theap);
  emit("retry.table_count", mi_thread_locals_peek()->count);
  emit("retry.refusals", slot_refusals);

  void* const main_block = mi_heap_malloc(mi_heap_main(), 16);
  const bool cache_moved = main_block != NULL && _mi_theap_cached() == _mi_theap_default();
  void* const stable = mi_heap_malloc(heap, 64);
  emit("stable.slot_theap", cache_moved && stable != NULL && _mi_theap_cached() == second_theap
      && heap_theap_count(heap) == 2);

  mi_free(main_block);
  mi_free(stable);
  mi_free(retried);
  mi_free(first);
  mi_heap_delete(heap);
  emit("release.slot_table_kept", mi_thread_locals_peek()->count == 16);
  emit("report.efault", efault_reports);
  emit("report.other", other_reports);
  return 0;
}

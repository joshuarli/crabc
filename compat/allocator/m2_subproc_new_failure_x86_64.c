/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned mi_subproc_new (src/subproc.c:158-194) with one refused allocation
   at each of its three failure points: the child image and the metadata
   Theap from the parent's metadata Theap (src/subproc.c:29-37), and the child
   main Heap from the parent's main Heap (src/heap.c:128-134). The link-time
   wrappers refuse only the exact source request and forward every other
   allocation and free to the pinned bodies. Printed in the field order of
   subproc::lifecycle::tests::emit_m2_subproc_new_failure_cleanup_c_rust_trace. */
#include "mimalloc.h"
#include "mimalloc/internal.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#if !defined(__linux__) || !(defined(__x86_64__) || defined(__aarch64__))
#error this fixture requires native Linux x86-64 or AArch64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif

enum stage { STAGE_NONE, STAGE_IMAGE, STAGE_METADATA_THEAP, STAGE_HEAP };

static bool tracking;
static enum stage refuse;
static size_t refusals;
static void* tracked[8];
static size_t tracked_count;
static void* released[8];
static size_t released_count;

void* __real_mi_theap_zalloc(mi_theap_t* theap, size_t size);
void* __real_mi_heap_zalloc(mi_heap_t* heap, size_t size);
void __real_mi_free(void* pointer);
void __real__mi_free_subproc_safe(void* pointer);

static void track(void* pointer) {
  if (pointer == NULL) return;
  if (tracked_count == sizeof(tracked) / sizeof(tracked[0])) abort();
  tracked[tracked_count++] = pointer;
}

static void note_release(void* pointer) {
  for (size_t i = 0; i < tracked_count; i++) {
    if (tracked[i] == pointer) {
      if (released_count == sizeof(released) / sizeof(released[0])) abort();
      released[released_count++] = pointer;
      return;
    }
  }
}

void* __wrap_mi_theap_zalloc(mi_theap_t* theap, size_t size) {
  if (!tracking || theap != _mi_subproc_main()->theap_meta) return __real_mi_theap_zalloc(theap, size);
  if ((refuse == STAGE_IMAGE && size == sizeof(mi_subproc_t))
      || (refuse == STAGE_METADATA_THEAP && size == sizeof(mi_theap_t))) {
    refusals++;
    refuse = STAGE_NONE;
    return NULL;
  }
  void* pointer = __real_mi_theap_zalloc(theap, size);
  track(pointer);
  return pointer;
}

void* __wrap_mi_heap_zalloc(mi_heap_t* heap, size_t size) {
  if (!tracking || heap != mi_heap_main() || size != sizeof(mi_heap_t)) return __real_mi_heap_zalloc(heap, size);
  if (refuse == STAGE_HEAP) {
    refusals++;
    refuse = STAGE_NONE;
    return NULL;
  }
  void* pointer = __real_mi_heap_zalloc(heap, size);
  track(pointer);
  return pointer;
}

void __wrap_mi_free(void* pointer) {
  if (tracking) note_release(pointer);
  __real_mi_free(pointer);
}

void __wrap__mi_free_subproc_safe(void* pointer) {
  if (tracking) note_release(pointer);
  __real__mi_free_subproc_safe(pointer);
}

static void emit(const char* stage, const char* field, size_t value) {
  printf("m2.subproc_new_failure.%s.%s=%zu\n", stage, field, value);
}

static bool all_released(void) {
  for (size_t i = 0; i < tracked_count; i++) {
    bool found = false;
    for (size_t j = 0; j < released_count; j++) found = found || released[j] == tracked[i];
    if (!found) return false;
  }
  return true;
}

static void reset_tracking(void) {
  tracked_count = 0;
  released_count = 0;
}

int main(void) {
  mi_process_init();
  mi_subproc_t* const main_subproc = _mi_subproc_main();
  emit("start", "main_sequence", main_subproc->subproc_seq);
  emit("start", "members", main_subproc->prev == NULL && main_subproc->next == NULL);

  static const char* const names[] = { "image", "metadata_theap", "heap" };
  static const enum stage stages[] = { STAGE_IMAGE, STAGE_METADATA_THEAP, STAGE_HEAP };
  bool heap_release_order = false;
  for (size_t index = 0; index < 3; index++) {
    const char* const name = names[index];
    reset_tracking();
    refusals = 0;
    refuse = stages[index];
    tracking = true;
    mi_subproc_id_t failed = mi_subproc_new();
    tracking = false;
    emit(name, "refused", refusals == 1 && refuse == STAGE_NONE);
    emit(name, "returned_null", _mi_subproc_from_id(failed) == NULL);
    emit(name, "no_member", main_subproc->prev == NULL);
    emit(name, "blocks_released", all_released() && released_count == tracked_count);
    if (stages[index] == STAGE_HEAP) {
      heap_release_order = tracked_count == 2 && released_count == 2
          && released[0] == tracked[1] && released[1] == tracked[0];
    }

    reset_tracking();
    tracking = true;
    mi_subproc_id_t retry_id = mi_subproc_new();
    tracking = false;
    mi_subproc_t* const retry = _mi_subproc_from_id(retry_id);
    emit(name, "retry_created", retry != NULL && retry->heap_main != NULL);
    emit(name, "retry_sequence", retry == NULL ? 0 : retry->subproc_seq);
    emit(name, "retry_head", retry != NULL && retry->next == main_subproc && main_subproc->prev == retry
        && retry->prev == NULL && retry->parent == main_subproc);
    tracking = true;
    mi_subproc_destroy(retry_id);
    tracking = false;
    emit(name, "retry_destroyed", main_subproc->prev == NULL && tracked_count == 3 && all_released());
  }
  emit("heap", "release_order", heap_release_order);
  return 0;
}

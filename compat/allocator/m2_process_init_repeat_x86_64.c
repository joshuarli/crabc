/* Copyright (c) 2026 crabc contributors. SPDX-License-Identifier: MIT */
/* Pinned repeated explicit mi_process_init (src/init.c:537-592): the first
   call initializes the process and attaches the calling thread; a repeat on
   that thread and a call from a distinct thread return through the completed
   once (src/libc.c:115-140) without a second body, a second TLD or a default
   Theap for the distinct thread. Printed in the field order of
   runtime_lifecycle::tests::emit_m2_process_init_repeat_c_rust_trace. */
#include "mimalloc.h"
#include "mimalloc/internal.h"
#include "mimalloc/prim-tls.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>

#if !defined(__linux__) || !(defined(__x86_64__) || defined(__aarch64__))
#error this fixture requires native Linux x86-64 or AArch64
#endif
#if MI_BUILD_RELEASE != 1 || MI_DEBUG != 0 || MI_STAT != 0 || MI_SECURE != 0 || MI_GUARDED != 0
#error this fixture requires the fixed release profile
#endif

typedef struct distinct_s {
  bool empty_before;
  bool empty_after;
} distinct_t;

static void* distinct_main(void* argument) {
  distinct_t* const distinct = (distinct_t*)argument;
  distinct->empty_before = !mi_theap_is_initialized(_mi_theap_default());
  mi_process_init();
  distinct->empty_after = !mi_theap_is_initialized(_mi_theap_default());
  return NULL;
}

static void emit(const char* field, size_t value) {
  printf("m2.process_init_repeat.%s=%zu\n", field, value);
}

int main(void) {
  mi_subproc_t* const subproc = _mi_subproc_main();
  const bool cold = !_mi_process_is_initialized && !mi_theap_is_initialized(_mi_theap_default());
  mi_process_init();
  mi_theap_t* const first = _mi_theap_default();
  const size_t total = mi_atomic_load_relaxed(&subproc->thread_total_count);
  const size_t live = mi_atomic_load_relaxed(&subproc->thread_count);
  emit("first.cold_before", cold);
  emit("first.initialized", _mi_process_is_initialized && mi_theap_is_initialized(first));
  emit("first.thread_total", total);
  emit("first.thread_live", live);

  mi_process_init();
  emit("repeat.default_preserved", _mi_theap_default() == first && mi_theap_is_initialized(first));
  emit("repeat.counts_preserved", mi_atomic_load_relaxed(&subproc->thread_total_count) == total
      && mi_atomic_load_relaxed(&subproc->thread_count) == live);

  distinct_t distinct = { false, false };
  pthread_t thread;
  if (pthread_create(&thread, NULL, distinct_main, &distinct) != 0 || pthread_join(thread, NULL) != 0) return 3;
  emit("distinct.no_default", distinct.empty_before && distinct.empty_after);
  emit("distinct.counts_preserved", mi_atomic_load_relaxed(&subproc->thread_total_count) == total
      && mi_atomic_load_relaxed(&subproc->thread_count) == live);
  emit("distinct.owner_preserved", _mi_theap_default() == first);
  return 0;
}
